package consumer

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"myesi-vuln-service-golang/internal/config"
	"myesi-vuln-service-golang/internal/redis"
	"myesi-vuln-service-golang/internal/services"
	"myesi-vuln-service-golang/utils"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"

	// --- OpenTelemetry ---
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
)

// ===== Struct định nghĩa =====
type SBOMEvent struct {
	SBOMID     string              `json:"sbom_id"`
	Project    string              `json:"project_name"`
	Components []map[string]string `json:"components"`
}

type SBOMBatchEvent struct {
	Type        string `json:"type"`
	Project     string `json:"project"`
	SBOMRecords []struct {
		ID         string                   `json:"id"`
		Components []map[string]interface{} `json:"components"`
	} `json:"sbom_records"`
	Timestamp time.Time `json:"timestamp"`
}

// ===== Hằng số =====
const (
	maxRetry     = 3
	retryDelay   = 5 * time.Second
	parallelism  = 10
	cacheTTL     = 24 * time.Hour
	redisHashKey = "sbom:%s:hash"
)

// ===== Metric =====
var (
	meter     metric.Meter
	scanCount metric.Int64Counter
)

// ===== Khởi tạo OTEL Metric =====
func InitMetrics() error {
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("vuln-service"),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res))
	otel.SetMeterProvider(mp)

	meter = otel.Meter("vuln-service")
	scanCount, err = meter.Int64Counter("vuln.scan.count")
	if err != nil {
		return fmt.Errorf("failed to create metric counter: %w", err)
	}

	log.Println("[OTEL] Metrics initialized for vuln-service")
	return nil
}

// ===== Consumer chính =====
func StartConsumer(db *sql.DB) error {
	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  strings.Split(config.LoadConfig().KafkaBroker, ","),
		GroupID:  config.LoadConfig().ConsumerGroup,
		Topic:    config.LoadConfig().KafkaTopic,
		MinBytes: 1e3,
		MaxBytes: 10e6,
	})

	log.Println("[VulnService] Kafka consumer started, topic:", config.LoadConfig().KafkaTopic)

	for {
		m, err := r.FetchMessage(context.Background())
		if err != nil {
			log.Println("[VulnService] kafka fetch error:", err)
			time.Sleep(1 * time.Second)
			continue
		}

		var single SBOMEvent
		var batch SBOMBatchEvent

		// CASE 1 — batch message từ sbom-service
		if err := json.Unmarshal(m.Value, &batch); err == nil && batch.Type == "sbom.batch_created" {
			log.Printf("[VulnService] Received batch with %d SBOM(s) for project %s", len(batch.SBOMRecords), batch.Project)

			// tạm lưu kết quả toàn batch
			var batchResults []utils.VulnProcessedPayload
			var mu sync.Mutex
			var wg sync.WaitGroup

			for _, rec := range batch.SBOMRecords {
				wg.Add(1)
				go func(id string, comps []map[string]interface{}) {
					defer wg.Done()
					e := SBOMEvent{
						SBOMID:     id,
						Project:    batch.Project,
						Components: make([]map[string]string, 0, len(comps)),
					}
					for _, c := range comps {
						compMap := map[string]string{}
						for k, v := range c {
							compMap[k] = fmt.Sprintf("%v", v)
						}
						e.Components = append(e.Components, compMap)
					}

					result, err := processEventWithQuota(e, db)
					if err != nil {
						log.Printf("[VulnService] batch item failed for SBOM %s: %v", id, err)
						return
					}

					// Luôn tạo payload để gửi sang risk, kể cả khi không có vuln
					payload := result
					if payload == nil {
						payload = &utils.VulnProcessedPayload{
							Type:        "vuln.processed",
							SBOMID:      id,
							ProjectName: batch.Project,
							Components:  []map[string]interface{}{}, // sạch vuln
							Timestamp:   time.Now().UTC(),
							Hash:        "",
						}
					}

					mu.Lock()
					batchResults = append(batchResults, *payload)
					mu.Unlock()
				}(rec.ID, rec.Components)
			}

			wg.Wait()

			if len(batchResults) > 0 {
				err = utils.ProduceVulnProcessedBatch(utils.VulnProcessedBatchPayload{
					Type:        "vuln.processed.batch",
					ProjectName: batch.Project,
					Records:     batchResults,
					Timestamp:   time.Now().UTC(),
				})
				if err != nil {
					log.Printf("[VulnService] Kafka batch publish failed for project %s: %v", batch.Project, err)
				} else {
					log.Printf("[KAFKA] Published vuln.processed.batch for %s (%d SBOMs)", batch.Project, len(batchResults))
				}
			}

			_ = r.CommitMessages(context.Background(), m)
			continue
		}

		// CASE 2 — single SBOM event
		if err := json.Unmarshal(m.Value, &single); err == nil && single.SBOMID != "" {
			processWithRetry(single, db)
			_ = r.CommitMessages(context.Background(), m)
			continue
		}

		// CASE 3 — SBOM limit failed
		var limitMsg map[string]interface{}
		if err := json.Unmarshal(m.Value, &limitMsg); err == nil && limitMsg["type"] == "sbom.limit_reached" {
			project := fmt.Sprintf("%v", limitMsg["project"])
			timestamp := time.Now().UTC()

			log.Printf("[VulnService] Handling sbom.limit_check_failed for project=%s", project)

			// Tạo payload rỗng
			payload := utils.VulnProcessedPayload{
				Type:        "vuln.processed",
				SBOMID:      uuid.NewString(),
				ProjectName: project,
				Components:  []map[string]interface{}{},
				Timestamp:   timestamp,
				Hash:        "",
			}

			// ALWAYS SEND
			if err := utils.ProduceVulnProcessed(payload); err != nil {
				log.Printf("[KAFKA][ERR] failed to publish empty vuln.processed: %v", err)
			} else {
				log.Printf("[KAFKA] Published empty vuln.processed for project=%s (limit reached)", project)
			}

			_ = r.CommitMessages(context.Background(), m)
			continue
		}

		log.Printf("[VulnService] Unknown or malformed message, skipping: %s", string(m.Value))
		_ = r.CommitMessages(context.Background(), m)
	}
}

// ===== Retry wrapper =====
func processWithRetry(evt SBOMEvent, db *sql.DB) *utils.VulnProcessedPayload {
	ctx := context.Background()
	start := time.Now()
	var result *utils.VulnProcessedPayload
	success := false

	for attempt := 1; attempt <= maxRetry; attempt++ {
		r, err := processEventWithQuota(evt, db)
		if err != nil {
			log.Printf("[VulnService] attempt %d failed for SBOMID %s: %v", attempt, evt.SBOMID, err)
			time.Sleep(retryDelay)
		} else {
			result = r
			success = true
			// ---- ALWAYS SEND MESSAGE TO RISK SERVICE ----
			payload := r
			if payload == nil {
				payload = &utils.VulnProcessedPayload{
					Type:        "vuln.processed",
					SBOMID:      evt.SBOMID,
					ProjectName: evt.Project,
					Components:  []map[string]interface{}{},
					Timestamp:   time.Now().UTC(),
					Hash:        "",
				}
			}

			if err := utils.ProduceVulnProcessed(*payload); err != nil {
				log.Printf("[KAFKA][ERR] publish failed: %v", err)
			} else {
				log.Printf("[KAFKA] Published vuln.processed for SBOM %s", evt.SBOMID)
			}
			break
		}
	}

	scanCount.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("sbom.id", evt.SBOMID),
			attribute.String("project.name", evt.Project),
			attribute.Bool("success", success),
		),
	)

	log.Printf("[VulnService] SBOMID %s processed in %s (success=%v)", evt.SBOMID, time.Since(start), success)
	return result
}

// ===== Logic xử lý SBOM =====
func processEvent(evt SBOMEvent, db *sql.DB) (*utils.VulnProcessedPayload, error) {
	ctx := context.Background()

	// Generate stable hash of component list (kể cả khi rỗng)
	compBytes, _ := json.Marshal(evt.Components)
	hash := sha256.Sum256(compBytes)
	hashStr := hex.EncodeToString(hash[:])
	cacheKey := fmt.Sprintf(redisHashKey, evt.SBOMID)

	// Check cache
	cachedHash, err := redis.Client.Get(ctx, cacheKey).Result()
	if err == nil && cachedHash == hashStr {
		log.Printf("[Cache] SBOM %s unchanged (hash=%s), skipping reprocess", evt.SBOMID, hashStr[:10])
		return nil, nil
	}

	// 1) Deactivate toàn bộ vuln cũ của SBOM này
	if _, err := db.ExecContext(ctx, `
		UPDATE vulnerabilities
		SET is_active = FALSE,
			updated_at = NOW()
		WHERE sbom_id = $1
	`, evt.SBOMID); err != nil {
		log.Printf("[VulnService][ERR] Failed to deactivate old vulns for SBOM %s: %v", evt.SBOMID, err)
	}

	// 2) Nếu SBOM mới không có component nào -> coi như không còn vuln active
	if len(evt.Components) == 0 {
		log.Println("[VulnService] No components to process for SBOMID (after change):", evt.SBOMID)

		if err := utils.UpdateProjectSummary(ctx, db, evt.Project); err != nil {
			log.Printf("[VulnService][ERR] Update project summary: %v", err)
		}

		redis.Client.Set(ctx, cacheKey, hashStr, cacheTTL)
		log.Printf("[Cache] Updated SBOM %s (hash=%s, count=%d)",
			evt.SBOMID, hashStr[:10], len(evt.Components))

		// Không có vuln active nào để gửi sang risk
		return nil, nil
	}

	// 3) Query OSV cho từng component (song song)
	osvRecords := make([]config.OSVRecord, 0, len(evt.Components))
	for _, c := range evt.Components {
		name := c["name"]
		version := c["version"]
		typ := c["type"]

		if name == "" || version == "" {
			continue
		}

		ecosystem := normalizeEcosystemForOSV(typ)
		if ecosystem == "" || ecosystem == "unknown" {
			log.Printf("[VulnService] Unknown ecosystem for %s@%s (type=%s), skipping OSV query",
				name, version, typ)
			continue
		}

		osvRecords = append(osvRecords, config.OSVRecord{
			Package: struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			}{
				Name:      name,
				Ecosystem: ecosystem,
			},
			Version: version,
		})
	}

	type resultItem struct {
		Comp   config.OSVRecord
		Result map[string]interface{}
		Err    error
	}

	sem := make(chan struct{}, parallelism)
	resultsCh := make(chan resultItem, len(osvRecords))

	for _, comp := range osvRecords {
		sem <- struct{}{}
		go func(c config.OSVRecord) {
			defer func() { <-sem }()
			res, err := services.QueryOSVBatch(ctx, []config.OSVRecord{c})
			item := resultItem{Comp: c}
			if err != nil {
				item.Err = err
			} else if len(res) > 0 {
				item.Result = res[0]
			}
			resultsCh <- item
		}(comp)
	}

	vulnComponents := []map[string]interface{}{}
	for i := 0; i < len(osvRecords); i++ {
		item := <-resultsCh
		if item.Err != nil {
			log.Printf("[VulnService] OSV query failed for %s@%s: %v",
				item.Comp.Package.Name, item.Comp.Version, item.Err)
			continue
		}

		meta := item.Result
		if meta == nil {
			meta = map[string]interface{}{"note": "no result"}
		}
		metaBytes, _ := json.Marshal(meta)

		var vulnID, severity *string
		if vsRaw, ok := meta["vulns"]; ok {
			if arr, _ := vsRaw.([]interface{}); len(arr) > 0 {
				if first, ok := arr[0].(map[string]interface{}); ok {
					vulnID = interfaceToStringPtr(first["id"])

					var sev *string
					if cvssRaw, ok := first["cvss"]; ok {
						if cvssArr, _ := cvssRaw.([]interface{}); len(cvssArr) > 0 {
							if cvss0, ok := cvssArr[0].(map[string]interface{}); ok {
								if score, ok := cvss0["score"].(string); ok {
									sev = &score
								}
							}
						}
					}
					if sev == nil {
						if dbSpec, ok := first["database_specific"].(map[string]interface{}); ok {
							if s, ok := dbSpec["severity"].(string); ok {
								sev = &s
							}
						}
					}
					severity = sev
				}
			}
		}

		if vulnID == nil {
			continue
		}

		sevLabel := "unknown"
		var cvssVector *string
		fixAvailable := false
		var fixedVersion *string

		if severity != nil && *severity != "" {
			sevLabel = *severity
		} else {
			if s, vec, fixAvail, fixVer, err := services.FetchVulnDetails(ctx, *vulnID); err == nil {
				sevLabel = s
				cvssVector = vec
				fixAvailable = fixAvail
				fixedVersion = fixVer
			}
		}

		if strings.HasPrefix(*vulnID, "MAL") {
			sevLabel = "critical"
		}

		_, err := db.ExecContext(ctx, `
			INSERT INTO vulnerabilities (
				sbom_id, project_name, component_name, component_version,
				vuln_id, severity, osv_metadata, cvss_vector,
				fix_available, fixed_version, updated_at, is_active
			)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW(), TRUE)
			ON CONFLICT (sbom_id, component_name, component_version)
			DO UPDATE SET
				vuln_id        = EXCLUDED.vuln_id,
				severity       = EXCLUDED.severity,
				osv_metadata   = EXCLUDED.osv_metadata,
				cvss_vector    = EXCLUDED.cvss_vector,
				fix_available  = EXCLUDED.fix_available,
				fixed_version  = EXCLUDED.fixed_version,
				is_active      = TRUE,
				updated_at     = NOW();
		`, evt.SBOMID, evt.Project, item.Comp.Package.Name, item.Comp.Version,
			vulnID, sevLabel, metaBytes, cvssVector, fixAvailable, fixedVersion)

		if err != nil {
			log.Printf("[VulnService] Upsert vuln failed for %s@%s: %v",
				item.Comp.Package.Name, item.Comp.Version, err)
			continue
		}

		log.Printf("[VulnService] Upserted vuln %s@%s (%s)",
			item.Comp.Package.Name, item.Comp.Version, sevLabel)

		vulnComponents = append(vulnComponents, map[string]interface{}{
			"component": item.Comp.Package.Name,
			"version":   item.Comp.Version,
			"vuln_id":   *vulnID,
			"severity":  sevLabel,
		})
	}

	if err := utils.UpdateProjectSummary(ctx, db, evt.Project); err != nil {
		log.Printf("[VulnService][ERR] Update project summary: %v", err)
	}

	// Auto-resolve assignments cho các vuln đã trở thành inactive
	if _, err := db.ExecContext(ctx, `
		UPDATE vulnerability_assignments va
		SET status = 'resolved',
			updated_at = NOW()
		WHERE va.vulnerability_id IN (
			SELECT id FROM vulnerabilities
			WHERE sbom_id = $1
			AND is_active = FALSE
		)
		AND va.status <> 'resolved';
	`, evt.SBOMID); err != nil {
		log.Printf("[VulnService][ERR] Auto-resolve assignments for SBOM %s: %v", evt.SBOMID, err)
	}

	redis.Client.Set(ctx, cacheKey, hashStr, cacheTTL)
	log.Printf("[Cache] Updated SBOM %s (hash=%s, count=%d)",
		evt.SBOMID, hashStr[:10], len(evt.Components))

	if len(vulnComponents) == 0 {
		// Không còn vuln active cho SBOM này
		return nil, nil
	}

	return &utils.VulnProcessedPayload{
		Type:        "vuln.processed",
		SBOMID:      evt.SBOMID,
		ProjectName: evt.Project,
		Components:  vulnComponents,
		Timestamp:   time.Now().UTC(),
		Hash:        hashStr,
	}, nil
}

func normalizeEcosystemForOSV(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	switch t {
	case "pypi", "python":
		return "PyPI"
	case "npm", "javascript", "node":
		return "npm"
	case "maven", "java":
		return "Maven"
	case "golang", "go":
		return "Go"
	case "composer", "php":
		return "Composer"
	case "nuget", "dotnet":
		return "NuGet"
	default:
		return "unknown"
	}
}

func interfaceToStringPtr(v interface{}) *string {
	if v == nil {
		return nil
	}
	s := fmt.Sprintf("%v", v)
	return &s
}

func processEventWithQuota(evt SBOMEvent, db *sql.DB) (*utils.VulnProcessedPayload, error) {
	ctx := context.Background()

	// ---- Lấy orgID của project ----
	var orgID int
	err := db.QueryRowContext(ctx, "SELECT organization_id FROM projects WHERE name=$1", evt.Project).Scan(&orgID)
	if err != nil {
		return nil, fmt.Errorf("cannot find orgID for project %s: %w", evt.Project, err)
	}

	// ---- Project scan quota check ONLY ----
	var allowed bool
	var msg string
	var nextReset time.Time
	row := db.QueryRowContext(ctx,
		"SELECT allowed, message, next_reset FROM check_and_consume_usage($1,$2,$3)",
		orgID, "project_scan", 1,
	)

	if err := row.Scan(&allowed, &msg, &nextReset); err != nil || !allowed {
		log.Printf("[LIMIT] Project scan limit reached for %s: %v", evt.Project, msg)
		payload := utils.VulnProcessedPayload{
			Type:        "vuln.processed",
			ProjectName: evt.Project,
			SBOMID:      uuid.NewString(),
			Components:  []map[string]interface{}{},
			Timestamp:   time.Now().UTC(),
			Hash:        "",
		}
		_ = utils.ProduceVulnProcessed(payload)
		return nil, nil
	}

	// ---- Call original logic ----
	return processEvent(evt, db)
}
