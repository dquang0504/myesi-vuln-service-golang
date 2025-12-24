package consumer

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"myesi-vuln-service-golang/internal/config"
	"myesi-vuln-service-golang/internal/events"
	kafkautil "myesi-vuln-service-golang/internal/kafka"
	"myesi-vuln-service-golang/internal/redis"
	"myesi-vuln-service-golang/internal/services"
	orgsettings "myesi-vuln-service-golang/internal/services/orgsettings"
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
	SBOMID                   string              `json:"sbom_id"`
	Project                  string              `json:"project_name"`
	ProjectID                int                 `json:"project_id,omitempty"`
	Components               []map[string]string `json:"components"`
	OrganizationID           int64               `json:"organization_id,omitempty"`
	Source                   string              `json:"source,omitempty"`
	ProjectScanQuotaConsumed bool                `json:"project_scan_quota_consumed"`
}

type SBOMBatchEvent struct {
	Type                     string `json:"type"`
	Project                  string `json:"project"`
	ProjectID                int    `json:"project_id,omitempty"`
	OrganizationID           int64  `json:"organization_id,omitempty"`
	Source                   string `json:"source,omitempty"`
	CodeFindingsCount        int    `json:"code_findings_count,omitempty"`
	ProjectScanQuotaConsumed bool   `json:"project_scan_quota_consumed"`
	SBOMRecords              []struct {
		ID         string                   `json:"id"`
		Components []map[string]interface{} `json:"components"`
	} `json:"sbom_records"`
	Timestamp time.Time `json:"timestamp"`
}

type rawEnvelope struct {
	Type           string          `json:"type"`
	Version        int             `json:"version,omitempty"`
	ID             string          `json:"id,omitempty"`
	OccurredAt     time.Time       `json:"occurred_at,omitempty"`
	OrganizationID int64           `json:"organization_id,omitempty"`
	ProjectName    string          `json:"project_name,omitempty"`
	Data           json.RawMessage `json:"data"`
}

// ===== Hằng số =====
const (
	maxRetry     = 3
	retryDelay   = 5 * time.Second
	cacheTTL     = 24 * time.Hour
	redisHashKey = "sbom:%s:hash"
)

type failureCategory string

const (
	failureTransient failureCategory = "transient"
	failurePermanent failureCategory = "permanent"
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

		envInfo, isEnvelope, err := decodeEnvelope(m.Value, &batch)
		if err == nil && (batch.Type == "sbom.batch_created" || (isEnvelope && envInfo.Type == "sbom.batch_created")) {
			if batch.Type == "" {
				batch.Type = envInfo.Type
			}
			if batch.Project == "" && envInfo.ProjectName != "" {
				batch.Project = envInfo.ProjectName
			}
			if batch.OrganizationID == 0 && envInfo.OrganizationID != 0 {
				batch.OrganizationID = envInfo.OrganizationID
			}
			log.Printf("[VulnService] Received batch with %d SBOM(s) for project %s", len(batch.SBOMRecords), batch.Project)

			// tạm lưu kết quả toàn batch
			var batchResults []utils.VulnProcessedPayload
			var mu sync.Mutex
			var wg sync.WaitGroup
			changed := false

			for _, rec := range batch.SBOMRecords {
				wg.Add(1)
				go func(id string, comps []map[string]interface{}) {
					defer wg.Done()
					e := SBOMEvent{
						SBOMID:                   id,
						Project:                  batch.Project,
						ProjectID:                batch.ProjectID,
						OrganizationID:           batch.OrganizationID,
						Source:                   batch.Source,
						ProjectScanQuotaConsumed: batch.ProjectScanQuotaConsumed,
						Components:               make([]map[string]string, 0, len(comps)),
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
							SBOMID:         id,
							ProjectName:    batch.Project,
							OrganizationID: batch.OrganizationID,
							Components:     []map[string]interface{}{}, // sạch vuln
							Timestamp:      time.Now().UTC(),
							Hash:           "",
							Status:         "success",
						}
					} else {
						changed = true
					}
					payload.Status = "success"

					mu.Lock()
					batchResults = append(batchResults, *payload)
					mu.Unlock()
				}(rec.ID, rec.Components)
			}

			wg.Wait()

			if len(batchResults) > 0 {
				err = utils.ProduceVulnProcessedBatch(utils.VulnProcessedBatchPayload{
					ProjectName:    batch.Project,
					OrganizationID: batch.OrganizationID,
					Records:        batchResults,
					Timestamp:      time.Now().UTC(),
				})
				if err != nil {
					log.Printf("[VulnService] Kafka batch publish failed for project %s: %v", batch.Project, err)
				} else {
					log.Printf("[KAFKA] Published vuln.processed.batch for %s (%d SBOMs)", batch.Project, len(batchResults))
				}

				// Send project scan summary once per batch with aggregated vuln count
				if changed {
					totalVulns := 0
					for _, rec := range batchResults {
						totalVulns += len(rec.Components)
					}
					orgID := batch.OrganizationID
					if orgID == 0 {
						orgID = lookupOrgIDByProject(context.Background(), db, batch.Project)
					}
					if orgID > 0 {
						utils.PublishScanSummary(orgID, batch.Project, totalVulns, batch.CodeFindingsCount)
					}
				}
			}

			_ = r.CommitMessages(context.Background(), m)
			continue
		}

		// CASE 2 — single SBOM event
		envInfoSingle, singleEnvelope, err := decodeEnvelope(m.Value, &single)
		if err == nil && (single.SBOMID != "" || (singleEnvelope && envInfoSingle.Type == "sbom.created")) {
			if single.OrganizationID == 0 && envInfoSingle.OrganizationID != 0 {
				single.OrganizationID = envInfoSingle.OrganizationID
			}
			if single.Project == "" && envInfoSingle.ProjectName != "" {
				single.Project = envInfoSingle.ProjectName
			}
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
				SBOMID:      uuid.NewString(),
				ProjectName: project,
				Components:  []map[string]interface{}{},
				Timestamp:   timestamp,
				Hash:        "",
				Status:      "failed",
				Error:       "sbom.limit_reached",
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
// processWithRetry drives the SBOM pipeline with bounded retries (maxRetry with
// 5s backoff). Each attempt either succeeds and immediately emits
// vuln.processed(status=success) or fails and is retried based on error
// classification. After the final attempt we always emit a terminal event and a
// DLQ entry so downstream consumers never wait indefinitely.
func processWithRetry(evt SBOMEvent, db *sql.DB) *utils.VulnProcessedPayload {
	ctx := context.Background()
	start := time.Now()
	var result *utils.VulnProcessedPayload
	success := false
	var lastErr error
	attempts := 0
	failureClass := failureTransient

	for attempt := 1; attempt <= maxRetry; attempt++ {
		attempts = attempt
		r, err := processEventWithQuota(evt, db)
		if err != nil {
			log.Printf("[VulnService] attempt %d failed for SBOMID %s: %v", attempt, evt.SBOMID, err)
			lastErr = err
			failureClass = classifyFailure(err)
			if failureClass == failurePermanent {
				break
			}
			time.Sleep(retryDelay)
		} else {
			result = r
			success = true
			emitSuccessEvent(evt, r)
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
	if !success && lastErr != nil {
		emitFailureEvent(evt, lastErr)
		publishDLQEvent(evt, lastErr, attempts, failureClass)
	}
	return result
}

// ===== Logic xử lý SBOM =====
func processEvent(evt SBOMEvent, db *sql.DB) (*utils.VulnProcessedPayload, error) {
	ctx := context.Background()

	projectID, err := resolveProjectID(ctx, db, evt)
	if err != nil {
		return nil, err
	}

	sbomBytes, err := loadSBOMBytes(ctx, db, evt)
	if err != nil {
		return nil, err
	}

	components := evt.Components
	if len(components) == 0 && len(sbomBytes) > 0 {
		var sbomDoc map[string]interface{}
		if err := json.Unmarshal(sbomBytes, &sbomDoc); err != nil {
			log.Printf("[VulnService][WARN] unable to parse SBOM for %s: %v", evt.SBOMID, err)
		} else {
			components = utils.ExtractComponents(sbomDoc)
			evt.Components = components
		}
	}

	// Generate stable hash of component list (kể cả khi rỗng)
	compBytes, _ := json.Marshal(components)
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
	if len(components) == 0 {
		log.Println("[VulnService] No components to process for SBOMID (after change):", evt.SBOMID)

		if err := utils.UpdateProjectSummary(ctx, db, evt.Project); err != nil {
			log.Printf("[VulnService][ERR] Update project summary: %v", err)
		}

		// Auto-resolve every assignment associated with every vuln that has been inactive of this SBOM
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
			log.Printf("[VulnService][ERR] Auto-resolve assignments (no components) for SBOM %s: %v", evt.SBOMID, err)
		}

		redis.Client.Set(ctx, cacheKey, hashStr, cacheTTL)
		log.Printf("[Cache] Updated SBOM %s (hash=%s, count=%d)",
			evt.SBOMID, hashStr[:10], len(components))

		// Không có vuln active nào để gửi sang risk
		return nil, nil
	}

	findings, err := services.ScanSBOMWithGrype(ctx, sbomBytes)
	if err != nil {
		return nil, err
	}

	vulnComponents := []map[string]interface{}{}
	for _, finding := range findings {
		_, err := db.ExecContext(ctx, `
			INSERT INTO vulnerabilities (
				sbom_id, project_id, project_name, component_name, component_version,
				vuln_id, severity, osv_metadata, cvss_vector,
				fix_available, fixed_version, updated_at, is_active
			)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW(), TRUE)
			ON CONFLICT (sbom_id, component_name, component_version, vuln_id)
			DO UPDATE SET
				project_id     = EXCLUDED.project_id,
				project_name   = EXCLUDED.project_name,
				vuln_id        = EXCLUDED.vuln_id,
				severity       = EXCLUDED.severity,
				osv_metadata   = EXCLUDED.osv_metadata,
				cvss_vector    = EXCLUDED.cvss_vector,
				fix_available  = EXCLUDED.fix_available,
				fixed_version  = EXCLUDED.fixed_version,
				is_active      = TRUE,
				updated_at     = NOW();
		`, evt.SBOMID, projectID, evt.Project, finding.ComponentName, finding.ComponentVersion,
			finding.VulnerabilityID, finding.Severity, finding.Metadata, finding.CVSSVector, finding.FixAvailable, finding.FixedVersion)

		if err != nil {
			log.Printf("[VulnService] Upsert vuln failed for %s@%s: %v",
				finding.ComponentName, finding.ComponentVersion, err)
			continue
		}

		log.Printf("[VulnService] Upserted vuln %s@%s (%s)",
			finding.ComponentName, finding.ComponentVersion, finding.Severity)

		if err := services.AutoMapControlAdvanced(ctx, db, evt.SBOMID, finding.ComponentName, finding.ComponentVersion, finding.CVSSScore, finding.Severity); err != nil {
			log.Printf("[VulnService] Failed to auto-map control for %s@%s: %v", finding.ComponentName, finding.ComponentVersion, err)
		}

		vulnComponents = append(vulnComponents, map[string]interface{}{
			"component": finding.ComponentName,
			"version":   finding.ComponentVersion,
			"vuln_id":   finding.VulnerabilityID,
			"severity":  finding.Severity,
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
		evt.SBOMID, hashStr[:10], len(components))

	if len(vulnComponents) == 0 {
		// Không còn vuln active cho SBOM này
		return nil, nil
	}

	orgID := evt.OrganizationID
	if orgID == 0 {
		orgID = lookupOrgIDByProject(ctx, db, evt.Project)
	}
	if orgID > 0 {
		if err := maybePublishCriticalAlert(ctx, db, orgID, evt.Project, vulnComponents); err != nil {
			log.Printf("[VULN][ALERT] publish critical alert failed: %v", err)
		}
	}

	payload := &utils.VulnProcessedPayload{
		SBOMID:         evt.SBOMID,
		ProjectName:    evt.Project,
		OrganizationID: orgID,
		Components:     vulnComponents,
		Timestamp:      time.Now().UTC(),
		Hash:           hashStr,
		Status:         "success",
	}

	// Publish SBOM summary with real vuln count (after processing)
	orgIDForNotify := evt.OrganizationID
	if orgIDForNotify == 0 {
		orgIDForNotify = lookupOrgIDByProject(ctx, db, evt.Project)
	}
	if orgIDForNotify > 0 {
		// Only emit SBOM summary for manual uploads (source=upload)
		if strings.ToLower(evt.Source) == "upload" {
			utils.PublishSBOMSummary(orgIDForNotify, evt.Project, len(evt.Components), len(vulnComponents))
		}
	}

	return payload, nil
}

// lookupOrgIDByProject resolves organization_id by project name (best effort)
func lookupOrgIDByProject(ctx context.Context, dbConn *sql.DB, projectName string) int64 {
	if projectName == "" {
		return 0
	}
	var orgID sql.NullInt64
	if err := dbConn.QueryRowContext(ctx, `SELECT organization_id FROM projects WHERE name=$1 LIMIT 1`, projectName).Scan(&orgID); err != nil {
		return 0
	}
	return orgID.Int64
}

func processEventWithQuota(evt SBOMEvent, db *sql.DB) (*utils.VulnProcessedPayload, error) {
	ctx := context.Background()

	if strings.EqualFold(evt.Source, "project_scan") && evt.ProjectScanQuotaConsumed {
		return processEvent(evt, db)
	}

	// ---- Lấy orgID của project ----
	var orgID int
	var projectID int
	err := db.QueryRowContext(ctx, "SELECT organization_id, id FROM projects WHERE name=$1", evt.Project).Scan(&orgID, &projectID)
	if err != nil {
		return nil, fmt.Errorf("cannot find orgID for project %s: %w", evt.Project, err)
	}
	evt.ProjectID = projectID
	if evt.OrganizationID == 0 && orgID > 0 {
		evt.OrganizationID = int64(orgID)
	}

	// ---- Project scan quota check ONLY ----
	var allowed bool
	var msg string
	var nextReset sql.NullTime
	row := db.QueryRowContext(ctx,
		"SELECT allowed, message, next_reset FROM check_and_consume_usage($1,$2,$3)",
		orgID, "project_scan", 1,
	)

	if err := row.Scan(&allowed, &msg, &nextReset); err != nil || !allowed {
		log.Printf("[LIMIT] Project scan limit reached for %s: %v", evt.Project, msg)
		payload := utils.VulnProcessedPayload{
			ProjectName:    evt.Project,
			SBOMID:         uuid.NewString(),
			OrganizationID: int64(orgID),
			Components:     []map[string]interface{}{},
			Timestamp:      time.Now().UTC(),
			Hash:           "",
			Status:         "failed",
			Error:          msg,
		}
		_ = utils.ProduceVulnProcessed(payload)
		return nil, nil
	}

	// ---- Call original logic ----
	return processEvent(evt, db)
}

func resolveProjectID(ctx context.Context, dbConn *sql.DB, evt SBOMEvent) (int, error) {
	if evt.ProjectID > 0 {
		return evt.ProjectID, nil
	}

	if evt.Project != "" {
		var projectID int
		if err := dbConn.QueryRowContext(ctx, `SELECT id FROM projects WHERE name=$1`, evt.Project).Scan(&projectID); err == nil {
			return projectID, nil
		}
	}

	if evt.SBOMID != "" {
		var projectID int
		if err := dbConn.QueryRowContext(ctx, `SELECT project_id FROM sboms WHERE id=$1`, evt.SBOMID).Scan(&projectID); err == nil && projectID > 0 {
			return projectID, nil
		}
	}

	return 0, fmt.Errorf("project_id not found for project=%s sbom=%s", evt.Project, evt.SBOMID)
}

func loadSBOMBytes(ctx context.Context, dbConn *sql.DB, evt SBOMEvent) ([]byte, error) {
	if evt.SBOMID != "" {
		var sbomData []byte
		err := dbConn.QueryRowContext(ctx, `SELECT sbom FROM sboms WHERE id=$1`, evt.SBOMID).Scan(&sbomData)
		if err == nil && len(sbomData) > 0 {
			return sbomData, nil
		}
		if err != nil && err != sql.ErrNoRows {
			return nil, fmt.Errorf("fetch sbom %s: %w", evt.SBOMID, err)
		}
	}

	if len(evt.Components) > 0 {
		return services.BuildCycloneDXFromComponents(evt.Components)
	}

	return nil, fmt.Errorf("no SBOM payload available for project=%s sbom=%s", evt.Project, evt.SBOMID)
}

func decodeEnvelope(raw []byte, target interface{}) (rawEnvelope, bool, error) {
	var env rawEnvelope
	if err := json.Unmarshal(raw, &env); err == nil && env.Type != "" && len(env.Data) > 0 {
		if err := json.Unmarshal(env.Data, target); err != nil {
			return env, true, err
		}
		return env, true, nil
	}

	if err := json.Unmarshal(raw, target); err != nil {
		return rawEnvelope{}, false, err
	}
	return rawEnvelope{}, false, nil
}

func emitSuccessEvent(evt SBOMEvent, payload *utils.VulnProcessedPayload) {
	if payload == nil {
		payload = &utils.VulnProcessedPayload{
			SBOMID:         evt.SBOMID,
			ProjectName:    evt.Project,
			OrganizationID: evt.OrganizationID,
			Components:     []map[string]interface{}{},
			Timestamp:      time.Now().UTC(),
			Status:         "success",
		}
	}
	if payload.OrganizationID == 0 {
		payload.OrganizationID = evt.OrganizationID
	}
	payload.Status = "success"
	payload.Error = ""
	if err := utils.ProduceVulnProcessed(*payload); err != nil {
		log.Printf("[KAFKA][ERR] publish success failed: %v", err)
	} else {
		log.Printf("[KAFKA] Published vuln.processed for SBOM %s", payload.SBOMID)
	}
}

func emitFailureEvent(evt SBOMEvent, failure error) {
	payload := utils.VulnProcessedPayload{
		SBOMID:         evt.SBOMID,
		ProjectName:    evt.Project,
		OrganizationID: evt.OrganizationID,
		Components:     []map[string]interface{}{},
		Timestamp:      time.Now().UTC(),
		Status:         "failed",
	}
	if failure != nil {
		payload.Error = failure.Error()
	}
	if err := utils.ProduceVulnProcessed(payload); err != nil {
		log.Printf("[KAFKA][ERR] publish failure status failed: %v", err)
	}
}

func publishDLQEvent(evt SBOMEvent, failure error, attempts int, category failureCategory) {
	cfg := config.LoadConfig()
	if strings.TrimSpace(cfg.DLQTopic) == "" {
		return
	}
	writer, err := kafkautil.GetWriter(cfg.DLQTopic)
	if err != nil {
		log.Printf("[DLQ][ERR] writer unavailable: %v", err)
		return
	}

	errorMsg := ""
	if failure != nil {
		errorMsg = failure.Error()
	}
	dedupSource := fmt.Sprintf("%s|%s|%s", evt.SBOMID, evt.Project, errorMsg)
	dedupHash := sha256.Sum256([]byte(dedupSource))
	dedupKey := hex.EncodeToString(dedupHash[:8])

	payload := map[string]interface{}{
		"sbom_id":         evt.SBOMID,
		"project_name":    evt.Project,
		"organization_id": evt.OrganizationID,
		"error":           errorMsg,
		"attempts":        attempts,
		"failure_class":   string(category),
		"dedup_key":       dedupKey,
		"timestamp":       time.Now().UTC(),
	}

	env := events.NewEnvelope("sbom.processing_failed", evt.OrganizationID, evt.Project, payload)
	body, _ := json.Marshal(env)
	msg := kafka.Message{
		Key:   []byte(evt.SBOMID),
		Value: body,
		Time:  time.Now().UTC(),
	}

	if err := writer.WriteMessages(context.Background(), msg); err != nil {
		log.Printf("[DLQ][ERR] publish failed: %v", err)
	}
}

func classifyFailure(err error) failureCategory {
	if err == nil {
		return failureTransient
	}
	if errors.Is(err, sql.ErrNoRows) {
		return failurePermanent
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "empty sbom payload"),
		strings.Contains(lower, "no valid components"),
		strings.Contains(lower, "project not found"),
		strings.Contains(lower, "cannot find orgid"),
		strings.Contains(lower, "invalid sbom"):
		return failurePermanent
	default:
		return failureTransient
	}
}

func maybePublishCriticalAlert(ctx context.Context, dbConn *sql.DB, orgID int64, project string, vulns []map[string]interface{}) error {
	critical := make([]map[string]string, 0, len(vulns))
	for _, v := range vulns {
		sev, _ := v["severity"].(string)
		if !strings.EqualFold(sev, "critical") {
			continue
		}
		comp, _ := v["component"].(string)
		ver, _ := v["version"].(string)
		id, _ := v["vuln_id"].(string)
		critical = append(critical, map[string]string{
			"component": comp,
			"version":   ver,
			"vuln_id":   id,
		})
	}
	if len(critical) == 0 {
		return nil
	}

	settings, err := orgsettings.Get(ctx, dbConn, orgID)
	if err != nil {
		return err
	}
	if settings != nil && !settings.VulnerabilityAlerts {
		return nil
	}

	var emails []string
	if settings != nil && settings.EmailNotifications && settings.AdminEmail != "" {
		emails = append(emails, settings.AdminEmail)
	}

	utils.PublishCriticalVulnAlert(orgID, project, critical, emails)
	return nil
}
