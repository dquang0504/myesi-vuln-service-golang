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
	"myesi-vuln-service-golang/models"
	"strings"
	"time"

	"github.com/aarondl/null/v8"
	"github.com/aarondl/sqlboiler/v4/boil"
	"github.com/segmentio/kafka-go"

	// --- OpenTelemetry ---
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
)

type SBOMEvent struct {
	SBOMID     string              `json:"sbom_id"`
	Project    string              `json:"project_name"`
	Components []map[string]string `json:"components"`
}

const (
	maxRetry     = 3
	retryDelay   = 5 * time.Second
	parallelism  = 10 //max concurrrent OSV queries
	cacheTTL     = 24 * time.Hour
	redisHashKey = "sbom:%s:hash"
)

var (
	meter     metric.Meter
	scanCount metric.Int64Counter
)

// --- Khởi tạo OpenTelemetry Metrics (gọi từ main.go hoặc init) ---
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

		var evt SBOMEvent
		if err := json.Unmarshal(m.Value, &evt); err != nil {
			log.Println("[VulnService] invalid SBOM event payload:", err)
			publishToDLQ(m, err)
			_ = r.CommitMessages(context.Background(), m)
			continue
		}

		ctx, span := otel.Tracer("vuln-service").Start(context.Background(), "ProcessSBOMEvent")
		span.SetAttributes(attribute.String("sbom.id", evt.SBOMID), attribute.String("project.name", evt.Project))
		start := time.Now()

		success := false
		for attempt := 1; attempt <= maxRetry; attempt++ {
			if err := processEvent(evt, db); err != nil {
				log.Printf("[VulnService] attempt %d failed for SBOMID %s: %v", attempt, evt.SBOMID, err)
				time.Sleep(retryDelay)
			} else {
				success = true
				break
			}
		}

		if !success {
			log.Printf("[VulnService] pushing SBOMID %s to DLQ after %d failed attempts", evt.SBOMID, maxRetry)
			publishToDLQMessage(evt)
		}

		scanCount.Add(ctx, 1,
			metric.WithAttributes(
				attribute.String("sbom.id", evt.SBOMID),
				attribute.String("project.name", evt.Project),
				attribute.Bool("success", success),
			),
		)

		log.Printf("[VulnService] SBOMID %s processed in %s, success=%v, components=%d",
			evt.SBOMID, time.Since(start), success, len(evt.Components))
		span.End()

		if err := r.CommitMessages(ctx, m); err != nil {
			log.Println("[VulnService] commit error:", err)
		}
	}
}

func processEvent(evt SBOMEvent, db *sql.DB) error {
	ctx := context.Background()

	if len(evt.Components) == 0 {
		log.Println("[VulnService] No components to process for SBOMID:", evt.SBOMID)
		return nil
	}

	// ✅ Generate stable hash of component list
	compBytes, _ := json.Marshal(evt.Components)
	hash := sha256.Sum256(compBytes)
	hashStr := hex.EncodeToString(hash[:])
	cacheKey := fmt.Sprintf(redisHashKey, evt.SBOMID)

	// 🔍 Check cache
	cachedHash, err := redis.Client.Get(ctx, cacheKey).Result()
	if err == nil && cachedHash == hashStr {
		log.Printf("[Cache] SBOM %s unchanged (hash=%s), skipping reprocess", evt.SBOMID, hashStr[:10])
		return nil
	}

	// ❌ Delete all old vulnerabilities for this SBOM
	if _, err := db.ExecContext(ctx, "DELETE FROM vulnerabilities WHERE sbom_id=$1", evt.SBOMID); err != nil {
		return fmt.Errorf("failed to clear old vulnerabilities: %w", err)
	}

	// 🧠 Query OSV for each component (parallelized)
	osvRecords := make([]config.OSVRecord, 0, len(evt.Components))
	for _, c := range evt.Components {
		name := c["name"]
		version := c["version"]
		if name == "" || version == "" {
			continue
		}
		ecosystem := mapTypeToEcosystem(c["type"])
		if ecosystem == "" {
			ecosystem = "npm"
		}
		osvRecords = append(osvRecords, config.OSVRecord{
			Package: struct {
				Name      string "json:\"name\""
				Ecosystem string "json:\"ecosystem\""
			}{name, ecosystem},
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

	// 🧩 Insert new vulnerabilities
	for i := 0; i < len(osvRecords); i++ {
		item := <-resultsCh
		if item.Err != nil {
			log.Printf("[VulnService] OSV query failed for %s@%s: %v", item.Comp.Package.Name, item.Comp.Version, item.Err)
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
					severity = interfaceToStringPtr(first["severity"])
				}
			}
		}

		v := models.Vulnerability{
			SbomID:           evt.SBOMID,
			ProjectName:      null.StringFrom(evt.Project),
			ComponentName:    item.Comp.Package.Name,
			ComponentVersion: item.Comp.Version,
			VulnID:           null.StringFromPtr(vulnID),
			Severity:         null.StringFromPtr(severity),
			OsvMetadata:      null.JSONFrom(metaBytes),
		}

		if err := v.Insert(ctx, db, boil.Infer()); err != nil {
			log.Printf("[VulnService] Insert vuln failed for %s: %v", item.Comp.Package.Name, err)
		}
	}

	// ✅ Update cache
	redis.Client.Set(ctx, cacheKey, hashStr, cacheTTL)
	redis.Client.Set(ctx, fmt.Sprintf("sbom:%s:count", evt.SBOMID), len(evt.Components), cacheTTL)

	log.Printf("[Cache] Updated SBOM %s (hash=%s, count=%d)", evt.SBOMID, hashStr[:10], len(evt.Components))
	return nil
}

// map type -> OSV ecosystem
func mapTypeToEcosystem(t string) string {
	switch strings.ToLower(t) {
	case "npm", "javascript", "library":
		return "npm"
	case "pypi", "python":
		return "PyPI"
	case "maven", "java":
		return "Maven"
	case "golang", "go":
		return "Go"
	// ... thêm nếu cần
	default:
		return ""
	}
}

// interface{} to *string
func interfaceToStringPtr(v interface{}) *string {
	if v == nil {
		return nil
	}
	var s string
	switch val := v.(type) {
	case string:
		s = val
	case []byte:
		s = string(val)
	default:
		s = fmt.Sprintf("%v", val)
	}
	return &s
}

// publishToDLQ publishes the original Kafka message to a Dead Letter Queue
func publishToDLQ(msg kafka.Message, cause error) {
	dlqWriter := kafka.Writer{
		Addr:     kafka.TCP(strings.Split(config.LoadConfig().KafkaBroker, ",")...),
		Topic:    config.LoadConfig().DLQTopic,
		Balancer: &kafka.LeastBytes{},
	}
	defer dlqWriter.Close()

	payload := map[string]interface{}{
		"key":   string(msg.Key),
		"value": string(msg.Value),
		"error": cause.Error(),
		"time":  time.Now().UTC(),
	}
	data, _ := json.Marshal(payload)
	err := dlqWriter.WriteMessages(context.Background(), kafka.Message{
		Key:   msg.Key,
		Value: data,
	})
	if err != nil {
		log.Println("[VulnService] failed to publish to DLQ:", err)
	}
}

// publishToDLQMessage publishes a SBOMEvent to DLQ
func publishToDLQMessage(evt SBOMEvent) {
	dlqWriter := kafka.Writer{
		Addr:     kafka.TCP(strings.Split(config.LoadConfig().KafkaBroker, ",")...),
		Topic:    config.LoadConfig().DLQTopic,
		Balancer: &kafka.LeastBytes{},
	}
	defer dlqWriter.Close()

	data, _ := json.Marshal(map[string]interface{}{
		"sbom_id":    evt.SBOMID,
		"project":    evt.Project,
		"components": evt.Components,
		"time":       time.Now().UTC(),
	})
	err := dlqWriter.WriteMessages(context.Background(), kafka.Message{
		Key:   []byte(evt.SBOMID),
		Value: data,
	})
	if err != nil {
		log.Println("[VulnService] failed to publish SBOMEvent to DLQ:", err)
	}
}
