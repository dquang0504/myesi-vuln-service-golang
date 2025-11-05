package scheduler

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"myesi-vuln-service-golang/internal/config"
	"myesi-vuln-service-golang/internal/db"
	"myesi-vuln-service-golang/utils"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/segmentio/kafka-go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type SchedulerConfig struct {
	RunSpec    string `yaml:"run_spec"`    //e.g "0 2 * * *"
	BatchLimit int    `yaml:"batch_limit"` //number of SBOM per run
}

// LoadSchedulerConfig — fallback defaults if not present
func LoadSchedulerConfig() SchedulerConfig {
	cfg := SchedulerConfig{
		RunSpec:    "0 2 * * *", // default 2 AM UTC
		BatchLimit: 20,
	}
	yamlCfg := config.LoadConfig() // your existing YAML loader
	if yamlCfg.SchedulerSpec != "" {
		cfg.RunSpec = yamlCfg.SchedulerSpec
	}
	if yamlCfg.SchedulerBatchLimit > 0 {
		cfg.BatchLimit = yamlCfg.SchedulerBatchLimit
	}
	return cfg
}

func StartDailyScheduler() {
	cfg := LoadSchedulerConfig()
	meter := otel.Meter("vuln-scheduler")
	runCount, _ := meter.Int64Counter("scheduler.run.count")
	sbomCount, _ := meter.Int64Counter("scheduler.sbom.enqueued")

	c := cron.New(cron.WithSeconds())

	_, err := c.AddFunc(cfg.RunSpec, func() {
		ctx := context.Background()
		start := time.Now()
		log.Printf("[Scheduler] Starting OSV refresh batch - cron: %s", cfg.RunSpec)

		count, err := runOnce(ctx, db.Conn, cfg.BatchLimit)
		if err != nil {
			log.Printf("[Scheduler] error: %v", err)
		}
		runCount.Add(ctx, 1)
		sbomCount.Add(ctx, int64(count),
			metric.WithAttributes(attribute.String("status", "completed")),
		)
		log.Printf("[Scheduler] Completed OSV batch in %s — queued=%d", time.Since(start), count)
	})
	if err != nil {
		log.Printf("[Scheduler] Failed to schedule job: %v", err)
		return
	}

	c.Start()
	log.Printf("[Scheduler] OSV scheduler initialized — runs at '%s' UTC", cfg.RunSpec)
}

func runOnce(ctx context.Context, conn *sql.DB, limit int) (int, error) {
	rows, err := conn.QueryContext(ctx, `
		SELECT id, project_name, sbom
		FROM sboms
		WHERE updated_at < NOW() - INTERVAL '10 seconds'
		ORDER BY updated_at ASC
		LIMIT $1
	`, limit)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	writer := kafka.Writer{
		Addr:     kafka.TCP(config.LoadConfig().KafkaBroker),
		Topic:    config.LoadConfig().KafkaTopic,
		Balancer: &kafka.LeastBytes{},
	}
	defer writer.Close()

	count := 0
	for rows.Next() {
		var id, project string
		var sbomData []byte
		if err := rows.Scan(&id, &project, &sbomData); err != nil {
			continue
		}

		// Parse JSON SBOM để lấy danh sách components
		var sbom map[string]interface{}
		if err := json.Unmarshal(sbomData, &sbom); err != nil {
			log.Printf("[Scheduler] Failed to parse SBOM for %s: %v", id, err)
			continue
		}

		components := utils.ExtractComponents(sbom)
		if len(components) == 0 {
			log.Printf("[Scheduler] SBOM %s has no components", id)
			continue
		}

		event := map[string]interface{}{
			"sbom_id":        id,
			"project_name":   project,
			"components":     components,
			"auto_triggered": true,
			"timestamp":      time.Now().UTC(),
		}
		data, _ := json.Marshal(event)

		msg := kafka.Message{Key: []byte(id), Value: data}
		if err := writer.WriteMessages(ctx, msg); err != nil {
			log.Printf("[Scheduler] Failed to publish %s: %v", id, err)
			continue
		}
		count++
	}
	return count, nil
}
