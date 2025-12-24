package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"myesi-vuln-service-golang/internal/events"
	kafkautil "myesi-vuln-service-golang/internal/kafka"
	"time"

	"github.com/segmentio/kafka-go"
)

// VulnProcessedPayload defines the schema for vuln.processed event data.
type VulnProcessedPayload struct {
	SBOMID         string                   `json:"sbom_id"`
	ProjectName    string                   `json:"project_name"`
	OrganizationID int64                    `json:"organization_id,omitempty"`
	Components     []map[string]interface{} `json:"components"`
	Timestamp      time.Time                `json:"timestamp"`
	Hash           string                   `json:"hash,omitempty"`
	Status         string                   `json:"status"`
	Error          string                   `json:"error,omitempty"`
}

// ProduceVulnProcessed publishes a processed SBOM event to Kafka
func ProduceVulnProcessed(evt VulnProcessedPayload) error {
	payload := events.NewEnvelope("vuln.processed", evt.OrganizationID, evt.ProjectName, evt)
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	writer, err := kafkautil.GetWriter(kafkautil.TopicVulnProcessed)
	if err != nil {
		return fmt.Errorf("kafka writer unavailable: %w", err)
	}

	msg := kafka.Message{
		Key:   []byte(evt.SBOMID),
		Value: data,
		Time:  time.Now().UTC(),
	}

	// Retry an toàn (Kafka đôi khi cần vài giây để sync topic)
	for attempt := 1; attempt <= 5; attempt++ {
		if err := writer.WriteMessages(context.Background(), msg); err != nil {
			log.Printf("[Kafka] ⚠️ Publish attempt %d failed: %v", attempt, err)
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}
		log.Printf("[Kafka] ✅ Published vuln.processed for SBOM %s (%d components)",
			evt.SBOMID, len(evt.Components))
		return nil
	}

	log.Printf("[Kafka] ❌ Failed to publish vuln.processed after retries for %s", evt.SBOMID)
	return fmt.Errorf("kafka publish failed after retries")
}
