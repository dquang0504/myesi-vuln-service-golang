package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"myesi-vuln-service-golang/internal/config"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
)

// VulnProcessedPayload defines the schema for vuln.processed event
type VulnProcessedPayload struct {
	Type        string                   `json:"type"`
	SBOMID      string                   `json:"sbom_id"`
	ProjectName string                   `json:"project_name"`
	Components  []map[string]interface{} `json:"components"`
	Timestamp   time.Time                `json:"timestamp"`
	Hash        string                   `json:"hash,omitempty"`
}

// EnsureKafkaTopicExists checks if a Kafka topic exists and creates it if missing.
// Safe to call on every publish — no duplicate topics will be created.
func EnsureKafkaTopicExists(broker, topic string, partitions int) {
	// Kết nối tới broker đầu tiên
	conn, err := kafka.Dial("tcp", broker)
	if err != nil {
		log.Printf("[Kafka] ⚠️ Failed to connect to broker %s: %v", broker, err)
		return
	}
	defer conn.Close()

	controller, err := conn.Controller()
	if err != nil {
		log.Printf("[Kafka] ⚠️ Failed to get controller: %v", err)
		return
	}

	controllerAddr := fmt.Sprintf("%s:%d", controller.Host, controller.Port)
	controllerConn, err := kafka.Dial("tcp", controllerAddr)
	if err != nil {
		log.Printf("[Kafka] ⚠️ Failed to connect to controller at %s: %v", controllerAddr, err)
		return
	}
	defer controllerConn.Close()

	err = controllerConn.CreateTopics(kafka.TopicConfig{
		Topic:             topic,
		NumPartitions:     partitions,
		ReplicationFactor: 1,
	})
	if err != nil {
		// Không sao nếu topic đã tồn tại
		if !strings.Contains(err.Error(), "Topic with this name already exists") {
			log.Printf("[Kafka] ⚠️ Could not create topic %q: %v", topic, err)
		}
	} else {
		log.Printf("[Kafka] ✅ Topic ensured: %s", topic)
	}

	// Cho Kafka vài giây sync metadata
	time.Sleep(1 * time.Second)
}

// ProduceVulnProcessed publishes a processed SBOM event to Kafka
func ProduceVulnProcessed(evt VulnProcessedPayload) error {
	cfg := config.LoadConfig()
	broker := strings.Split(cfg.KafkaBroker, ",")[0]

	// 🔧 Ensure topic exists trước khi publish
	EnsureKafkaTopicExists(broker, "vuln.processed", 1)

	data, err := json.Marshal(evt)
	if err != nil {
		return err
	}

	writer := kafka.Writer{
		Addr:         kafka.TCP(strings.Split(cfg.KafkaBroker, ",")...),
		Topic:        "vuln.processed",
		Balancer:     &kafka.LeastBytes{},
		RequiredAcks: kafka.RequireAll,
	}
	defer writer.Close()

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
