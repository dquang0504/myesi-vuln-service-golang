package kafka

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"myesi-vuln-service-golang/internal/config"

	kafkago "github.com/segmentio/kafka-go"
)

var (
	writerPool sync.Map
	cfgOnce    sync.Once
	writerCfg  struct {
		brokers        []string
		autoCreate     bool
		initializedErr error
	}
)

// GetWriter returns a shared kafka.Writer for the given topic. Writers are
// cached and must not be closed by callers.
func GetWriter(topic string) (*kafkago.Writer, error) {
	if strings.TrimSpace(topic) == "" {
		return nil, errors.New("topic is required")
	}
	if writer, ok := writerPool.Load(topic); ok {
		return writer.(*kafkago.Writer), nil
	}

	cfgOnce.Do(func() {
		cfg := config.LoadConfig()
		writerCfg.brokers = splitAndTrim(cfg.KafkaBroker)
		if len(writerCfg.brokers) == 0 {
			writerCfg.initializedErr = errors.New("kafka broker list is empty")
			return
		}
		writerCfg.autoCreate = cfg.AutoCreateTopics
	})
	if writerCfg.initializedErr != nil {
		return nil, writerCfg.initializedErr
	}
	if len(writerCfg.brokers) == 0 {
		return nil, errors.New("no kafka brokers configured")
	}

	if writerCfg.autoCreate {
		ensureTopicExists(writerCfg.brokers[0], topic, 1)
	}

	writer := &kafkago.Writer{
		Addr:         kafkago.TCP(writerCfg.brokers...),
		Topic:        topic,
		Balancer:     &kafkago.LeastBytes{},
		RequiredAcks: kafkago.RequireAll,
	}

	actual, loaded := writerPool.LoadOrStore(topic, writer)
	if loaded {
		_ = writer.Close()
		return actual.(*kafkago.Writer), nil
	}
	return writer, nil
}

// CloseWriters drains the shared writer pool; call during service shutdown.
func CloseWriters() {
	writerPool.Range(func(_, value interface{}) bool {
		if w, ok := value.(*kafkago.Writer); ok {
			_ = w.Close()
		}
		return true
	})
}

func splitAndTrim(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func ensureTopicExists(broker, topic string, partitions int) {
	if broker == "" || topic == "" {
		return
	}

	conn, err := kafkago.Dial("tcp", broker)
	if err != nil {
		log.Printf("[Kafka] ⚠️ auto-create disabled (dial failed %s): %v", broker, err)
		return
	}
	defer conn.Close()

	controller, err := conn.Controller()
	if err != nil {
		log.Printf("[Kafka] ⚠️ controller lookup failed: %v", err)
		return
	}

	controllerAddr := fmt.Sprintf("%s:%d", controller.Host, controller.Port)
	controllerConn, err := kafkago.Dial("tcp", controllerAddr)
	if err != nil {
		log.Printf("[Kafka] ⚠️ controller dial failed: %v", err)
		return
	}
	defer controllerConn.Close()

	err = controllerConn.CreateTopics(kafkago.TopicConfig{
		Topic:             topic,
		NumPartitions:     partitions,
		ReplicationFactor: 1,
	})
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			log.Printf("[Kafka] ⚠️ could not create topic %q: %v", topic, err)
		}
	} else {
		log.Printf("[Kafka] ✅ ensured topic: %s", topic)
	}

	time.Sleep(time.Second)
}
