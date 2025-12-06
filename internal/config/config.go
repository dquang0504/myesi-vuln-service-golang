package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

type Config struct {
	RedisURL            string
	KafkaBroker         string
	KafkaTopic          string
	DLQTopic            string
	DatabaseURL         string
	ConsumerGroup       string
	Port                string
	SchedulerSpec       string `yaml:"scheduler_spec"`
	SchedulerBatchLimit int    `yaml:"scheduler_batch_limit"`
	RepoCleanupSpec     string `yaml:"repo_cleanup_spec"`
	RepoRetentionDays   int    `yaml:"repo_retention_days"`
}

func LoadConfig() *Config {
	_ = godotenv.Load()
	cfg := &Config{
		RedisURL:          getEnv("REDIS_URL", "localhost:6379"),
		KafkaBroker:       getEnv("KAFKA_BROKER", "localhost:9092"),
		KafkaTopic:        getEnv("KAFKA_TOPIC", "sbom-events"),
		DLQTopic:          getEnv("DLQ_TOPIC", "sbom-events-dlq"),
		DatabaseURL:       getEnv("DATABASE_URL", "postgres://myesi:123456789@localhost:5432/myesi_db?sslmode=disable"),
		ConsumerGroup:     getEnv("CONSUMER_GROUP", "myesi-vuln-group"),
		Port:              getEnv("PORT", "8080"),
		RepoCleanupSpec:   "@daily",
		RepoRetentionDays: 7,
	}

	// --- Load optional scheduler.yml if present ---
	if file, err := os.ReadFile("internal/config/scheduler.yml"); err == nil {
		var y Config
		if err := yaml.Unmarshal(file, &y); err == nil {
			if y.SchedulerSpec != "" {
				cfg.SchedulerSpec = y.SchedulerSpec
			}
			if y.SchedulerBatchLimit > 0 {
				cfg.SchedulerBatchLimit = y.SchedulerBatchLimit
			}
			if y.KafkaBroker != "" {
				cfg.KafkaBroker = y.KafkaBroker
			}
			if y.KafkaTopic != "" {
				cfg.KafkaTopic = y.KafkaTopic
			}
			if y.ConsumerGroup != "" {
				cfg.ConsumerGroup = y.ConsumerGroup
			}
			if y.RepoCleanupSpec != "" {
				cfg.RepoCleanupSpec = y.RepoCleanupSpec
			}
			if y.RepoRetentionDays > 0 {
				cfg.RepoRetentionDays = y.RepoRetentionDays
			}
		}
	}

	log.Printf("[CONFIG] Loaded configuration: %+v\n", cfg)
	return cfg
}

func getEnv(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}
