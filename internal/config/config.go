package config

import (
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

const defaultKafkaTopic = "sbom-events"

type Config struct {
	RedisURL            string
	KafkaBroker         string
	KafkaTopic          string
	AutoCreateTopics    bool
	DLQTopic            string
	DatabaseURL         string
	ConsumerGroup       string
	Port                string
	SchedulerSpec       string `yaml:"scheduler_spec"`
	SchedulerBatchLimit int    `yaml:"scheduler_batch_limit"`
	RepoCleanupSpec     string `yaml:"repo_cleanup_spec"`
	RepoRetentionDays   int    `yaml:"repo_retention_days"`
	SLABreachSpec       string `yaml:"sla_breach_spec"`
	FrontendBaseURL     string `yaml:"frontend_base_url"`
}

func LoadConfig() *Config {
	_ = godotenv.Load()
	cfg := &Config{
		RedisURL:          getEnv("REDIS_URL", "localhost:6379"),
		KafkaBroker:       getEnv("KAFKA_BROKER", "localhost:9092"),
		KafkaTopic:        getEnv("KAFKA_TOPIC", defaultKafkaTopic),
		AutoCreateTopics:  getEnvBool("KAFKA_AUTO_CREATE_TOPICS", false),
		DLQTopic:          getEnv("DLQ_TOPIC", "sbom-events-dlq"),
		DatabaseURL:       getEnv("DATABASE_URL", "postgres://myesi:123456789@localhost:5432/myesi_db?sslmode=disable"),
		ConsumerGroup:     getEnv("CONSUMER_GROUP", "myesi-vuln-group"),
		Port:              getEnv("PORT", "8080"),
		RepoCleanupSpec:   "@daily",
		RepoRetentionDays: 7,
		SLABreachSpec:     "@daily",
		FrontendBaseURL:   getEnv("FRONTEND_APP_URL", "https://localhost:3000"),
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
			if y.AutoCreateTopics {
				cfg.AutoCreateTopics = y.AutoCreateTopics
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
			if y.SLABreachSpec != "" {
				cfg.SLABreachSpec = y.SLABreachSpec
			}
			if y.FrontendBaseURL != "" {
				cfg.FrontendBaseURL = y.FrontendBaseURL
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

func getEnvBool(key string, defaultValue bool) bool {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return defaultValue
	}
	if b, err := strconv.ParseBool(val); err == nil {
		return b
	}
	return defaultValue
}
