package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	RedisURL      string
	KafkaBroker   string
	KafkaTopic    string
	DLQTopic      string
	DatabaseURL   string
	OSVURL        string
	ConsumerGroup string
	Port          string
}

func LoadConfig() *Config {
	_ = godotenv.Load()
	cfg := &Config{
		RedisURL:      getEnv("REDIS_URL", "localhost:6379"),
		KafkaBroker:   getEnv("KAFKA_BROKER", "localhost:9092"),
		KafkaTopic:    getEnv("KAFKA_TOPIC", "sbom-events"),
		DLQTopic:      getEnv("DLQ_TOPIC", "sbom-events-dlq"),
		DatabaseURL:   getEnv("DATABASE_URL", "postgres://myesi:123456789@localhost:5432/myesi_db?sslmode=disable"),
		OSVURL:        getEnv("OSV_URL", "https://api.osv.dev/v1/querybatch"),
		ConsumerGroup: getEnv("CONSUMER_GROUP", "myesi-vuln-group"),
		Port:          getEnv("PORT", "8080"),
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

// --- Map SBOM components → OSV batch format ---
type OSVRecord struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}
