package redis

import (
	"context"
	"log"
	"myesi-vuln-service-golang/internal/config"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var Client *redis.Client

func InitRedis() {
	cfg := config.LoadConfig()
	var opts *redis.Options

	if strings.HasPrefix(cfg.RedisURL, "redis://") {
		parsed, err := redis.ParseURL(cfg.RedisURL)
		if err != nil {
			log.Fatalf("[REDIS] Invalid REDIS_URL (%s): %v", cfg.RedisURL, err)
		}
		opts = parsed
	} else {
		opts = &redis.Options{
			Addr: cfg.RedisURL,
			DB:   0,
		}
	}

	Client = redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := Client.Ping(ctx).Err(); err != nil {
		log.Fatalf("[REDIS] Failed to connect: %v", err)
	}

	log.Println("[REDIS] Connected successfully to", cfg.RedisURL)
}

func CloseRedis() {
	if Client != nil {
		if err := Client.Close(); err != nil {
			log.Printf("[REDIS] Error closing connection: %v", err)
		} else {
			log.Println("[REDIS] Connection closed")
		}
	}
}
