package redis

import (
	"context"
	"log"
	"myesi-vuln-service-golang/internal/config"
	"time"

	"github.com/redis/go-redis/v9"
)

var Client *redis.Client

func InitRedis() {
	cfg := config.LoadConfig()
	Client = redis.NewClient(&redis.Options{
		Addr:     cfg.RedisURL,
		Password: "",
		DB:       0,
	})
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
