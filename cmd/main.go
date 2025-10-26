// @title MyESI Vulnerability Service API
// @version 1.0
// @description API for managing vulnerabilities from SBOM.
// @host localhost:8003
// @BasePath /api/vuln

package main

import (
	"context"
	"log"
	_ "myesi-vuln-service-golang/docs"
	v1 "myesi-vuln-service-golang/internal/api/v1"
	"myesi-vuln-service-golang/internal/config"
	"myesi-vuln-service-golang/internal/consumer"
	"myesi-vuln-service-golang/internal/db"
	"myesi-vuln-service-golang/internal/redis"
	"os"
	"os/signal"
	"syscall"

	fiber "github.com/gofiber/fiber/v2"
	fiberSwagger "github.com/gofiber/swagger"
)

func main() {
	//load configs
	cfg := config.LoadConfig()

	//connect to db and redis
	db.InitPostgres(cfg.DatabaseURL)
	redis.InitRedis()
	defer db.CloseDB()
	defer redis.CloseRedis()

	//init kafka consumer
	go func() {
		if err := consumer.StartConsumer(db.Conn); err != nil {
			log.Fatalf("consume error: %v", err)
		}
	}()

	if err := consumer.InitMetrics(); err != nil {
		log.Fatalf("failed to init metrics: %v", err)
	}

	//start API
	app := fiber.New()
	v1.RegisterVulnRoutes(app)

	// Swagger UI
	app.Get("/swagger/*", fiberSwagger.HandlerDefault)

	// Start server
	go func() {
		if err := app.Listen(":8003"); err != nil {
			log.Fatalf("failed to start server: %v", err)
		}
	}()

	//setup graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Println("[STARTUP] Vulnerability Service running...")

	//wait until shutdown
	<-ctx.Done()

	log.Println("[EXIT] Vulnerability stopped gracefully")
}
