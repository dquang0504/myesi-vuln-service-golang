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
	"myesi-vuln-service-golang/internal/scheduler"
	"myesi-vuln-service-golang/internal/services"
	"os"
	"os/signal"
	"syscall"

	fiber "github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
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
	//init scheduler
	go scheduler.StartDailyScheduler()
	go scheduler.StartRepoCleanupScheduler()

	if err := consumer.InitMetrics(); err != nil {
		log.Fatalf("failed to init metrics: %v", err)
	}

	go services.StartCronJobs()

	//start API
	app := fiber.New()
	// ✅ Enable CORS
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "https://localhost:8000, https://127.0.0.1:8000, https://localhost:3000", // chỉ gateway gọi được
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		ExposeHeaders:    "Content-Length",
		AllowCredentials: true, // vẫn giữ true nếu cần cookie / token
	}))

	api := app.Group("/api/vuln")
	v1.RegisterAnalystRoutes(api)
	v1.RegisterVulnRoutes(api)

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
