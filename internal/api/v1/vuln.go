package v1

import (
	"encoding/json"
	"log"
	"myesi-vuln-service-golang/internal/config"
	"myesi-vuln-service-golang/internal/db"
	"myesi-vuln-service-golang/utils"
	"strings"

	fiber "github.com/gofiber/fiber/v2"
	kafka "github.com/segmentio/kafka-go"
)

func RegisterVulnRoutes(app *fiber.App) {
	r := app.Group("/api/vuln")
	r.Get("/health", HealthCheck)
	r.Post("/refresh", refreshVuln)    //refreshVuln triggers a re-scan: either publish a Kafka event or run inline
	r.Get("/stream", utils.StreamVulnerabilities)
	r.Get("/:sbom_id", getVulnsBySBOM) //getVulnsBySBOM returns stored vulnerabilities for an sbom_id
	
}

// @Summary Health check
// @Description Check if vuln service is alive
// @Tags health
// @Produce plain
// @Success 200 {string} string "ok"
// @Router /health [get]
func HealthCheck(c *fiber.Ctx) error { return c.SendString("ok") }

// @Summary Get vulnerabilities by SBOM ID
// @Description Returns all vulnerabilities stored for a given SBOM
// @Tags vulnerability
// @Produce json
// @Param sbom_id path string true "SBOM ID"
// @Success 200 {array} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /{sbom_id} [get]
func getVulnsBySBOM(c *fiber.Ctx) error {
	sbomID := c.Params("sbom_id")
	if sbomID == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "sbom_id required",
		})
	}
	vulns, _ := utils.FindVulnsBySbomID(c.Context(), db.Conn, sbomID)

	return c.JSON(vulns)
}

type RefreshRequest struct {
	SBOMID     string              `json:"sbom_id"`
	Project    string              `json:"project_name,omitempty"`
	Components []map[string]string `json:"components,omitempty"`
}

// @Summary Refresh vulnerabilities
// @Description Trigger vulnerability scan / refresh via Kafka
// @Tags vulnerability
// @Accept json
// @Produce json
// @Param request body RefreshRequest true "Refresh request body"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /refresh [post]
func refreshVuln(c *fiber.Ctx) error {
	var req RefreshRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
	}
	if req.SBOMID == "" && len(req.Components) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "sbom_id or components required"})
	}

	//If components present, publish event with them. Otherwise publish event referencing sbom_id only
	w := kafka.Writer{
		Addr:  kafka.TCP(strings.Split(config.LoadConfig().KafkaBroker, ",")...),
		Topic: config.LoadConfig().KafkaTopic,
	}
	defer w.Close()

	event := map[string]interface{}{
		"sbom_id": req.SBOMID,
		"project": req.Project,
	}
	if len(req.Components) > 0 {
		event["components"] = req.Components
	}
	data, _ := json.Marshal(event)
	msg := kafka.Message{
		Key:   []byte(req.SBOMID),
		Value: data,
	}
	if err := w.WriteMessages(c.Context(), msg); err != nil {
		log.Println("publish refresh error: ", err)
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"message": "refresh queued"})
}


