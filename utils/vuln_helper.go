package utils

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"myesi-vuln-service-golang/models"
	"time"

	"github.com/aarondl/sqlboiler/v4/queries/qm"
	"github.com/gofiber/fiber/v2"
)

func FindVulnsBySbomID(ctx context.Context, db *sql.DB, sbomID string) ([]*models.Vulnerability, error) {
	return models.Vulnerabilities(
		qm.Where("sbom_id=?", sbomID),
	).All(ctx, db)
}

type SSEClient struct {
	Chan chan []byte
}

var clients = map[string][]*SSEClient{} // key = project_name

func StreamVulnerabilities(c *fiber.Ctx) error {
	project := c.Query("project_name")
	if project == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project_name required"})
	}

	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")

	client := &SSEClient{Chan: make(chan []byte, 10)}
	clients[project] = append(clients[project], client)
	defer func() {
		// remove client on disconnect
		list := clients[project]
		for i, cl := range list {
			if cl == client {
				clients[project] = append(list[:i], list[i+1:]...)
				break
			}
		}
	}()

	// Fiber v2: loop viết trực tiếp vào c.Context().Write()
	for {
		select {
		case msg := <-client.Chan:
			_, err := c.Context().Write([]byte("data: " + string(msg) + "\n\n"))
			if err != nil {
				return err
			}
		case <-c.Context().Done():
			return nil
		case <-time.After(30 * time.Second):
			// ping để giữ kết nối sống
			_, err := c.Context().Write([]byte(": ping\n\n"))
			if err != nil {
				return err
			}
		}
	}
}

// Call this in processEvent after inserting a vuln record
func PublishVulnRealtime(project string, vuln map[string]interface{}) {
	msg, _ := json.Marshal(vuln)
	for _, client := range clients[project] {
		select {
		case client.Chan <- msg:
		default:
			log.Printf("[SSE] client channel full for project %s, skipping message", project)
		}
	}
}
