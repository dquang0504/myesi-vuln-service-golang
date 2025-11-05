package utils

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"myesi-vuln-service-golang/models"
	"sync"
	"time"

	"github.com/aarondl/sqlboiler/v4/queries/qm"
	"github.com/gofiber/fiber/v2"
)

type SSEClient struct {
	Chan   chan []byte
	Close  chan struct{}
	Writer io.Writer
}

var (
	SSEClients = make(map[string][]*SSEClient)
	mu         sync.Mutex
)

// AddSSEClient thêm client mới vào project
func AddSSEClient(project string, c *SSEClient) {
	mu.Lock()
	defer mu.Unlock()
	SSEClients[project] = append(SSEClients[project], c)
}

// RemoveSSEClient xóa client
func RemoveSSEClient(project string, c *SSEClient) {
	mu.Lock()
	defer mu.Unlock()
	list := SSEClients[project]
	for i, cl := range list {
		if cl == c {
			SSEClients[project] = append(list[:i], list[i+1:]...)
			break
		}
	}
}

// BroadcastVulnEvent gửi message tới tất cả client của project và global
func BroadcastVulnEvent(project string, payload interface{}) {
	msg, err := json.Marshal(payload)
	if err != nil {
		log.Println("[SSE] Failed to marshal payload:", err)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	targets := append(SSEClients[project], SSEClients["*"]...)
	for _, client := range targets {
		select {
		case client.Chan <- msg:
		default:
			// client không đọc kịp -> đóng kết nối
			close(client.Close)
		}
	}
}

// Fiber handler SSE
func StreamVulnerabilities(c *fiber.Ctx) error {
	project := c.Query("project_name", "*") // default global
	ctx := c.Context()

	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("Access-Control-Allow-Origin", "*")

	client := &SSEClient{
		Chan:   make(chan []byte, 16),
		Close:  make(chan struct{}),
		Writer: ctx.Response.BodyWriter(), // <-- sửa ở đây, io.Writer
	}

	AddSSEClient(project, client)

	// Heartbeat
	go func() {
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-client.Close:
				return
			case <-ticker.C:
				fmt.Fprintf(client.Writer, ":\n\n")
				if f, ok := client.Writer.(interface{ Flush() }); ok {
					f.Flush()
				}
			}
		}
	}()

	// Lắng nghe channel
	for {
		select {
		case <-ctx.Done():
			RemoveSSEClient(project, client)
			return nil
		case <-client.Close:
			RemoveSSEClient(project, client)
			return nil
		case msg := <-client.Chan:
			fmt.Fprintf(client.Writer, "data: %s\n\n", msg)
			if f, ok := client.Writer.(interface{ Flush() }); ok {
				f.Flush()
			}
		}
	}
}

func FindVulnsBySbomID(ctx context.Context, db *sql.DB, sbomID string) ([]*models.Vulnerability, error) {
	return models.Vulnerabilities(qm.Where("sbom_id=?", sbomID)).All(ctx, db)
}
