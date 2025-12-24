package utils

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"myesi-vuln-service-golang/internal/config"
	"myesi-vuln-service-golang/internal/events"
	kafkautil "myesi-vuln-service-golang/internal/kafka"
	"myesi-vuln-service-golang/models"
	"sync"
	"time"

	"github.com/aarondl/sqlboiler/v4/boil"
	"github.com/aarondl/sqlboiler/v4/queries"
	"github.com/aarondl/sqlboiler/v4/queries/qm"
	"github.com/gofiber/fiber/v2"
	"github.com/segmentio/kafka-go"
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

func UpdateProjectSummary(ctx context.Context, exec boil.ContextExecutor, projectName string) error {
	// Step 1: Count vulns
	var total int
	row := queries.Raw(`
        SELECT COUNT(*) FROM vulnerabilities WHERE project_name = $1 AND is_active = TRUE
    `, projectName).QueryRowContext(ctx, exec.(*sql.DB))
	if err := row.Scan(&total); err != nil {
		return err
	}

	// Step 2: Update summary
	_, err := queries.Raw(`
        UPDATE projects
        SET total_vulnerabilities = $2,
            last_vuln_scan = NOW(),
            updated_at = NOW()
        WHERE name = $1;
    `, projectName, total).ExecContext(ctx, exec)
	if err == nil {
		log.Printf("[Project] Updated %s (total_vulnerabilities=%d)", projectName, total)
	}
	return err
}

type VulnProcessedBatchPayload struct {
	ProjectName    string                 `json:"project_name"`
	OrganizationID int64                  `json:"organization_id,omitempty"`
	Records        []VulnProcessedPayload `json:"records"`
	Timestamp      time.Time              `json:"timestamp"`
}

func ProduceVulnProcessedBatch(payload VulnProcessedBatchPayload) error {
	_ = config.LoadConfig()
	writer, err := kafkautil.GetWriter(kafkautil.TopicVulnProcessed)
	if err != nil {
		return fmt.Errorf("kafka writer unavailable: %w", err)
	}

	env := events.NewEnvelope("vuln.processed.batch", payload.OrganizationID, payload.ProjectName, payload)
	data, _ := json.Marshal(env)
	err = writer.WriteMessages(context.Background(), kafka.Message{
		Key:   []byte(payload.ProjectName),
		Value: data,
	})
	if err != nil {
		log.Printf("[KAFKA][ERR] write batch: %v", err)
		return err
	}
	return nil
}

// (unused query helpers removed in favor of DAO-specific implementations)
