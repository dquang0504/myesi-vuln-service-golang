package utils

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"myesi-vuln-service-golang/internal/config"
	"myesi-vuln-service-golang/internal/db"
	"myesi-vuln-service-golang/internal/schemas"
	"myesi-vuln-service-golang/models"
	"strconv"
	"strings"
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
	Type        string                 `json:"type"`
	ProjectName string                 `json:"project_name"`
	Records     []VulnProcessedPayload `json:"records"`
	Timestamp   time.Time              `json:"timestamp"`
}

func ProduceVulnProcessedBatch(payload VulnProcessedBatchPayload) error {
	cfg := config.LoadConfig()
	EnsureKafkaTopicExists(cfg.KafkaBroker, "vuln.processed", 1)
	w := kafka.Writer{
		Addr:  kafka.TCP(strings.Split(cfg.KafkaBroker, ",")...),
		Topic: "vuln.processed",
	}
	defer w.Close()

	data, _ := json.Marshal(payload)
	err := w.WriteMessages(context.Background(), kafka.Message{
		Key:   []byte(payload.ProjectName),
		Value: data,
	})
	if err != nil {
		log.Printf("[KAFKA][ERR] write batch: %v", err)
		return err
	}
	return nil
}

func GetProjectScanLimit(orgID int) (int, error) {
	query := `
        SELECT sp.project_scan_limit
        FROM organizations o
        JOIN subscriptions s ON s.id = o.subscription_id
        JOIN subscription_plans sp ON sp.id = s.plan_id
        WHERE o.id = $1
    `

	var limit int
	err := db.Conn.QueryRowContext(context.Background(), query, orgID).Scan(&limit)
	return limit, err
}

func QueryVulnAssignments(ctx context.Context, f struct {
	ProjectName string
	AssigneeID  *int64
	Status      string
	Limit       int
	Offset      int
}) ([]schemas.Assignment, int64, error) {

	where := []string{"v.is_active = TRUE"}
	args := []interface{}{}
	idx := 1

	if f.ProjectName != "" && f.ProjectName != "all" {
		where = append(where, "v.project_name = $"+strconv.Itoa(idx))
		args = append(args, f.ProjectName)
		idx++
	}
	if f.AssigneeID != nil {
		where = append(where, "va.assignee_id = $"+strconv.Itoa(idx))
		args = append(args, *f.AssigneeID)
		idx++
	}
	if f.Status != "" {
		where = append(where, "COALESCE(va.status, 'open') = $"+strconv.Itoa(idx))
		args = append(args, f.Status)
		idx++
	}

	whereSQL := strings.Join(where, " AND ")

	var total int64
	countQuery := `
        SELECT COUNT(DISTINCT v.id)
        FROM vulnerabilities v
        LEFT JOIN vulnerability_assignments va ON va.vulnerability_id = v.id
        JOIN sboms s ON s.id = v.sbom_id
        WHERE ` + whereSQL

	if err := db.Conn.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listQuery := `
        SELECT
            COALESCE(va.id, 0) AS assignment_id,
            v.id                AS vulnerability_id,
            COALESCE(va.assignee_id, 0),
            COALESCE(va.assigned_by, 0),
            COALESCE(va.status, 'open')          AS status,
            COALESCE(va.priority, 'medium')      AS priority,
            COALESCE(va.note, '')                AS note,
            va.due_date,
            COALESCE(va.created_at, v.created_at) AS created_at,
            COALESCE(va.updated_at, v.updated_at) AS updated_at,

            COALESCE(v.project_name,''), COALESCE(v.component_name,''), COALESCE(v.component_version,''), COALESCE(v.severity,''),
            COALESCE(u1.email,''), COALESCE(u2.email,''),

            -- source từ SBOM: manual | github | api
            COALESCE(s.source, 'manual') AS source
        FROM vulnerabilities v
        LEFT JOIN vulnerability_assignments va ON va.vulnerability_id = v.id
        LEFT JOIN users u1 ON u1.id = va.assignee_id
        LEFT JOIN users u2 ON u2.id = va.assigned_by
        JOIN sboms s ON s.id = v.sbom_id
        WHERE ` + whereSQL + `
        ORDER BY COALESCE(va.created_at, v.created_at) DESC
        LIMIT $` + strconv.Itoa(idx) + ` OFFSET $` + strconv.Itoa(idx+1)

	argsList := append(append([]interface{}{}, args...), f.Limit, f.Offset)

	rows, err := db.Conn.QueryContext(ctx, listQuery, argsList...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []schemas.Assignment{}
	for rows.Next() {
		var a schemas.Assignment
		if err := rows.Scan(
			&a.ID,
			&a.VulnerabilityID,
			&a.AssigneeID,
			&a.AssignedBy,
			&a.Status,
			&a.Priority,
			&a.Note,
			&a.DueDate,
			&a.CreatedAt,
			&a.UpdatedAt,
			&a.ProjectName,
			&a.ComponentName,
			&a.ComponentVersion,
			&a.Severity,
			&a.AssigneeEmail,
			&a.AssignedByEmail,
			&a.Source,
		); err != nil {
			continue
		}
		out = append(out, a)
	}

	return out, total, nil
}

func QueryCodeFindingAssignments(ctx context.Context, f struct {
	ProjectName string
	AssigneeID  *int64
	Status      string
	Limit       int
	Offset      int
}) ([]schemas.CodeFindingAssignment, int64, error) {

	where := []string{"1=1"}
	args := []interface{}{}
	idx := 1

	if f.ProjectName != "" && f.ProjectName != "all" {
		where = append(where, "cf.project_name = $"+strconv.Itoa(idx))
		args = append(args, f.ProjectName)
		idx++
	}
	if f.AssigneeID != nil {
		where = append(where, "cfa.assignee_id = $"+strconv.Itoa(idx))
		args = append(args, *f.AssigneeID)
		idx++
	}
	if f.Status != "" {
		where = append(where, "COALESCE(cfa.status, 'open') = $"+strconv.Itoa(idx))
		args = append(args, f.Status)
		idx++
	}

	whereSQL := strings.Join(where, " AND ")

	var total int64
	countQuery := `
        SELECT COUNT(DISTINCT cf.id)
        FROM code_findings cf
        LEFT JOIN code_finding_assignments cfa ON cfa.code_finding_id = cf.id
        WHERE ` + whereSQL

	if err := db.Conn.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listQuery := `
        SELECT
            COALESCE(cfa.id, 0) AS assignment_id,
            cf.id                AS code_finding_id,
            COALESCE(cfa.assignee_id, 0),
            COALESCE(cfa.assigned_by, 0),
            COALESCE(cfa.status, 'open')   AS status,
            COALESCE(cfa.priority, 'medium') AS priority,
            COALESCE(cfa.note, '')         AS note,
            cfa.due_date,
            COALESCE(cfa.created_at, cf.created_at) AS created_at,
            COALESCE(cfa.updated_at, cf.created_at) AS updated_at,

            cf.project_name,
            COALESCE(cf.rule_id, ''),
            COALESCE(cf.rule_title, ''),
            COALESCE(cf.severity, ''),
            COALESCE(cf.confidence, ''),
            COALESCE(cf.category, ''),
            COALESCE(cf.file_path, ''),
            COALESCE(cf.start_line, 0),
            COALESCE(cf.end_line, 0),

            COALESCE(u1.email,''), COALESCE(u2.email,''),

            'Code (Semgrep)' AS source
        FROM code_findings cf
        LEFT JOIN code_finding_assignments cfa ON cfa.code_finding_id = cf.id
        LEFT JOIN users u1 ON u1.id = cfa.assignee_id
        LEFT JOIN users u2 ON u2.id = cfa.assigned_by
        WHERE ` + whereSQL + `
        ORDER BY COALESCE(cfa.created_at, cf.created_at) DESC
        LIMIT $` + strconv.Itoa(idx) + ` OFFSET $` + strconv.Itoa(idx+1)

	argsList := append(append([]interface{}{}, args...), f.Limit, f.Offset)

	rows, err := db.Conn.QueryContext(ctx, listQuery, argsList...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []schemas.CodeFindingAssignment{}
	for rows.Next() {
		var a schemas.CodeFindingAssignment
		if err := rows.Scan(
			&a.ID,
			&a.CodeFindingID,
			&a.AssigneeID,
			&a.AssignedBy,
			&a.Status,
			&a.Priority,
			&a.Note,
			&a.DueDate,
			&a.CreatedAt,
			&a.UpdatedAt,
			&a.ProjectName,
			&a.RuleID,
			&a.RuleTitle,
			&a.Severity,
			&a.Confidence,
			&a.Category,
			&a.FilePath,
			&a.StartLine,
			&a.EndLine,
			&a.AssigneeEmail,
			&a.AssignedByEmail,
			&a.Source,
		); err != nil {
			continue
		}
		out = append(out, a)
	}

	return out, total, nil
}
