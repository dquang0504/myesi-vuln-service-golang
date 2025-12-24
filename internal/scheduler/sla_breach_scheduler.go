package scheduler

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"myesi-vuln-service-golang/internal/config"
	"myesi-vuln-service-golang/internal/db"
	"myesi-vuln-service-golang/internal/events"
	kafkautil "myesi-vuln-service-golang/internal/kafka"

	"github.com/robfig/cron/v3"
	"github.com/segmentio/kafka-go"
)

const (
	slaSampleLimit       = 5
	eventTypeSLABreach   = "vulnerability.sla_breach"
	defaultActionPathFmt = "/developer/vulnerabilities?project_id=%d"
	slaSnapshotQuery     = `
SELECT
    v.id,
    v.project_id,
    COALESCE(v.project_name, p.name) AS project_name,
    p.organization_id,
    COALESCE(NULLIF(TRIM(LOWER(v.severity)), ''), 'medium') AS severity,
    COALESCE(v.component_name, '') AS component_name,
    COALESCE(v.created_at, NOW() AT TIME ZONE 'UTC') AS created_at,
    va.due_date,
    COALESCE(LOWER(va.status), 'open') AS assignment_status
FROM vulnerabilities v
JOIN projects p ON p.id = v.project_id
LEFT JOIN vulnerability_assignments va ON va.vulnerability_id = v.id
WHERE v.is_active = TRUE;
`
)

type slaRow struct {
	VulnerabilityID  int64
	ProjectID        int64
	ProjectName      string
	OrganizationID   sql.NullInt64
	Severity         string
	ComponentName    string
	CreatedAt        time.Time
	DueDate          sql.NullTime
	AssignmentStatus string
}

type slaSample struct {
	VulnerabilityID  int64      `json:"vulnerability_id"`
	Component        string     `json:"component"`
	Severity         string     `json:"severity"`
	AgeDays          int        `json:"age_days"`
	DueDate          *time.Time `json:"due_date,omitempty"`
	AssignmentStatus string     `json:"assignment_status,omitempty"`
	Reason           string     `json:"reason"`
	OverdueDays      int        `json:"overdue_days"`
}

type slaProjectBreach struct {
	ProjectID      int64
	ProjectName    string
	OrganizationID sql.NullInt64
	Samples        []slaSample
	Count          int
}

// StartSLABreachScheduler runs the SLA detection cron job once per day.
func StartSLABreachScheduler() {
	cfg := config.LoadConfig()
	spec := cfg.SLABreachSpec
	if strings.TrimSpace(spec) == "" {
		spec = "@daily"
	}

	c := cron.New(cron.WithSeconds())
	_, err := c.AddFunc(spec, func() {
		ctx := context.Background()
		runSLABreachJob(ctx, cfg, db.Conn, time.Now().UTC())
	})
	if err != nil {
		log.Printf("[SLA] failed to schedule breach detector: %v", err)
		return
	}

	c.Start()
	log.Printf("[SLA] scheduler initialized — runs at '%s'", spec)
}

func runSLABreachJob(ctx context.Context, cfg *config.Config, conn *sql.DB, now time.Time) {
	if conn == nil {
		log.Printf("[SLA] skipped run: database connection unavailable")
		return
	}

	rows, err := conn.QueryContext(ctx, slaSnapshotQuery)
	if err != nil {
		log.Printf("[SLA][ERR] query failed: %v", err)
		return
	}
	defer rows.Close()

	var snapshot []slaRow
	for rows.Next() {
		var r slaRow
		if err := rows.Scan(
			&r.VulnerabilityID,
			&r.ProjectID,
			&r.ProjectName,
			&r.OrganizationID,
			&r.Severity,
			&r.ComponentName,
			&r.CreatedAt,
			&r.DueDate,
			&r.AssignmentStatus,
		); err != nil {
			log.Printf("[SLA][WARN] scan failed: %v", err)
			continue
		}
		snapshot = append(snapshot, r)
	}
	if err := rows.Err(); err != nil {
		log.Printf("[SLA][WARN] row iteration failed: %v", err)
	}

	breaches := evaluateSLABreaches(snapshot, now, slaSampleLimit)
	if len(breaches) == 0 {
		log.Printf("[SLA] no SLA breaches detected at %s", now.Format(time.RFC3339))
		return
	}

	for _, breach := range breaches {
		if err := emitSLABreachEvent(ctx, cfg, breach); err != nil {
			log.Printf("[SLA][ERR] emit failed for project %s: %v", breach.ProjectName, err)
		}
	}
}

func evaluateSLABreaches(rows []slaRow, now time.Time, sampleLimit int) []slaProjectBreach {
	grouped := map[int64]*slaProjectBreach{}
	for _, row := range rows {
		breach, reason, overdue := shouldFlagBreach(row, now)
		if !breach {
			continue
		}

		entry, ok := grouped[row.ProjectID]
		if !ok {
			entry = &slaProjectBreach{
				ProjectID:      row.ProjectID,
				ProjectName:    row.ProjectName,
				OrganizationID: row.OrganizationID,
			}
			grouped[row.ProjectID] = entry
		}
		entry.Count++
		if len(entry.Samples) < sampleLimit {
			sample := slaSample{
				VulnerabilityID:  row.VulnerabilityID,
				Component:        row.ComponentName,
				Severity:         row.Severity,
				AgeDays:          int(now.Sub(row.CreatedAt).Hours() / 24),
				AssignmentStatus: row.AssignmentStatus,
				Reason:           reason,
				OverdueDays:      overdue,
			}
			if row.DueDate.Valid {
				dt := row.DueDate.Time.UTC()
				sample.DueDate = &dt
			}
			entry.Samples = append(entry.Samples, sample)
		}
	}

	out := make([]slaProjectBreach, 0, len(grouped))
	for _, b := range grouped {
		out = append(out, *b)
	}
	return out
}

func shouldFlagBreach(row slaRow, now time.Time) (bool, string, int) {
	age := now.Sub(row.CreatedAt)
	status := strings.ToLower(strings.TrimSpace(row.AssignmentStatus))
	dueResolved := status == "resolved" || status == "accepted_risk" || status == "wont_fix" || status == "closed"

	if row.DueDate.Valid {
		if row.DueDate.Time.Before(now) && !dueResolved {
			overdue := int(now.Sub(row.DueDate.Time).Hours() / 24)
			if overdue < 0 {
				overdue = 0
			}
			return true, "due_date", overdue
		}
		return false, "", 0
	}

	threshold := severityDuration(row.Severity)
	if age > threshold {
		return true, "age", int(age.Hours() / 24)
	}
	return false, "", 0
}

func severityDuration(severity string) time.Duration {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 7 * 24 * time.Hour
	case "high":
		return 14 * 24 * time.Hour
	case "medium":
		return 30 * 24 * time.Hour
	case "low":
		return 90 * 24 * time.Hour
	default:
		return 60 * 24 * time.Hour
	}
}

func emitSLABreachEvent(ctx context.Context, cfg *config.Config, breach slaProjectBreach) error {
	writer, err := kafkautil.GetWriter(kafkautil.TopicNotificationEvents)
	if err != nil {
		return fmt.Errorf("kafka writer unavailable: %w", err)
	}

	actionURL := buildProjectActionURL(cfg.FrontendBaseURL, breach.ProjectID)
	orgID := int64(0)
	if breach.OrganizationID.Valid {
		orgID = breach.OrganizationID.Int64
	}
	payload := map[string]interface{}{
		"project":    breach.ProjectName,
		"project_id": breach.ProjectID,
		"count":      breach.Count,
		"samples":    breach.Samples,
		"action_url": actionURL,
	}

	env := events.NewEnvelope(eventTypeSLABreach, orgID, breach.ProjectName, payload)
	data, _ := json.Marshal(env)
	msg := kafka.Message{
		Key:   []byte(fmt.Sprintf("%d", breach.ProjectID)),
		Value: data,
	}
	if err := writer.WriteMessages(ctx, msg); err != nil {
		return fmt.Errorf("kafka write failed: %w", err)
	}
	log.Printf("[SLA] emitted breach event for project=%s count=%d", breach.ProjectName, breach.Count)
	return nil
}

func buildProjectActionURL(base string, projectID int64) string {
	b := strings.TrimRight(base, "/")
	if b == "" {
		b = "https://localhost:3000"
	}
	return b + fmt.Sprintf(defaultActionPathFmt, projectID)
}
