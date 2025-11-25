package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"myesi-vuln-service-golang/internal/config"
	"myesi-vuln-service-golang/internal/db"
	"myesi-vuln-service-golang/internal/services"
	"myesi-vuln-service-golang/utils"
	"os"
	"strconv"
	"strings"
	"time"

	fiber "github.com/gofiber/fiber/v2"
	kafka "github.com/segmentio/kafka-go"
)

// Đăng ký các route thuần "vulnerabilities"
func RegisterVulnRoutes(r fiber.Router) {
	r.Get("/health", HealthCheck)
	r.Post("/refresh", refreshVuln)
	r.Get("/stream", utils.StreamVulnerabilities)
	r.Get("/list", ListVulnerabilities)
	r.Post("/scan/code", scanCode)
	r.Get("/trend", getVulnerabilityTrend)
	r.Get("/sbom/:sbom_id", getVulnsBySBOM)
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

// List tất cả vuln (hoặc theo project_name)
func ListVulnerabilities(c *fiber.Ctx) error {
	ctx := context.Background()
	projectQuery := c.Query("project_name")
	limit := c.Query("limit", "200")

	// 1) Query all projects (LEFT JOIN vulnerabilities)
	query := `
        SELECT 
            p.name, p.last_vuln_scan,
            v.id, v.sbom_id, v.component_name, v.component_version,
            v.vuln_id, v.severity, v.cvss_vector, v.osv_metadata,
            v.fix_available, v.fixed_version,
            v.updated_at,
            COALESCE(r.score, 0)
        FROM projects p
        LEFT JOIN vulnerabilities v
            ON v.project_name = p.name
			AND v.is_active = TRUE
        LEFT JOIN risk_scores r
            ON v.sbom_id = r.sbom_id
           AND v.component_name = r.component_name
           AND v.component_version = r.component_version
        WHERE p.is_scanned = TRUE
    `
	args := []any{}
	if projectQuery != "" && projectQuery != "all" {
		query += " AND p.name = $1"
		args = append(args, projectQuery)
	}
	query += " ORDER BY v.updated_at DESC LIMIT " + limit

	rows, err := db.Conn.QueryContext(ctx, query, args...)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	defer rows.Close()

	type Vuln struct {
		ID        *int64                 `json:"id,omitempty"`
		SbomID    *string                `json:"sbom_id,omitempty"`
		Project   string                 `json:"project_name"`
		Component *string                `json:"component,omitempty"`
		Version   *string                `json:"version,omitempty"`
		CVE       *string                `json:"cve,omitempty"`
		Severity  *string                `json:"severity,omitempty"`
		CVSS      *string                `json:"cvss_vector,omitempty"`
		OSVMeta   map[string]interface{} `json:"osv_meta,omitempty"`
		FixAvail  *bool                  `json:"fix_available,omitempty"`
		FixedVer  *string                `json:"fixed_version,omitempty"`
		UpdatedAt *time.Time             `json:"updated_at,omitempty"`
		RiskScore float64                `json:"risk_score"`
	}

	vulns := []Vuln{}
	projectStats := map[string]*struct {
		Total      int
		Avg        float64
		Highest    string
		LastScan   *time.Time
		Scores     []float64
		Severities []string
	}{}

	for rows.Next() {
		var v Vuln
		var osvRaw []byte
		var lastScan *time.Time
		var projectName string

		err := rows.Scan(
			&projectName, &lastScan,
			&v.ID, &v.SbomID, &v.Component, &v.Version,
			&v.CVE, &v.Severity, &v.CVSS, &osvRaw,
			&v.FixAvail, &v.FixedVer,
			&v.UpdatedAt, &v.RiskScore,
		)
		if err != nil {
			continue
		}

		v.Project = projectName
		if len(osvRaw) > 0 {
			_ = json.Unmarshal(osvRaw, &v.OSVMeta)
		}

		vulns = append(vulns, v)

		if projectStats[projectName] == nil {
			projectStats[projectName] = &struct {
				Total      int
				Avg        float64
				Highest    string
				LastScan   *time.Time
				Scores     []float64
				Severities []string
			}{Highest: "none", LastScan: lastScan}
		}

		if v.ID != nil {
			projectStats[projectName].Total++
			projectStats[projectName].Scores = append(projectStats[projectName].Scores, v.RiskScore)
			if v.Severity != nil {
				projectStats[projectName].Severities = append(projectStats[projectName].Severities, strings.ToLower(*v.Severity))
			}
		}
	}

	projects := []fiber.Map{}
	severityOrder := []string{"critical", "high", "moderate", "low", "none"}

	for p, st := range projectStats {
		sum := 0.0
		for _, s := range st.Scores {
			sum += s
		}

		highest := "none"
		for _, lvl := range severityOrder {
			for _, actual := range st.Severities {
				if actual == lvl {
					highest = lvl
					goto DONE
				}
			}
		}
	DONE:

		avg := 0.0
		if st.Total > 0 {
			avg = math.Round((sum/float64(st.Total))*100) / 100
		}

		projects = append(projects, fiber.Map{
			"project_name":     p,
			"total_vulns":      st.Total,
			"avg_risk_score":   avg,
			"highest_severity": highest,
			"last_scan":        st.LastScan,
		})
	}

	return c.JSON(fiber.Map{
		"projects":        projects,
		"vulnerabilities": vulns,
	})
}

func scanCode(c *fiber.Ctx) error {
	var req services.CodeScanRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
	}
	if req.ProjectName == "" || req.Tool == "" || req.RepoURL == "" || req.OrganizationID == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "project_name, repo_url, tool and organization_id required"})
	}

	orgID := req.OrganizationID

	// 2) Acquire scan lock (to prevent concurrent scan start)
	locked, _ := utils.AcquireScanLock(orgID, context.Background())
	if !locked {
		// revert DB usage consumption since scan not started
		db.Conn.ExecContext(c.Context(),
			"SELECT revert_usage($1,$2,$3)",
			orgID, "project_scan", 1,
		)

		return c.Status(429).JSON(fiber.Map{
			"error": "Another scan request is being processed. Try again.",
		})
	}
	defer utils.ReleaseScanLock(orgID, context.Background())

	// 3) Optional legacy Redis running-limit
	running, err := utils.GetRunningCount(orgID, context.Background())
	if err != nil {
		db.Conn.ExecContext(c.Context(),
			"SELECT revert_usage($1,$2,$3)",
			orgID, "project_scan", 1,
		)
		return c.Status(500).JSON(fiber.Map{"error": "cannot check running scans"})
	}

	if running >= 5 {
		db.Conn.ExecContext(c.Context(),
			"SELECT revert_usage($1,$2,$3)",
			orgID, "project_scan", 1,
		)
		return c.Status(429).JSON(fiber.Map{
			"error": "Too many scans running at the moment. Try again shortly.",
		})
	}

	utils.IncrementRunning(orgID, context.Background())

	// 4) Resolve GitHub token
	githubToken := ""
	if user := c.Locals("user"); user != nil {
		if u, ok := user.(map[string]interface{}); ok {
			if t, ok2 := u["github_token"].(string); ok2 && t != "" {
				githubToken = t
			}
		}
	}
	if githubToken == "" {
		githubToken = os.Getenv("GITHUB_TOKEN")
	}

	// 5) Run scan async — revoke usage if FAILED
	go func() {
		defer utils.DecrementRunning(orgID, context.Background())

		err := services.RunCodeScan(req.ProjectName, req.RepoURL, req.Tool, githubToken)
		if err != nil {
			db.Conn.ExecContext(context.Background(),
				"SELECT revert_usage($1,$2,$3)",
				orgID, "project_scan", 1,
			)
		}
	}()

	return c.JSON(fiber.Map{
		"message": "code scan started",
		"project": req.ProjectName,
		"tool":    req.Tool,
		"running": running + 1,
	})
}

// Vulnerability Trend (Last X days)
func getVulnerabilityTrend(c *fiber.Ctx) error {
	days, err := strconv.Atoi(c.Query("days", "7"))
	if err != nil || days <= 0 {
		days = 7
	}

	ctx := context.Background()

	query := `
        SELECT
            DATE(created_at) AS date,
            LOWER(severity) AS severity,
            COUNT(*) AS count
        FROM vulnerabilities
        WHERE created_at >= NOW() - INTERVAL '` + fmt.Sprintf("%d", days) + ` day'
        GROUP BY DATE(created_at), LOWER(severity)
        ORDER BY DATE(created_at)
    `

	rows, err := db.Conn.QueryContext(ctx, query)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	defer rows.Close()

	type Row struct {
		Date     string
		Severity string
		Count    int
	}

	list := []Row{}
	for rows.Next() {
		var rawDate time.Time
		var sev string
		var cnt int

		if err := rows.Scan(&rawDate, &sev, &cnt); err == nil {
			list = append(list, Row{
				Date:     rawDate.Format("2006-01-02"),
				Severity: sev,
				Count:    cnt,
			})
		}
	}

	// Convert raw rows → FE trend format
	trendMap := map[string]map[string]int{}

	for _, r := range list {
		if trendMap[r.Date] == nil {
			trendMap[r.Date] = map[string]int{
				"critical": 0,
				"high":     0,
				"moderate": 0,
				"low":      0,
			}
		}
		if _, ok := trendMap[r.Date][r.Severity]; ok {
			trendMap[r.Date][r.Severity] = r.Count
		}
	}

	// Transform into array
	trend := []map[string]interface{}{}
	for date, sev := range trendMap {
		trend = append(trend, map[string]interface{}{
			"date":     date,
			"critical": sev["critical"],
			"high":     sev["high"],
			"moderate": sev["moderate"],
			"low":      sev["low"],
		})
	}

	return c.JSON(fiber.Map{
		"trend": trend,
	})
}
