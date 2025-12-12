package v1

import (
	"context"
	"database/sql"
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

	orgID, err := requireOrgID(c)
	if err != nil {
		return err
	}

	if _, err := ensureSBOMAccessible(c.Context(), sbomID, orgID); err != nil {
		return err
	}

	vulns, err := utils.FindVulnsBySbomID(c.Context(), db.Conn, sbomID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

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

	orgID, err := requireOrgID(c)
	if err != nil {
		return err
	}

	if req.SBOMID != "" {
		projectName, err := ensureSBOMAccessible(c.Context(), req.SBOMID, orgID)
		if err != nil {
			return err
		}
		if req.Project == "" {
			req.Project = projectName
		}
	}

	if len(req.Components) > 0 && req.Project == "" {
		return c.Status(400).JSON(fiber.Map{"error": "project_name required when providing components"})
	}
	if req.Project != "" {
		if _, err := ensureProjectAccessible(c.Context(), req.Project, orgID); err != nil {
			return err
		}
	}

	//If components present, publish event with them. Otherwise publish event referencing sbom_id only
	w := kafka.Writer{
		Addr:  kafka.TCP(strings.Split(config.LoadConfig().KafkaBroker, ",")...),
		Topic: config.LoadConfig().KafkaTopic,
	}
	defer w.Close()

	event := map[string]interface{}{
		"sbom_id":         req.SBOMID,
		"project":         req.Project,
		"organization_id": orgID,
	}
	if len(req.Components) > 0 {
		event["components"] = req.Components
	}
	data, _ := json.Marshal(event)
	key := req.SBOMID
	if key == "" {
		key = req.Project
	}
	msg := kafka.Message{
		Key:   []byte(key),
		Value: data,
	}
	if err := w.WriteMessages(c.Context(), msg); err != nil {
		log.Println("publish refresh error: ", err)
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"message": "refresh queued"})
}

func ListVulnerabilities(c *fiber.Ctx) error {
	orgID, err := requireOrgID(c)
	if err != nil {
		return err
	}

	ctx := context.Background()
	projectQuery := strings.TrimSpace(c.Query("project_name"))
	search := strings.TrimSpace(c.Query("q"))
	severity := strings.ToLower(strings.TrimSpace(c.Query("severity")))
	source := strings.ToLower(strings.TrimSpace(c.Query("source")))
	codeFinding := strings.ToLower(strings.TrimSpace(c.Query("code_findings")))

	page, _ := strconv.Atoi(c.Query("page", "1"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(c.Query("page_size", "10"))
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 10
	}
	offset := (page - 1) * pageSize

	where := []string{"p.organization_id = $1", "p.is_scanned = TRUE", "(p.is_archived IS NULL OR p.is_archived = FALSE)"}
	args := []any{orgID}
	nextParam := func() string {
		return "$" + strconv.Itoa(len(args)+1)
	}

	if projectQuery != "" && projectQuery != "all" {
		placeholder := nextParam()
		where = append(where, fmt.Sprintf("p.name = %s", placeholder))
		args = append(args, projectQuery)
	}
	if search != "" {
		placeholder := nextParam()
		where = append(where, fmt.Sprintf("(p.name ILIKE %s)", placeholder))
		args = append(args, "%"+search+"%")
	}
	if severity != "" && severity != "all" {
		placeholder := nextParam()
		where = append(where, fmt.Sprintf(
			"EXISTS (SELECT 1 FROM vulnerabilities v2 WHERE v2.project_id = p.id AND v2.is_active = TRUE AND LOWER(v2.severity) = %s)",
			placeholder,
		))
		args = append(args, severity)
	}
	if source != "" && source != "all" {
		placeholder := nextParam()
		where = append(where, fmt.Sprintf(`
        (
            EXISTS (
                SELECT 1 FROM sboms s
                WHERE s.project_id = p.id
                  AND LOWER(s.source) = %s
            )
            OR EXISTS (
                SELECT 1 FROM vulnerabilities v3
                WHERE v3.project_id = p.id
                  AND v3.is_active = TRUE
                  AND LOWER(v3.osv_metadata->>'source') = %s
            )
        )
    `, placeholder, placeholder))
		args = append(args, source)
	}
	if codeFinding == "has" {
		where = append(where,
			"EXISTS (SELECT 1 FROM code_findings cf WHERE cf.project_id = p.id)",
		)
	} else if codeFinding == "none" {
		where = append(where,
			"NOT EXISTS (SELECT 1 FROM code_findings cf WHERE cf.project_id = p.id)",
		)
	}

	whereSQL := strings.Join(where, " AND ")

	countQuery := `SELECT COUNT(*) FROM projects p WHERE ` + whereSQL
	var totalProjects int64
	if err := db.Conn.QueryRowContext(ctx, countQuery, args...).Scan(&totalProjects); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	limitParam := "$" + strconv.Itoa(len(args)+1)
	offsetParam := "$" + strconv.Itoa(len(args)+2)
	projectQuerySQL := `
        SELECT 
            p.id,
            p.name,
            p.last_vuln_scan,
            COALESCE(SUM(CASE WHEN v.is_active THEN 1 ELSE 0 END),0) AS total_vulns,
            COALESCE(AVG(CASE WHEN v.is_active THEN r.score END),0)   AS avg_risk_score,
            COALESCE(MAX(
                CASE LOWER(v.severity)
                    WHEN 'critical' THEN 5
                    WHEN 'high' THEN 4
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 2
                    ELSE 1
                END
            ),1) as sev_rank,
            COALESCE(cf_counts.code_findings,0) AS code_findings
        FROM projects p
        LEFT JOIN vulnerabilities v
            ON v.project_id = p.id AND v.is_active = TRUE
        LEFT JOIN risk_scores r
            ON v.sbom_id = r.sbom_id
           AND v.component_name = r.component_name
           AND v.component_version = r.component_version
        LEFT JOIN (
            SELECT project_id, COUNT(*) AS code_findings
            FROM code_findings
            GROUP BY project_id
        ) cf_counts ON cf_counts.project_id = p.id
        WHERE ` + whereSQL + `
        GROUP BY p.id, p.name, p.last_vuln_scan, cf_counts.code_findings
        ORDER BY sev_rank DESC, total_vulns DESC
        LIMIT ` + limitParam + ` OFFSET ` + offsetParam

	argsWithPaging := append([]any{}, args...)
	argsWithPaging = append(argsWithPaging, pageSize, offset)

	rows, err := db.Conn.QueryContext(ctx, projectQuerySQL, argsWithPaging...)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	defer rows.Close()

	type ProjectRow struct {
		ID           int
		Name         string
		LastScan     *time.Time
		TotalVulns   int
		AvgRiskScore float64
		SevRank      int
		CodeFindings int
	}
	projectRows := []ProjectRow{}
	for rows.Next() {
		var pr ProjectRow
		if err := rows.Scan(&pr.ID, &pr.Name, &pr.LastScan, &pr.TotalVulns, &pr.AvgRiskScore, &pr.SevRank, &pr.CodeFindings); err == nil {
			projectRows = append(projectRows, pr)
		}
	}

	// Fetch vulnerabilities for the current page projects
	projectIDs := []int{}
	projectNames := []string{}
	for _, pr := range projectRows {
		projectIDs = append(projectIDs, pr.ID)
		projectNames = append(projectNames, pr.Name)
	}

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
	if len(projectNames) > 0 {
		if len(projectIDs) > 0 {
			placeholders := []string{}
			argsV := []any{orgID} // $1 = orgID
			for i, id := range projectIDs {
				placeholders = append(placeholders, "$"+strconv.Itoa(i+2)) // bắt đầu từ $2
				argsV = append(argsV, id)
			}

			vQuery := `
        SELECT 
            v.id,
            v.sbom_id,
            v.project_name,
            v.component_name,
            v.component_version,
            v.vuln_id,
            v.severity,
            v.cvss_vector,
            v.osv_metadata,
            v.fix_available,
            v.fixed_version,
            v.updated_at,
            COALESCE(r.score, 0)
        FROM vulnerabilities v
        JOIN projects p
          ON p.id = v.project_id
        LEFT JOIN sboms s
          ON s.id = v.sbom_id
        LEFT JOIN risk_scores r
          ON v.sbom_id = r.sbom_id
         AND v.component_name = r.component_name
         AND v.component_version = r.component_version
        WHERE v.is_active = TRUE
          AND p.organization_id = $1
          AND p.id IN (` + strings.Join(placeholders, ",") + `)
    `

			// severity filter
			if severity != "" && severity != "all" {
				vQuery += " AND LOWER(v.severity) = LOWER($" + strconv.Itoa(len(argsV)+1) + ")"
				argsV = append(argsV, severity)
			}

			// source filter
			if source != "" && source != "all" {
				idx := len(argsV) + 1
				vQuery += `
            AND (
                LOWER(s.source) = LOWER($` + strconv.Itoa(idx) + `)
                OR LOWER(v.osv_metadata->>'source') = LOWER($` + strconv.Itoa(idx) + `)
            )
        `
				argsV = append(argsV, source)
			}

			vRows, err := db.Conn.QueryContext(ctx, vQuery, argsV...)
			if err == nil {
				defer vRows.Close()
				for vRows.Next() {
					var v Vuln
					var osvRaw []byte
					if err := vRows.Scan(
						&v.ID, &v.SbomID, &v.Project, &v.Component, &v.Version,
						&v.CVE, &v.Severity, &v.CVSS, &osvRaw,
						&v.FixAvail, &v.FixedVer, &v.UpdatedAt, &v.RiskScore,
					); err == nil {
						if len(osvRaw) > 0 {
							_ = json.Unmarshal(osvRaw, &v.OSVMeta)
						}
						vulns = append(vulns, v)
					}
				}
			}
		}
	}

	// Fetch code findings for current page projects (lightweight fields)
	type CodeFinding struct {
		ID         int64  `json:"id"`
		Project    string `json:"project_name"`
		RuleID     string `json:"rule_id"`
		RuleTitle  string `json:"rule_title"`
		Severity   string `json:"severity"`
		FilePath   string `json:"file_path"`
		StartLine  int    `json:"start_line"`
		EndLine    int    `json:"end_line"`
		Category   string `json:"category"`
		Confidence string `json:"confidence"`
		Message    string `json:"message"`
	}
	codeFindings := []CodeFinding{}
	if len(projectIDs) > 0 {
		placeholders := []string{}
		argsCF := []any{}
		for i, id := range projectIDs {
			placeholders = append(placeholders, "$"+strconv.Itoa(i+1))
			argsCF = append(argsCF, id)
		}
		cfQuery := `
            SELECT id,
                   COALESCE(project_name, '') AS project_name,
                   COALESCE(project_id, 0)    AS project_id,
                   COALESCE(rule_id, '')      AS rule_id,
                   COALESCE(rule_title, '')   AS rule_title,
                   COALESCE(severity, '')     AS severity,
                   COALESCE(file_path, '')    AS file_path,
                   COALESCE(start_line, 0)    AS start_line,
                   COALESCE(end_line, 0)      AS end_line,
                   COALESCE(category, '')     AS category,
                   COALESCE(confidence, '')   AS confidence,
                   COALESCE(message, '')      AS message
            FROM code_findings
            WHERE project_id IN (` + strings.Join(placeholders, ",") + `)
            ORDER BY created_at DESC
            LIMIT 500
        `
		cfRows, err := db.Conn.QueryContext(ctx, cfQuery, argsCF...)
		if err == nil {
			defer cfRows.Close()
			for cfRows.Next() {
				var cf CodeFinding
				var projectID int
				if err := cfRows.Scan(
					&cf.ID, &cf.Project, &projectID, &cf.RuleID, &cf.RuleTitle, &cf.Severity, &cf.FilePath, &cf.StartLine, &cf.EndLine,
					&cf.Category, &cf.Confidence, &cf.Message,
				); err == nil {
					codeFindings = append(codeFindings, cf)
				}
			}
		}
	}

	// Build project payloads
	toSev := func(rank int) string {
		switch rank {
		case 5:
			return "critical"
		case 4:
			return "high"
		case 3:
			return "medium"
		case 2:
			return "low"
		default:
			return "none"
		}
	}

	projects := []fiber.Map{}
	for _, pr := range projectRows {
		projects = append(projects, fiber.Map{
			"project_name":     pr.Name,
			"total_vulns":      pr.TotalVulns,
			"avg_risk_score":   math.Round(pr.AvgRiskScore*100) / 100,
			"highest_severity": toSev(pr.SevRank),
			"last_scan":        pr.LastScan,
			"code_findings":    pr.CodeFindings,
		})
	}

	return c.JSON(fiber.Map{
		"projects":        projects,
		"vulnerabilities": vulns,
		"code_findings":   codeFindings,
		"page":            page,
		"page_size":       pageSize,
		"total":           totalProjects,
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

	orgID, err := requireOrgID(c)
	if err != nil {
		return err
	}
	if req.OrganizationID == 0 {
		req.OrganizationID = orgID
	} else if req.OrganizationID != orgID {
		return fiber.NewError(fiber.StatusForbidden, "Organization mismatch")
	}

	orgID = req.OrganizationID

	// 1) Acquire scan lock (to prevent concurrent scan start)
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

	// 2) Check & consume project_scan quota here
	var allowed bool
	var msg string
	var nextReset sql.NullTime

	row := db.Conn.QueryRowContext(
		c.Context(),
		"SELECT allowed, message, next_reset FROM check_and_consume_usage($1,$2,$3)",
		orgID, "project_scan", 1,
	)

	if err := row.Scan(&allowed, &msg, &nextReset); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "usage check failed: " + err.Error()})
	}

	if !allowed {
		return c.Status(429).JSON(fiber.Map{
			"error": msg,
		})
	}

	// helper để revert lại quota nếu sau đó không chạy được scan
	revertUsage := func() {
		db.Conn.ExecContext(
			c.Context(),
			"SELECT revert_usage($1,$2,$3)",
			orgID, "project_scan", 1,
		)
	}

	// 3) Optional legacy Redis running-limit
	running, err := utils.GetRunningCount(orgID, context.Background())
	if err != nil {
		revertUsage()
		return c.Status(500).JSON(fiber.Map{"error": "cannot check running scans"})
	}

	if running >= 5 {
		revertUsage()
		return c.Status(429).JSON(fiber.Map{
			"error": "Too many scans running at the moment. Try again shortly.",
		})
	}

	utils.IncrementRunning(orgID, context.Background())

	// 4) Resolve GitHub token
	githubToken := ""
	userID := 0
	if user := c.Locals("user"); user != nil {
		if u, ok := user.(map[string]interface{}); ok {
			if t, ok2 := u["github_token"].(string); ok2 && t != "" {
				githubToken = t
			}
			switch idVal := u["id"].(type) {
			case float64:
				userID = int(idVal)
			case int:
				userID = idVal
			}
		}
	}
	if githubToken == "" {
		githubToken = os.Getenv("GITHUB_TOKEN")
	}

	// 5) Run scan async — revoke usage if FAILED
	go func() {
		defer utils.DecrementRunning(orgID, context.Background())

		err := services.RunCodeScan(req.ProjectName, req.RepoURL, req.Tool, githubToken, userID)
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

	orgID, err := requireOrgID(c)
	if err != nil {
		return err
	}

	ctx := context.Background()
	startDate := time.Now().AddDate(0, 0, -days)

	query := `
    WITH created_counts AS (
        SELECT
            DATE(v.created_at) AS date,
            LOWER(v.severity) AS severity,
            COUNT(*) AS count
        FROM vulnerabilities v
        JOIN projects p ON p.id = v.project_id
        WHERE v.created_at >= $1
          AND p.organization_id = $2
        GROUP BY DATE(v.created_at), LOWER(v.severity)
    ),
    fixed_counts AS (
        SELECT
            DATE(v.updated_at) AS date,
            'fixed' AS severity,
            COUNT(*) AS count
        FROM vulnerabilities v
        JOIN projects p ON p.id = v.project_id
        WHERE v.updated_at >= $1
          AND v.is_active = FALSE
          AND p.organization_id = $2
        GROUP BY DATE(v.updated_at)
    )
    SELECT * FROM created_counts
    UNION ALL
    SELECT * FROM fixed_counts
    ORDER BY date
`

	rows, err := db.Conn.QueryContext(ctx, query, startDate, orgID)
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
				"medium":   0,
				"low":      0,
				"fixed":    0,
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
			"medium":   sev["medium"],
			"low":      sev["low"],
			"fixed":    sev["fixed"],
		})
	}

	return c.JSON(fiber.Map{
		"trend": trend,
	})
}
