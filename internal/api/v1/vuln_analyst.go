package v1

import (
	"context"
	"database/sql"
	"errors"
	"myesi-vuln-service-golang/internal/db"
	"myesi-vuln-service-golang/internal/schemas"
	"strconv"
	"strings"
	"time"

	fiber "github.com/gofiber/fiber/v2"
)

func RegisterAnalystRoutes(r fiber.Router) {
	r.Post("/assign", createAssignment)
	r.Post("/assign/bulk", bulkAssign)
	r.Get("/assignments", listAssignments)
	r.Patch("/assignments/:id", updateAssignment)

	r.Get("/triage", analystTriage)

	r.Post("/code-finding/assign", createCodeFindingAssignment)
	r.Post("/code-finding/assign/bulk", bulkAssignCodeFinding)
	r.Patch("/code-finding/assignments/:id", updateCodeFindingAssignment)
}

func createAssignment(c *fiber.Ctx) error {
	var req schemas.CreateAssignmentReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid body",
		})
	}

	// Validate input
	if req.VulnerabilityID == 0 || req.AssigneeID == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "vulnerability_id and assignee_id are required",
		})
	}
	if req.Status == "" {
		req.Status = "open"
	}
	if req.Priority == "" {
		req.Priority = "medium"
	}

	// Fetch assigned_by from header X-User-Id
	userIDHeader := c.Get("X-User-Id")
	if userIDHeader == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "X-User-Id header is required",
		})
	}

	assignedBy, err := strconv.ParseInt(userIDHeader, 10, 64)
	if err != nil || assignedBy == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid X-User-Id header",
		})
	}

	ctx := context.Background()

	// Check vulnerability existence
	var tmp int64
	if err := db.Conn.QueryRowContext(
		ctx,
		"SELECT id FROM vulnerabilities WHERE id = $1",
		req.VulnerabilityID,
	).Scan(&tmp); err != nil {

		if errors.Is(err, sql.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "vulnerability not found",
			})
		}

		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Parse due_date
	var due sql.NullTime
	if req.DueDate != nil && strings.TrimSpace(*req.DueDate) != "" {
		t, err := time.Parse(time.RFC3339, *req.DueDate)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid due_date, must be RFC3339 format",
			})
		}
		due = sql.NullTime{
			Time:  t,
			Valid: true,
		}
	}

	query := `
        INSERT INTO vulnerability_assignments (
            vulnerability_id, assignee_id, assigned_by,
            status, priority, note, due_date
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT (vulnerability_id) DO UPDATE
        SET assignee_id = EXCLUDED.assignee_id,
            status      = EXCLUDED.status,
            priority    = EXCLUDED.priority,
            note        = EXCLUDED.note,
            due_date    = EXCLUDED.due_date,
            updated_at  = NOW()
        RETURNING id, vulnerability_id, assignee_id, assigned_by,
                  status, priority, note, due_date, created_at, updated_at;
    `

	var a schemas.Assignment
	row := db.Conn.QueryRowContext(
		ctx,
		query,
		req.VulnerabilityID,
		req.AssigneeID,
		assignedBy,
		req.Status,
		req.Priority,
		req.Note,
		due,
	)

	if err := row.Scan(
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
	); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(fiber.StatusCreated).JSON(a)
}

func bulkAssign(c *fiber.Ctx) error {
	var req schemas.BulkAssignReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
	}
	if len(req.VulnerabilityIDs) == 0 || req.AssigneeID == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "vulnerability_ids and assignee_id are required"})
	}
	if req.Status == "" {
		req.Status = "open"
	}
	if req.Priority == "" {
		req.Priority = "medium"
	}

	// Fetch assigned_by from header X-User-Id
	userIDHeader := c.Get("X-User-Id")
	if userIDHeader == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "X-User-Id header is required",
		})
	}

	assignedBy, err := strconv.ParseInt(userIDHeader, 10, 64)
	if err != nil || assignedBy == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid X-User-Id header",
		})
	}

	var due sql.NullTime
	if req.DueDate != nil && *req.DueDate != "" {
		if t, err := time.Parse(time.RFC3339, *req.DueDate); err == nil {
			due = sql.NullTime{Time: t, Valid: true}
		}
	}

	ctx := context.Background()
	tx, err := db.Conn.BeginTx(ctx, nil)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	defer tx.Rollback()

	assigned := make([]int64, 0)
	skipped := make([]map[string]interface{}, 0)

	stmt := `
        INSERT INTO vulnerability_assignments (
            vulnerability_id, assignee_id, assigned_by,
            status, priority, note, due_date
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT (vulnerability_id) DO UPDATE
        SET assignee_id = EXCLUDED.assignee_id,
            status      = EXCLUDED.status,
            priority    = EXCLUDED.priority,
            note        = EXCLUDED.note,
            due_date    = EXCLUDED.due_date,
            updated_at  = NOW();
    `

	for _, vid := range req.VulnerabilityIDs {
		if vid == 0 {
			continue
		}
		if _, err := tx.ExecContext(
			ctx, stmt,
			vid, req.AssigneeID, assignedBy,
			req.Status, req.Priority, req.Note, due,
		); err != nil {
			skipped = append(skipped, map[string]interface{}{
				"id":     vid,
				"reason": err.Error(),
			})
			continue
		}
		assigned = append(assigned, vid)
	}

	if err := tx.Commit(); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"assigned": assigned,
		"skipped":  skipped,
	})
}

func updateAssignment(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil || id <= 0 {
		return c.Status(400).JSON(fiber.Map{"error": "invalid id"})
	}

	var req schemas.UpdateAssignmentReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
	}

	// build dynamic SET
	sets := []string{}
	args := []interface{}{}
	idx := 1

	if req.Status != nil {
		sets = append(sets, "status = $"+strconv.Itoa(idx))
		args = append(args, *req.Status)
		idx++
	}
	if req.Priority != nil {
		sets = append(sets, "priority = $"+strconv.Itoa(idx))
		args = append(args, *req.Priority)
		idx++
	}
	if req.Note != nil {
		sets = append(sets, "note = $"+strconv.Itoa(idx))
		args = append(args, *req.Note)
		idx++
	}
	if req.AssigneeID != nil {
		sets = append(sets, "assignee_id = $"+strconv.Itoa(idx))
		args = append(args, *req.AssigneeID)
		idx++
	}
	if req.DueDate != nil {
		if *req.DueDate == "" {
			sets = append(sets, "due_date = NULL")
		} else {
			t, err := time.Parse(time.RFC3339, *req.DueDate)
			if err == nil {
				sets = append(sets, "due_date = $"+strconv.Itoa(idx))
				args = append(args, t)
				idx++
			}
		}
	}

	if len(sets) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "no fields to update"})
	}

	sets = append(sets, "updated_at = NOW()")
	args = append(args, id)

	query := `
        UPDATE vulnerability_assignments
        SET ` + strings.Join(sets, ", ") + `
        WHERE id = $` + strconv.Itoa(len(args)) + `
        RETURNING id, vulnerability_id, assignee_id, assigned_by,
                  status, priority, note, due_date, created_at, updated_at;
    `

	var a schemas.Assignment
	row := db.Conn.QueryRowContext(context.Background(), query, args...)
	if err := row.Scan(
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
	); err != nil {
		if err == sql.ErrNoRows {
			return c.Status(404).JSON(fiber.Map{"error": "assignment not found"})
		}
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(a)
}

// ====== analyst triage + listAssignments + code finding assignments ======

type AssignmentList struct {
	Items []schemas.Assignment `json:"items"`
	Total int64                `json:"total"`
}

type CodeFindingList struct {
	Items []schemas.CodeFindingAssignment `json:"items"`
	Total int64                           `json:"total"`
}

type AnalystTriageResponse struct {
	Vulnerabilities AssignmentList  `json:"vulnerabilities"`
	CodeFindings    CodeFindingList `json:"code_findings"`
}

func listAssignments(c *fiber.Ctx) error {
	ctx := context.Background()

	projectName := c.Query("project_name", "")
	assigneeStr := c.Query("assignee_id", "")
	status := c.Query("status", "")
	limitStr := c.Query("limit", "50")
	offsetStr := c.Query("offset", "0")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 || limit > 200 {
		limit = 50
	}
	offset, _ := strconv.Atoi(offsetStr)

	where := []string{"1=1"}
	args := []interface{}{}
	idx := 1

	// filter theo project_name (trên bảng vulnerabilities)
	if projectName != "" && projectName != "all" {
		where = append(where, "v.project_name = $"+strconv.Itoa(idx))
		args = append(args, projectName)
		idx++
	}

	// filter theo assignee_id (chỉ những cái ĐÃ assign)
	if assigneeStr != "" {
		if aid, err := strconv.ParseInt(assigneeStr, 10, 64); err == nil {
			where = append(where, "va.assignee_id = $"+strconv.Itoa(idx))
			args = append(args, aid)
			idx++
		}
	}

	// filter status: dùng COALESCE để mặc định "open" nếu chưa có assignment
	if status != "" {
		where = append(where, "COALESCE(va.status, 'open') = $"+strconv.Itoa(idx))
		args = append(args, status)
		idx++
	}

	whereSQL := strings.Join(where, " AND ")

	// ---- TOTAL: đếm theo vulnerabilities, không phải assignments ----
	countQuery := `
        SELECT COUNT(DISTINCT v.id)
        FROM vulnerabilities v
        LEFT JOIN vulnerability_assignments va ON va.vulnerability_id = v.id
        WHERE ` + whereSQL

	var total int64
	if err := db.Conn.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	// ---- LIST: lấy vuln + (nếu có) assignment ----
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

        COALESCE(v.project_name, ''),
        COALESCE(v.component_name, ''),
        COALESCE(v.component_version, ''),
        COALESCE(v.severity, ''),

        COALESCE(u1.email, '') AS assignee_email,
        COALESCE(u2.email, '') AS assigned_by_email,
        COALESCE(s.source, '') AS source
    FROM vulnerabilities v
    LEFT JOIN vulnerability_assignments va ON va.vulnerability_id = v.id
    LEFT JOIN users u1 ON u1.id = va.assignee_id
    LEFT JOIN users u2 ON u2.id = va.assigned_by
    LEFT JOIN sboms s ON s.id = v.sbom_id
    WHERE ` + whereSQL + `
    ORDER BY COALESCE(va.created_at, v.created_at) DESC
    LIMIT $` + strconv.Itoa(idx) + ` OFFSET $` + strconv.Itoa(idx+1)

	args = append(args, limit, offset)

	rows, err := db.Conn.QueryContext(ctx, listQuery, args...)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	defer rows.Close()

	items := []schemas.Assignment{}
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
		items = append(items, a)
	}

	return c.JSON(fiber.Map{
		"items": items,
		"total": total,
	})
}

func analystTriage(c *fiber.Ctx) error {
	ctx := context.Background()
	projectName := c.Query("project_name", "")
	assigneeStr := c.Query("assignee_id", "")
	status := c.Query("status", "")
	priority := c.Query("priority", "")
	severity := c.Query("severity", "")
	search := c.Query("search", "")

	vulnLimitStr := c.Query("vuln_limit", "50")
	vulnOffsetStr := c.Query("vuln_offset", "0")
	codeLimitStr := c.Query("code_limit", "50")
	codeOffsetStr := c.Query("code_offset", "0")

	vulnLimit, err := strconv.Atoi(vulnLimitStr)
	if err != nil || vulnLimit <= 0 || vulnLimit > 200 {
		vulnLimit = 50
	}
	vulnOffset, _ := strconv.Atoi(vulnOffsetStr)

	codeLimit, err := strconv.Atoi(codeLimitStr)
	if err != nil || codeLimit <= 0 || codeLimit > 200 {
		codeLimit = 50
	}
	codeOffset, _ := strconv.Atoi(codeOffsetStr)

	// ========= COMMON: parse assigneeID =========
	var assigneeID *int64
	if assigneeStr != "" && assigneeStr != "0" {
		if aid, err := strconv.ParseInt(assigneeStr, 10, 64); err == nil {
			assigneeID = &aid
		}
	}

	// ========= 1) VULNERABILITIES PART =========
	where := []string{"v.is_active = TRUE"}
	args := []interface{}{}
	idx := 1

	if projectName != "" && projectName != "all" {
		where = append(where, "v.project_name = $"+strconv.Itoa(idx))
		args = append(args, projectName)
		idx++
	}

	if assigneeID != nil {
		where = append(where, "va.assignee_id = $"+strconv.Itoa(idx))
		args = append(args, *assigneeID)
		idx++
	}

	// status: support "unassigned" riêng
	if status == "unassigned" {
		// chưa có assignment row
		where = append(where, "va.id IS NULL")
	} else if status != "" {
		where = append(where, "va.status = $"+strconv.Itoa(idx))
		args = append(args, status)
		idx++
	}

	if priority != "" {
		where = append(where, "COALESCE(va.priority, 'medium') = $"+strconv.Itoa(idx))
		args = append(args, priority)
		idx++
	}

	if severity != "" {
		where = append(where, "LOWER(v.severity) = LOWER($"+strconv.Itoa(idx)+")")
		args = append(args, severity)
		idx++
	}

	if search != "" {
		like := "%" + search + "%"
		where = append(where, "("+ //nolint:goconst
			"v.project_name ILIKE $"+strconv.Itoa(idx)+
			" OR v.component_name ILIKE $"+strconv.Itoa(idx)+
			" OR v.component_version ILIKE $"+strconv.Itoa(idx)+
			" OR v.severity ILIKE $"+strconv.Itoa(idx)+
			" OR u1.email ILIKE $"+strconv.Itoa(idx)+
			" OR u2.email ILIKE $"+strconv.Itoa(idx)+
			" OR CAST(v.id AS TEXT) ILIKE $"+strconv.Itoa(idx)+
			")")
		args = append(args, like)
		idx++
	}

	whereSQL := strings.Join(where, " AND ")

	countQuery := `
        SELECT COUNT(DISTINCT v.id)
        FROM vulnerabilities v
        LEFT JOIN vulnerability_assignments va ON va.vulnerability_id = v.id
        LEFT JOIN users u1 ON u1.id = va.assignee_id
        LEFT JOIN users u2 ON u2.id = va.assigned_by
        WHERE ` + whereSQL

	var vulnTotal int64
	if err := db.Conn.QueryRowContext(ctx, countQuery, args...).Scan(&vulnTotal); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
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

            COALESCE(v.project_name, ''),
            COALESCE(v.component_name, ''),
            COALESCE(v.component_version, ''),
            COALESCE(v.severity, ''),

            COALESCE(u1.email, '') AS assignee_email,
            COALESCE(u2.email, '') AS assigned_by_email,
            COALESCE(s.source, '') AS source
        FROM vulnerabilities v
        LEFT JOIN vulnerability_assignments va ON va.vulnerability_id = v.id
        LEFT JOIN users u1 ON u1.id = va.assignee_id
        LEFT JOIN users u2 ON u2.id = va.assigned_by
        LEFT JOIN sboms s ON s.id = v.sbom_id
        WHERE ` + whereSQL + `
        ORDER BY COALESCE(va.created_at, v.created_at) DESC
        LIMIT $` + strconv.Itoa(idx) + ` OFFSET $` + strconv.Itoa(idx+1)

	vulnArgs := append(append([]interface{}{}, args...), vulnLimit, vulnOffset)

	vRows, err := db.Conn.QueryContext(ctx, listQuery, vulnArgs...)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	defer vRows.Close()

	vulnItems := []schemas.Assignment{}
	for vRows.Next() {
		var a schemas.Assignment
		if err := vRows.Scan(
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
		vulnItems = append(vulnItems, a)
	}

	// ========= 2) CODE FINDINGS PART =========
	cfWhere := []string{"1=1"}
	cfArgs := []interface{}{}
	cfIdx := 1

	if projectName != "" && projectName != "all" {
		cfWhere = append(cfWhere, "cf.project_name = $"+strconv.Itoa(cfIdx))
		cfArgs = append(cfArgs, projectName)
		cfIdx++
	}

	if assigneeID != nil {
		cfWhere = append(cfWhere, "cfa.assignee_id = $"+strconv.Itoa(cfIdx))
		cfArgs = append(cfArgs, *assigneeID)
		cfIdx++
	}

	if status == "unassigned" {
		cfWhere = append(cfWhere, "cfa.id IS NULL")
	} else if status != "" {
		cfWhere = append(cfWhere, "cfa.status = $"+strconv.Itoa(cfIdx))
		cfArgs = append(cfArgs, status)
		cfIdx++
	}

	if priority != "" {
		cfWhere = append(cfWhere, "COALESCE(cfa.priority, 'medium') = $"+strconv.Itoa(cfIdx))
		cfArgs = append(cfArgs, priority)
		cfIdx++
	}

	if severity != "" {
		cfWhere = append(cfWhere, "LOWER(cf.severity) = LOWER($"+strconv.Itoa(cfIdx)+")")
		cfArgs = append(cfArgs, severity)
		cfIdx++
	}

	if search != "" {
		like := "%" + search + "%"
		cfWhere = append(cfWhere, "("+ //nolint:goconst
			"cf.project_name ILIKE $"+strconv.Itoa(cfIdx)+
			" OR cf.rule_title ILIKE $"+strconv.Itoa(cfIdx)+
			" OR cf.file_path ILIKE $"+strconv.Itoa(cfIdx)+
			" OR cf.severity ILIKE $"+strconv.Itoa(cfIdx)+
			" OR u1.email ILIKE $"+strconv.Itoa(cfIdx)+
			" OR u2.email ILIKE $"+strconv.Itoa(cfIdx)+
			" OR CAST(cf.id AS TEXT) ILIKE $"+strconv.Itoa(cfIdx)+
			")")
		cfArgs = append(cfArgs, like)
		cfIdx++
	}

	cfWhereSQL := strings.Join(cfWhere, " AND ")

	cfCountQuery := `
        SELECT COUNT(DISTINCT cf.id)
        FROM code_findings cf
        LEFT JOIN code_finding_assignments cfa ON cfa.code_finding_id = cf.id
        LEFT JOIN users u1 ON u1.id = cfa.assignee_id
        LEFT JOIN users u2 ON u2.id = cfa.assigned_by
        WHERE ` + cfWhereSQL

	var cfTotal int64
	if err := db.Conn.QueryRowContext(ctx, cfCountQuery, cfArgs...).Scan(&cfTotal); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	cfListQuery := `
        SELECT
            COALESCE(cfa.id, 0) AS assignment_id,
            cf.id               AS code_finding_id,
            COALESCE(cfa.assignee_id, 0),
            COALESCE(cfa.assigned_by, 0),
            COALESCE(cfa.status, 'open')     AS status,
            COALESCE(cfa.priority, 'medium') AS priority,
            COALESCE(cfa.note, '')           AS note,
            cfa.due_date,
            COALESCE(cfa.created_at, cf.created_at) AS created_at,
            COALESCE(cfa.updated_at, cf.created_at) AS updated_at,

            COALESCE(cf.project_name, ''),
            COALESCE(cf.rule_id, ''),
            COALESCE(cf.rule_title, ''),
            COALESCE(cf.severity, ''),
            COALESCE(cf.confidence, ''),
            COALESCE(cf.category, ''),
            COALESCE(cf.file_path, ''),
            COALESCE(cf.start_line, 0),
            COALESCE(cf.end_line, 0),

            COALESCE(u1.email, ''),
            COALESCE(u2.email, ''),
            'Code (Semgrep)' AS source
        FROM code_findings cf
        LEFT JOIN code_finding_assignments cfa ON cfa.code_finding_id = cf.id
        LEFT JOIN users u1 ON u1.id = cfa.assignee_id
        LEFT JOIN users u2 ON u2.id = cfa.assigned_by
        WHERE ` + cfWhereSQL + `
        ORDER BY COALESCE(cfa.created_at, cf.created_at) DESC
        LIMIT $` + strconv.Itoa(cfIdx) + ` OFFSET $` + strconv.Itoa(cfIdx+1)

	cfArgs = append(cfArgs, codeLimit, codeOffset)

	cfRows, err := db.Conn.QueryContext(ctx, cfListQuery, cfArgs...)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	defer cfRows.Close()

	cfItems := []schemas.CodeFindingAssignment{}
	for cfRows.Next() {
		var a schemas.CodeFindingAssignment
		if err := cfRows.Scan(
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
		cfItems = append(cfItems, a)
	}

	resp := AnalystTriageResponse{
		Vulnerabilities: AssignmentList{
			Items: vulnItems,
			Total: vulnTotal,
		},
		CodeFindings: CodeFindingList{
			Items: cfItems,
			Total: cfTotal,
		},
	}

	return c.JSON(resp)
}

func createCodeFindingAssignment(c *fiber.Ctx) error {
	var req schemas.CreateCodeFindingAssignmentReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
	}
	if req.CodeFindingID == 0 || req.AssigneeID == 0 {
		return c.Status(400).JSON(fiber.Map{
			"error": "code_finding_id, assignee_id",
		})
	}

	if req.Priority == "" {
		req.Priority = "medium"
	}

	if req.Status == "" {
		req.Status = "open"
	}

	userIDHeader := c.Get("X-User-Id")
	if userIDHeader == "" {
		return c.Status(400).JSON(fiber.Map{"error": "X-User-Id header is required"})
	}
	assignedBy, err := strconv.ParseInt(userIDHeader, 10, 64)
	if err != nil || assignedBy == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "invalid X-User-Id header"})
	}

	ctx := context.Background()

	var tmp int64
	if err := db.Conn.QueryRowContext(
		ctx,
		"SELECT id FROM code_findings WHERE id = $1",
		req.CodeFindingID,
	).Scan(&tmp); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c.Status(404).JSON(fiber.Map{"error": "code finding not found"})
		}
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	var due sql.NullTime
	if req.DueDate != nil && strings.TrimSpace(*req.DueDate) != "" {
		t, err := time.Parse(time.RFC3339, *req.DueDate)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid due_date, must be RFC3339"})
		}
		due = sql.NullTime{Time: t, Valid: true}
	}

	query := `
        INSERT INTO code_finding_assignments (
            code_finding_id, assignee_id, assigned_by,
            status, priority, note, due_date
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT (code_finding_id) DO UPDATE
        SET assignee_id = EXCLUDED.assignee_id,
            status      = EXCLUDED.status,
            priority    = EXCLUDED.priority,
            note        = EXCLUDED.note,
            due_date    = EXCLUDED.due_date,
            updated_at  = NOW()
        RETURNING id, code_finding_id, assignee_id, assigned_by,
                  status, priority, note, due_date, created_at, updated_at;
    `

	var a schemas.CodeFindingAssignment
	row := db.Conn.QueryRowContext(
		ctx,
		query,
		req.CodeFindingID,
		req.AssigneeID,
		assignedBy,
		req.Status,
		req.Priority,
		req.Note,
		due,
	)
	if err := row.Scan(
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
	); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(201).JSON(a)
}

func bulkAssignCodeFinding(c *fiber.Ctx) error {
	var req schemas.BulkCodeFindingAssignReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
	}
	if len(req.CodeFindingIDs) == 0 || req.AssigneeID == 0 {
		return c.Status(400).JSON(fiber.Map{
			"error": "code_finding_ids, assignee_id",
		})
	}

	if req.Priority == "" {
		req.Priority = "medium"
	}

	if req.Status == "" {
		req.Status = "open"
	}

	userIDHeader := c.Get("X-User-Id")
	if userIDHeader == "" {
		return c.Status(400).JSON(fiber.Map{"error": "X-User-Id header is required"})
	}
	assignedBy, err := strconv.ParseInt(userIDHeader, 10, 64)
	if err != nil || assignedBy == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "invalid X-User-Id header"})
	}

	var due sql.NullTime
	if req.DueDate != nil && *req.DueDate != "" {
		if t, err := time.Parse(time.RFC3339, *req.DueDate); err == nil {
			due = sql.NullTime{Time: t, Valid: true}
		}
	}

	ctx := context.Background()
	tx, err := db.Conn.BeginTx(ctx, nil)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	defer tx.Rollback()

	assigned := make([]int64, 0)
	skipped := make([]map[string]interface{}, 0)

	stmt := `
        INSERT INTO code_finding_assignments (
            code_finding_id, assignee_id, assigned_by,
            status, priority, note, due_date
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT (code_finding_id) DO UPDATE
        SET assignee_id = EXCLUDED.assignee_id,
            status      = EXCLUDED.status,
            priority    = EXCLUDED.priority,
            note        = EXCLUDED.note,
            due_date    = EXCLUDED.due_date,
            updated_at  = NOW();
    `

	for _, id := range req.CodeFindingIDs {
		if id == 0 {
			continue
		}
		if _, err := tx.ExecContext(
			ctx, stmt,
			id, req.AssigneeID, assignedBy,
			req.Status, req.Priority, req.Note, due,
		); err != nil {
			skipped = append(skipped, map[string]interface{}{
				"id":     id,
				"reason": err.Error(),
			})
			continue
		}
		assigned = append(assigned, id)
	}

	if err := tx.Commit(); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"assigned": assigned,
		"skipped":  skipped,
	})
}

func updateCodeFindingAssignment(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil || id == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "invalid id"})
	}

	var req schemas.UpdateCodeFindingAssignmentReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
	}

	sets := []string{}
	args := []interface{}{}
	idx := 1

	if req.Status != nil {
		sets = append(sets, "status = $"+strconv.Itoa(idx))
		args = append(args, *req.Status)
		idx++
	}
	if req.Priority != nil {
		sets = append(sets, "priority = $"+strconv.Itoa(idx))
		args = append(args, *req.Priority)
		idx++
	}
	if req.Note != nil {
		sets = append(sets, "note = $"+strconv.Itoa(idx))
		args = append(args, *req.Note)
		idx++
	}
	if req.AssigneeID != nil {
		sets = append(sets, "assignee_id = $"+strconv.Itoa(idx))
		args = append(args, *req.AssigneeID)
		idx++
	}
	if req.DueDate != nil {
		if *req.DueDate == "" {
			sets = append(sets, "due_date = NULL")
		} else {
			if t, err := time.Parse(time.RFC3339, *req.DueDate); err == nil {
				sets = append(sets, "due_date = $"+strconv.Itoa(idx))
				args = append(args, t)
				idx++
			}
		}
	}

	if len(sets) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "no fields to update"})
	}

	sets = append(sets, "updated_at = NOW()")
	args = append(args, id)

	query := `
        UPDATE code_finding_assignments
        SET ` + strings.Join(sets, ", ") + `
        WHERE id = $` + strconv.Itoa(len(args)) + `
        RETURNING id, code_finding_id, assignee_id, assigned_by,
                  status, priority, note, due_date, created_at, updated_at;
    `

	var a schemas.CodeFindingAssignment
	row := db.Conn.QueryRowContext(context.Background(), query, args...)
	if err := row.Scan(
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
	); err != nil {
		if err == sql.ErrNoRows {
			return c.Status(404).JSON(fiber.Map{"error": "assignment not found"})
		}
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(a)
}
