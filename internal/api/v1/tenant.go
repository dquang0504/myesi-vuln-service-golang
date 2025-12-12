package v1

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"

	fiber "github.com/gofiber/fiber/v2"

	"myesi-vuln-service-golang/internal/db"
)

func requireOrgID(c *fiber.Ctx) (int, error) {
	orgHeader := strings.TrimSpace(c.Get("X-Organization-ID"))
	if orgHeader == "" {
		return 0, fiber.NewError(fiber.StatusUnauthorized, "Organization context missing")
	}

	orgID, err := strconv.Atoi(orgHeader)
	if err != nil || orgID <= 0 {
		return 0, fiber.NewError(fiber.StatusBadRequest, "Invalid X-Organization-ID header")
	}

	return orgID, nil
}

func ensureProjectAccessible(ctx context.Context, projectName string, orgID int) (int, error) {
	const query = `
        SELECT id
        FROM projects
        WHERE name = $1
          AND organization_id = $2
    `

	var projectID int
	err := db.Conn.QueryRowContext(ctx, query, projectName, orgID).Scan(&projectID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, fiber.NewError(fiber.StatusNotFound, "Project not found")
		}
		return 0, fmt.Errorf("verify project ownership: %w", err)
	}
	return projectID, nil
}

func ensureSBOMAccessible(ctx context.Context, sbomID string, orgID int) (string, error) {
	const query = `
        SELECT s.project_name
        FROM sboms s
        LEFT JOIN projects p ON p.id = s.project_id
        WHERE s.id = $1
          AND (
                (p.id IS NOT NULL AND p.organization_id = $2)
             OR EXISTS (
                    SELECT 1 FROM projects px
                    WHERE px.name = s.project_name
                      AND px.organization_id = $2
                )
          )
    `

	var projectName string
	err := db.Conn.QueryRowContext(ctx, query, sbomID, orgID).Scan(&projectName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fiber.NewError(fiber.StatusNotFound, "SBOM not found")
		}
		return "", fmt.Errorf("verify sbom ownership: %w", err)
	}

	return projectName, nil
}
