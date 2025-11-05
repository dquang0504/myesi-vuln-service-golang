package services

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// SeverityToControlMapping defines ISO controls by CVSS numeric score ranges and severity
var SeverityToControlMapping = []struct {
	MinScore   float64
	MaxScore   float64
	ControlIDs []string // allow multiple controls
}{
	{9.0, 10.0, []string{"A.8.24", "A.8.25"}}, // Critical
	{7.0, 8.9, []string{"A.8.24"}},            // High
	{4.0, 6.9, []string{"A.8.26"}},            // Medium / Moderate
	{0.1, 3.9, []string{"A.8.7"}},             // Low
	{0.0, 0.0, []string{"A.8.9"}},             // Unknown / fallback
}

// AutoMapControlAdvanced maps a vulnerability to one or more ISO 27001:2022 controls based on CVSS score or severity label
func AutoMapControlAdvanced(ctx context.Context, db *sql.DB, sbomID, compName, compVersion string, cvssScore float64, severityLabel string) error {
	var controlIDs []string

	// 1. Map numeric CVSS score first if > 0
	for _, m := range SeverityToControlMapping {
		if cvssScore >= m.MinScore && cvssScore <= m.MaxScore {
			controlIDs = m.ControlIDs
			break
		}
	}

	// 2. Fallback to severity label string mapping
	if len(controlIDs) == 0 {
		switch strings.ToLower(severityLabel) {
		case "critical", "high":
			controlIDs = []string{"A.8.24", "A.8.25"}
		case "medium", "moderate":
			controlIDs = []string{"A.8.26"}
		case "low":
			controlIDs = []string{"A.8.7"}
		default:
			controlIDs = []string{"A.8.9"}
		}
	}

	// Insert mappings into DB (multi-control)
	for _, controlID := range controlIDs {
		var title, category sql.NullString
		_ = db.QueryRowContext(ctx, `
			SELECT title, category FROM compliance_weights
			WHERE scope_key = $1 AND standard = 'ISO_27001:2022'
			LIMIT 1
		`, controlID).Scan(&title, &category)

		_, err := db.ExecContext(ctx, `
			INSERT INTO control_mappings (sbom_id, component_name, component_version, control_id, control_title, category, source)
			VALUES ($1,$2,$3,$4,$5,$6,'auto')
			ON CONFLICT DO NOTHING
		`, sbomID, compName, compVersion, controlID, title.String, category.String)

		if err != nil {
			return fmt.Errorf("failed to insert control mapping for %s: %w", controlID, err)
		}
	}

	return nil
}
