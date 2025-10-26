package utils

import (
	"context"
	"database/sql"
	"myesi-vuln-service-golang/models"

	"github.com/aarondl/sqlboiler/v4/queries/qm"
)

func FindVulnsBySbomID(ctx context.Context, db *sql.DB, sbomID string) ([]*models.Vulnerability, error) {
	return models.Vulnerabilities(
		qm.Where("sbom_id=?", sbomID),
	).All(ctx, db)
}
