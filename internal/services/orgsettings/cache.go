package orgsettings

import (
	"context"
	"database/sql"
	"sync"
	"time"
)

// OrgSettings mirrors organization_settings columns needed for notification gating.
type OrgSettings struct {
	OrganizationID      int64
	AdminEmail          string
	EmailNotifications  bool
	VulnerabilityAlerts bool
	WeeklyReports       bool
	UserActivityAlerts  bool
}

type cachedEntry struct {
	settings *OrgSettings
	expires  time.Time
}

var (
	cacheTTL   = 5 * time.Minute
	cacheStore = make(map[int64]cachedEntry)
	cacheMu    sync.RWMutex
)

// Get returns cached org settings or fetches them from DB.
func Get(ctx context.Context, dbConn *sql.DB, orgID int64) (*OrgSettings, error) {
	if orgID == 0 || dbConn == nil {
		return nil, nil
	}

	cacheMu.RLock()
	if entry, ok := cacheStore[orgID]; ok && time.Now().Before(entry.expires) {
		cacheMu.RUnlock()
		return entry.settings, nil
	}
	cacheMu.RUnlock()

	query := `
        SELECT organization_id,
               COALESCE(admin_email, ''),
               COALESCE(email_notifications, TRUE),
               COALESCE(vulnerability_alerts, TRUE),
               COALESCE(weekly_reports, TRUE),
               COALESCE(user_activity_alerts, FALSE)
        FROM organization_settings
        WHERE organization_id = $1
    `

	setting := OrgSettings{
		OrganizationID:      orgID,
		EmailNotifications:  true,
		VulnerabilityAlerts: true,
		WeeklyReports:       true,
		UserActivityAlerts:  false,
	}

	if err := dbConn.QueryRowContext(ctx, query, orgID).Scan(
		&setting.OrganizationID,
		&setting.AdminEmail,
		&setting.EmailNotifications,
		&setting.VulnerabilityAlerts,
		&setting.WeeklyReports,
		&setting.UserActivityAlerts,
	); err != nil {
		if err == sql.ErrNoRows {
			// Keep defaults if settings row missing.
			cacheMu.Lock()
			cacheStore[orgID] = cachedEntry{settings: &setting, expires: time.Now().Add(cacheTTL)}
			cacheMu.Unlock()
			return &setting, nil
		}
		return nil, err
	}

	cacheMu.Lock()
	cacheStore[orgID] = cachedEntry{settings: &setting, expires: time.Now().Add(cacheTTL)}
	cacheMu.Unlock()
	return &setting, nil
}
