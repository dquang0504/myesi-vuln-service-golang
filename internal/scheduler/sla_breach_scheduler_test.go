package scheduler

import (
	"database/sql"
	"testing"
	"time"
)

func TestShouldFlagBreachDueDate(t *testing.T) {
	now := time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC)
	row := slaRow{
		DueDate:          sql.NullTime{Time: now.Add(-48 * time.Hour), Valid: true},
		AssignmentStatus: "open",
		CreatedAt:        now.Add(-10 * 24 * time.Hour),
	}
	breached, reason, overdue := shouldFlagBreach(row, now)
	if !breached {
		t.Fatalf("expected breach when due date passed")
	}
	if reason != "due_date" {
		t.Fatalf("expected due_date reason, got %s", reason)
	}
	if overdue <= 0 {
		t.Fatalf("expected overdue days > 0")
	}

	row.AssignmentStatus = "resolved"
	if breached, _, _ = shouldFlagBreach(row, now); breached {
		t.Fatalf("resolved assignment should not breach")
	}
}

func TestShouldFlagBreachSeverityThresholds(t *testing.T) {
	now := time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		severity string
		age      time.Duration
	}{
		{"critical", 8 * 24 * time.Hour},
		{"high", 15 * 24 * time.Hour},
		{"medium", 31 * 24 * time.Hour},
		{"low", 91 * 24 * time.Hour},
		{"unknown", 61 * 24 * time.Hour},
	}

	for _, tc := range cases {
		row := slaRow{
			Severity:         tc.severity,
			CreatedAt:        now.Add(-tc.age),
			AssignmentStatus: "open",
		}
		breached, reason, _ := shouldFlagBreach(row, now)
		if !breached {
			t.Fatalf("expected breach for severity %s", tc.severity)
		}
		if reason != "age" {
			t.Fatalf("expected age reason for %s got %s", tc.severity, reason)
		}
	}

	nonBreach := slaRow{
		Severity:         "high",
		CreatedAt:        now.Add(-10 * 24 * time.Hour),
		AssignmentStatus: "open",
	}
	if breached, _, _ := shouldFlagBreach(nonBreach, now); breached {
		t.Fatalf("should not breach before SLA age")
	}
}

func TestEvaluateSLABreachesGroupsAndLimitsSamples(t *testing.T) {
	now := time.Now().UTC()
	rows := []slaRow{
		{
			VulnerabilityID: 1,
			ProjectID:       42,
			ProjectName:     "alpha",
			CreatedAt:       now.Add(-40 * 24 * time.Hour),
			Severity:        "medium",
		},
		{
			VulnerabilityID: 2,
			ProjectID:       42,
			ProjectName:     "alpha",
			CreatedAt:       now.Add(-50 * 24 * time.Hour),
			Severity:        "medium",
		},
		{
			VulnerabilityID: 3,
			ProjectID:       99,
			ProjectName:     "beta",
			DueDate:         sql.NullTime{Time: now.Add(-24 * time.Hour), Valid: true},
		},
	}

	breaches := evaluateSLABreaches(rows, now, 1)
	if len(breaches) != 2 {
		t.Fatalf("expected 2 project breaches, got %d", len(breaches))
	}

	for _, b := range breaches {
		if b.ProjectID == 42 {
			if b.Count != 2 {
				t.Fatalf("expected 2 breaches for project 42, got %d", b.Count)
			}
			if len(b.Samples) != 1 {
				t.Fatalf("expected sample limit applied")
			}
		}
		if b.ProjectID == 99 && b.Count != 1 {
			t.Fatalf("expected 1 breach for project 99, got %d", b.Count)
		}
	}
}
