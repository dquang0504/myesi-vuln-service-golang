package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"myesi-vuln-service-golang/internal/config"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
)

const notificationTopic = "notification-events"

// AssignmentNotificationPayload describes a notification for analyst → developer assignment.
type AssignmentNotificationPayload struct {
	Type           string                 `json:"type"`
	OrganizationID int64                  `json:"organization_id"`
	UserID         int64                  `json:"user_id"`
	Severity       string                 `json:"severity"`
	Payload        map[string]interface{} `json:"payload"`
	OccurredAt     time.Time              `json:"occurred_at"`
}

// ScanSummaryPayload describes a scan summary to notify developers.
type ScanSummaryPayload struct {
	Type           string                 `json:"type"`
	OrganizationID int64                  `json:"organization_id"`
	Severity       string                 `json:"severity"`
	Payload        map[string]interface{} `json:"payload"`
	OccurredAt     time.Time              `json:"occurred_at"`
}

type SBOMSummaryPayload struct {
	Type           string                 `json:"type"`
	OrganizationID int64                  `json:"organization_id"`
	Severity       string                 `json:"severity"`
	Payload        map[string]interface{} `json:"payload"`
	OccurredAt     time.Time              `json:"occurred_at"`
}

func getWriter() kafka.Writer {
	cfg := config.LoadConfig()
	return kafka.Writer{
		Addr:         kafka.TCP(strings.Split(cfg.KafkaBroker, ",")...),
		Topic:        notificationTopic,
		Balancer:     &kafka.LeastBytes{},
		RequiredAcks: kafka.RequireAll,
	}
}

// PublishAssignmentNotification sends an event to the notification bus.
func PublishAssignmentNotification(evt AssignmentNotificationPayload) error {
	data, err := json.Marshal(evt)
	if err != nil {
		return err
	}

	writer := getWriter()
	defer writer.Close()

	msg := kafka.Message{
		Key:   []byte(fmt.Sprintf("user-%d", evt.UserID)),
		Value: data,
		Time:  time.Now().UTC(),
	}

	return writer.WriteMessages(context.Background(), msg)
}

// PublishScanSummary notifies developers about completed scans with counts.
func PublishScanSummary(orgID int64, project string, vulns int, codeFindings int) {
	payload := map[string]interface{}{
		"project":       project,
		"vulns":         vulns,
		"code_findings": codeFindings,
		"action_url":    "/developer/vulnerabilities",
		"target_role":   "developer",
	}

	evt := ScanSummaryPayload{
		Type:           "project.scan.summary",
		OrganizationID: orgID,
		Severity:       "info",
		Payload:        payload,
		OccurredAt:     time.Now().UTC(),
	}

	data, err := json.Marshal(evt)
	if err != nil {
		log.Printf("[NOTIFY] marshal scan summary failed: %v", err)
		return
	}

	writer := getWriter()
	defer writer.Close()

	msg := kafka.Message{
		Key:   []byte(fmt.Sprintf("org-%d", orgID)),
		Value: data,
		Time:  time.Now().UTC(),
	}

	if err := writer.WriteMessages(context.Background(), msg); err != nil {
		log.Printf("[NOTIFY] publish scan summary failed: %v", err)
	}
}

// PublishSBOMSummary notifies about SBOM scan results (manual or auto).
func PublishSBOMSummary(orgID int64, project string, components int, vulns int) {
	payload := map[string]interface{}{
		"project":     project,
		"components":  components,
		"vulns":       vulns,
		"action_url":  "/developer/vulnerabilities",
		"target_role": "developer",
	}

	evt := SBOMSummaryPayload{
		Type:           "sbom.scan.summary",
		OrganizationID: orgID,
		Severity:       "info",
		Payload:        payload,
		OccurredAt:     time.Now().UTC(),
	}

	data, err := json.Marshal(evt)
	if err != nil {
		log.Printf("[NOTIFY] marshal sbom summary failed: %v", err)
		return
	}

	writer := getWriter()
	defer writer.Close()

	msg := kafka.Message{
		Key:   []byte(fmt.Sprintf("org-%d", orgID)),
		Value: data,
		Time:  time.Now().UTC(),
	}

	if err := writer.WriteMessages(context.Background(), msg); err != nil {
		log.Printf("[NOTIFY] publish sbom summary failed: %v", err)
	}
}

// PublishCriticalVulnAlert notifies developers and admins about new critical vulns.
func PublishCriticalVulnAlert(orgID int64, project string, samples []map[string]string, targetEmails []string) {
	if orgID == 0 || len(samples) == 0 {
		return
	}

	payload := map[string]interface{}{
		"project":        project,
		"critical_count": len(samples),
		"samples":        samples,
		"action_url":     "/developer/vulnerabilities",
		"target_role":    "developer",
	}

	event := map[string]interface{}{
		"type":            "vulnerability.critical",
		"organization_id": orgID,
		"severity":        "critical",
		"payload":         payload,
		"occurred_at":     time.Now().UTC(),
	}
	if len(targetEmails) > 0 {
		event["emails"] = targetEmails
	}

	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("[NOTIFY] marshal critical vuln alert failed: %v", err)
		return
	}

	writer := getWriter()
	defer writer.Close()

	msg := kafka.Message{
		Key:   []byte(fmt.Sprintf("org-%d-critical", orgID)),
		Value: data,
		Time:  time.Now().UTC(),
	}

	if err := writer.WriteMessages(context.Background(), msg); err != nil {
		log.Printf("[NOTIFY] publish critical alert failed: %v", err)
	}
}
