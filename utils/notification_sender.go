package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"myesi-vuln-service-golang/internal/events"
	kafkautil "myesi-vuln-service-golang/internal/kafka"
	"time"

	"github.com/segmentio/kafka-go"
)

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

func notificationWriter() (*kafka.Writer, error) {
	return kafkautil.GetWriter(kafkautil.TopicNotificationEvents)
}

// PublishAssignmentNotification sends an event to the notification bus.
func PublishAssignmentNotification(evt AssignmentNotificationPayload) error {
	writer, err := notificationWriter()
	if err != nil {
		return err
	}

	data := map[string]interface{}{
		"user_id":  evt.UserID,
		"severity": evt.Severity,
		"payload":  evt.Payload,
	}
	env := events.NewEnvelope(evt.Type, evt.OrganizationID, fmt.Sprintf("%v", evt.Payload["project"]), data)
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}

	msg := kafka.Message{
		Key:   []byte(fmt.Sprintf("user-%d", evt.UserID)),
		Value: body,
		Time:  time.Now().UTC(),
	}

	return writer.WriteMessages(context.Background(), msg)
}

// PublishScanSummary notifies developers about completed scans with counts.
func PublishScanSummary(orgID int64, project string, vulns int, codeFindings int) {
	writer, err := notificationWriter()
	if err != nil {
		log.Printf("[NOTIFY] writer unavailable: %v", err)
		return
	}
	payload := map[string]interface{}{
		"project":       project,
		"vulns":         vulns,
		"code_findings": codeFindings,
		"action_url":    "/developer/vulnerabilities",
		"target_role":   "developer",
	}

	data := map[string]interface{}{
		"severity": "info",
		"payload":  payload,
	}
	env := events.NewEnvelope("project.scan.summary", orgID, project, data)

	body, err := json.Marshal(env)
	if err != nil {
		log.Printf("[NOTIFY] marshal scan summary failed: %v", err)
		return
	}

	msg := kafka.Message{
		Key:   []byte(fmt.Sprintf("org-%d", orgID)),
		Value: body,
		Time:  time.Now().UTC(),
	}

	if err := writer.WriteMessages(context.Background(), msg); err != nil {
		log.Printf("[NOTIFY] publish scan summary failed: %v", err)
	}
}

// PublishSBOMSummary notifies about SBOM scan results (manual or auto).
func PublishSBOMSummary(orgID int64, project string, components int, vulns int) {
	writer, err := notificationWriter()
	if err != nil {
		log.Printf("[NOTIFY] writer unavailable: %v", err)
		return
	}
	payload := map[string]interface{}{
		"project":     project,
		"components":  components,
		"vulns":       vulns,
		"action_url":  "/developer/vulnerabilities",
		"target_role": "developer",
	}

	data := map[string]interface{}{
		"severity": "info",
		"payload":  payload,
	}
	env := events.NewEnvelope("sbom.scan.summary", orgID, project, data)

	body, err := json.Marshal(env)
	if err != nil {
		log.Printf("[NOTIFY] marshal sbom summary failed: %v", err)
		return
	}

	msg := kafka.Message{
		Key:   []byte(fmt.Sprintf("org-%d", orgID)),
		Value: body,
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

	writer, err := notificationWriter()
	if err != nil {
		log.Printf("[NOTIFY] writer unavailable: %v", err)
		return
	}

	payload := map[string]interface{}{
		"project":        project,
		"critical_count": len(samples),
		"samples":        samples,
		"action_url":     "/developer/vulnerabilities",
		"target_role":    "developer",
	}

	data := map[string]interface{}{
		"severity": "critical",
		"payload":  payload,
	}
	if len(targetEmails) > 0 {
		data["emails"] = targetEmails
	}

	env := events.NewEnvelope("vulnerability.critical", orgID, project, data)
	body, err := json.Marshal(env)
	if err != nil {
		log.Printf("[NOTIFY] marshal critical vuln alert failed: %v", err)
		return
	}

	msg := kafka.Message{
		Key:   []byte(fmt.Sprintf("org-%d-critical", orgID)),
		Value: body,
		Time:  time.Now().UTC(),
	}

	if err := writer.WriteMessages(context.Background(), msg); err != nil {
		log.Printf("[NOTIFY] publish critical alert failed: %v", err)
	}
}
