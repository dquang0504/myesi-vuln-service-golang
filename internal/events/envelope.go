package events

import (
	"time"

	"github.com/google/uuid"
)

// Envelope defines the standard wrapper for outbound Kafka events.
type Envelope struct {
	Type           string      `json:"type"`
	Version        int         `json:"version"`
	ID             string      `json:"id"`
	OccurredAt     time.Time   `json:"occurred_at"`
	OrganizationID int64       `json:"organization_id,omitempty"`
	ProjectName    string      `json:"project_name,omitempty"`
	Data           interface{} `json:"data"`
}

// NewEnvelope builds a versioned envelope for the provided event data.
func NewEnvelope(eventType string, orgID int64, projectName string, data interface{}) Envelope {
	return Envelope{
		Type:           eventType,
		Version:        1,
		ID:             uuid.NewString(),
		OccurredAt:     time.Now().UTC(),
		OrganizationID: orgID,
		ProjectName:    projectName,
		Data:           data,
	}
}
