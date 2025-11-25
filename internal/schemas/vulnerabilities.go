package schemas

import "time"

type Assignment struct {
	ID               int64      `json:"id"`
	VulnerabilityID  int64      `json:"vulnerability_id"`
	AssigneeID       int64      `json:"assignee_id"`
	AssignedBy       int64      `json:"assigned_by"`
	Status           string     `json:"status"`
	Priority         string     `json:"priority"`
	Note             string     `json:"note"`
	DueDate          *time.Time `json:"due_date,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	ProjectName      string     `json:"project_name,omitempty"`
	ComponentName    string     `json:"component_name,omitempty"`
	ComponentVersion string     `json:"component_version,omitempty"`
	Severity         string     `json:"severity,omitempty"`
	AssigneeEmail    string     `json:"assignee_email,omitempty"`
	AssignedByEmail  string     `json:"assigned_by_email,omitempty"`
	Source           string     `json:"source,omitempty"`
}

type CodeFindingAssignment struct {
	ID              int64      `json:"id"`
	CodeFindingID   int64      `json:"code_finding_id"`
	AssigneeID      int64      `json:"assignee_id"`
	AssignedBy      int64      `json:"assigned_by"`
	Status          string     `json:"status"`
	Priority        string     `json:"priority"`
	Note            string     `json:"note"`
	DueDate         *time.Time `json:"due_date,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	ProjectName     string     `json:"project_name,omitempty"`
	RuleID          string     `json:"rule_id,omitempty"`
	RuleTitle       string     `json:"rule_title,omitempty"`
	Severity        string     `json:"severity,omitempty"`
	Confidence      string     `json:"confidence,omitempty"`
	Category        string     `json:"category,omitempty"`
	FilePath        string     `json:"file_path,omitempty"`
	StartLine       int        `json:"start_line,omitempty"`
	EndLine         int        `json:"end_line,omitempty"`
	AssigneeEmail   string     `json:"assignee_email,omitempty"`
	AssignedByEmail string     `json:"assigned_by_email,omitempty"`
	Source          string     `json:"source,omitempty"`
}

type CreateAssignmentReq struct {
	VulnerabilityID int64   `json:"vulnerability_id"`
	AssigneeID      int64   `json:"assignee_id"`
	Status          string  `json:"status"`   // open | in_progress | resolved | ...
	Priority        string  `json:"priority"` // low | medium | high | critical
	Note            string  `json:"note"`
	DueDate         *string `json:"due_date,omitempty"` // RFC3339
}

type BulkAssignReq struct {
	VulnerabilityIDs []int64 `json:"vulnerability_ids"`
	AssigneeID       int64   `json:"assignee_id"`
	Status           string  `json:"status"`
	Priority         string  `json:"priority"`
	Note             string  `json:"note"`
	DueDate          *string `json:"due_date,omitempty"`
}

type UpdateAssignmentReq struct {
	Status     *string `json:"status,omitempty"`
	Priority   *string `json:"priority,omitempty"`
	Note       *string `json:"note,omitempty"`
	AssigneeID *int64  `json:"assignee_id,omitempty"`
	DueDate    *string `json:"due_date,omitempty"` // null = clear
}

type CreateCodeFindingAssignmentReq struct {
	CodeFindingID int64   `json:"code_finding_id"`
	AssigneeID    int64   `json:"assignee_id"`
	Status        string  `json:"status"`   // open | in_progress | resolved | ...
	Priority      string  `json:"priority"` // low | medium | high | critical
	Note          string  `json:"note"`
	DueDate       *string `json:"due_date,omitempty"` // RFC3339
}

type BulkCodeFindingAssignReq struct {
	CodeFindingIDs []int64 `json:"code_finding_ids"`
	AssigneeID     int64   `json:"assignee_id"`
	Status         string  `json:"status"`
	Priority       string  `json:"priority"`
	Note           string  `json:"note"`
	DueDate        *string `json:"due_date,omitempty"` // RFC3339
}

type UpdateCodeFindingAssignmentReq struct {
	Status     *string `json:"status,omitempty"`
	Priority   *string `json:"priority,omitempty"`
	Note       *string `json:"note,omitempty"`
	AssigneeID *int64  `json:"assignee_id,omitempty"`
	DueDate    *string `json:"due_date,omitempty"` // null = clear
}
