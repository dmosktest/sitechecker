package domain

import "time"

type Status string

const (
	StatusPass  Status = "pass"
	StatusFail  Status = "fail"
	StatusWarn  Status = "warn"
	StatusInfo  Status = "info"
	StatusError Status = "error"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type CheckState string

const (
	CheckQueued    CheckState = "queued"
	CheckRunning   CheckState = "running"
	CheckDone      CheckState = "done"
	CheckFailed    CheckState = "failed"
	CheckCancelled CheckState = "cancelled"
)

type GroupID string

const (
	GroupHeaders GroupID = "headers"
	GroupTLS     GroupID = "tls"
	GroupCookie  GroupID = "cookie"
	GroupFiles   GroupID = "files"
	GroupSoft    GroupID = "software"
	GroupDNS     GroupID = "dns"
)

type Evidence struct {
	URL    string `json:"url,omitempty"`
	Header string `json:"header,omitempty"`
	Value  string `json:"value,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type Fixes struct {
	Nginx    string `json:"nginx,omitempty"`
	Apache   string `json:"apache,omitempty"`
	Htaccess string `json:"htaccess,omitempty"`
	Traefik  string `json:"traefik,omitempty"`
	Caddy    string `json:"caddy,omitempty"`
	Other    string `json:"other,omitempty"`
}

type Finding struct {
	ID         string   `json:"id"`
	Group      GroupID  `json:"group"`
	Status     Status   `json:"status"`
	Severity   Severity `json:"severity"`
	Evidence   Evidence `json:"evidence"`
	Fixes      Fixes    `json:"fixes,omitempty"`
	TitleKey   string   `json:"title_key"`
	DangerKey  string   `json:"danger_key"`
	SourceURL  string   `json:"source_url,omitempty"`
}

type GroupProgress struct {
	ID     GroupID `json:"id"`
	State  string  `json:"state"`
	Done   int     `json:"done"`
	Total  int     `json:"total"`
}

type CheckJob struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	Lang      string    `json:"lang"`
	CreatedAt time.Time `json:"created_at"`
	IP        string    `json:"ip"`
}

type CheckRecord struct {
	ID           string           `json:"id"`
	Domain       string           `json:"domain"`
	Lang         string           `json:"lang"`
	State        CheckState       `json:"state"`
	Level        int              `json:"level"`
	Score        int              `json:"score"`
	Grade        string           `json:"grade"`
	DurationMS   int64            `json:"duration_ms,omitempty"`
	CreatedAt    time.Time        `json:"created_at"`
	FinishedAt   *time.Time       `json:"finished_at,omitempty"`
	Progress     []GroupProgress  `json:"progress"`
	Findings     []Finding        `json:"findings,omitempty"`
	TopFixes     []string         `json:"top_fixes,omitempty"`
	Error        string           `json:"error,omitempty"`
	Disclaimer   string           `json:"disclaimer"`
}
