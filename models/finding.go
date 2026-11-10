package models

// Severity represents the risk level of a finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Finding represents a single security finding correlated from collected data.
type Finding struct {
	ID          string
	Title       string
	Description string
	Severity    Severity
	Confidence  float64 // 0.0–1.0
	Evidence    []string
	References  []string
	CWEID       string
	CAPECID     string
	MITREAttack []string
	OWASP       []string
	Remediation string
}
