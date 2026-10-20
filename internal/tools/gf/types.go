// Package gf provides the GF (grep-like pattern matching) tool adapter and Advanced Pattern Intelligence Layer.
package gf

// ConfidenceLevel indicates the evaluated confidence for candidate matches.
type ConfidenceLevel string

const (
	ConfidenceHigh   ConfidenceLevel = "HIGH"
	ConfidenceMedium ConfidenceLevel = "MEDIUM"
	ConfidenceLow    ConfidenceLevel = "LOW"
)

// PatternCategory categorises pattern intelligence candidates.
type PatternCategory string

const (
	CategoryVulnerability PatternCategory = "Vulnerability Candidate"
	CategoryAPI           PatternCategory = "API Intelligence"
	CategoryAuth          PatternCategory = "Authentication Intelligence"
	CategoryAuthorization PatternCategory = "Authorization Candidate"
	CategoryAdmin         PatternCategory = "Administrative Intelligence"
	CategoryDebug         PatternCategory = "Debug & Metrics Intelligence"
	CategorySensitiveFile PatternCategory = "Sensitive File Intelligence"
	CategoryBackup        PatternCategory = "Backup & Legacy Intelligence"
	CategorySecret        PatternCategory = "Secret & Credential Indicator"
	CategoryCloud         PatternCategory = "Cloud Infrastructure Intelligence"
	CategoryFileOps       PatternCategory = "File Operations Intelligence"
	CategoryTakeover      PatternCategory = "Subdomain Takeover Intelligence"
)

// FindingState indicates the explicit validation state of an intelligence finding.
// Reconpipeline strictly distinguishes unverified candidates from corroborated observations and confirmed conditions.
type FindingState string

const (
	StateCandidate    FindingState = "candidate"
	StateCorroborated FindingState = "corroborated"
	StateConfirmed    FindingState = "confirmed"
	StateRejected     FindingState = "rejected"
	StateUnverified   FindingState = "unverified"
)

// CandidateMatch represents an identified intelligence match for a URL.
// IMPORTANT: GF pattern matches are strictly candidate areas of interest, never confirmed vulnerabilities.
type CandidateMatch struct {
	URL              string          `json:"url"`
	Pattern          string          `json:"pattern"`
	Category         PatternCategory `json:"category"`
	Confidence       ConfidenceLevel `json:"confidence"`
	State            FindingState    `json:"state"`
	RequiredEvidence string          `json:"required_evidence,omitempty"`
	MatchedParam     string          `json:"matched_param,omitempty"`
	MatchedPath      string          `json:"matched_path,omitempty"`
	Context          string          `json:"context,omitempty"`
	SecurityFocus    string          `json:"security_focus"`
	StatusCode       int             `json:"status_code,omitempty"`
	ContentType      string          `json:"content_type,omitempty"`
	Server           string          `json:"server,omitempty"`
	ContentLength    int             `json:"content_length,omitempty"`
	Location         string          `json:"location,omitempty"`
	Technologies     []string        `json:"technologies,omitempty"`
}

// TakeoverCandidate represents a potential subdomain takeover vulnerability candidate.
type TakeoverCandidate struct {
	Subdomain        string          `json:"subdomain"`
	CNAME            string          `json:"cname"`
	Service          string          `json:"service"`
	Fingerprint      string          `json:"fingerprint"`
	Confidence       ConfidenceLevel `json:"confidence"`
	State            FindingState    `json:"state"`
	RequiredEvidence string          `json:"required_evidence,omitempty"`
	StatusCode       int             `json:"status_code,omitempty"`
	Evidence         string          `json:"evidence"`
}

// CategorySummary aggregates count and confidence levels per category.
type CategorySummary struct {
	Category         PatternCategory `json:"category"`
	TotalMatches     int             `json:"total_matches"`
	HighConfidence   int             `json:"high_confidence"`
	MediumConfidence int             `json:"medium_confidence"`
	LowConfidence    int             `json:"low_confidence"`
}

// PatternDetailSummary aggregates count and confidence levels per pattern.
type PatternDetailSummary struct {
	Name                   string                  `json:"name"`
	Category               PatternCategory         `json:"category"`
	OutFile                string                  `json:"out_file"`
	Matches                int                     `json:"matches"`
	ConfidenceDistribution map[ConfidenceLevel]int `json:"confidence_distribution"`
}

// IntelligenceSummary is the top-level structured summary written to pattern-summary.json.
type IntelligenceSummary struct {
	ScanID             string                     `json:"scan_id,omitempty"`
	Target             string                     `json:"target,omitempty"`
	GeneratedAt        string                     `json:"generated_at"`
	TotalCandidateURLs int                        `json:"total_candidate_urls"`
	TotalMatches       int                        `json:"total_matches"`
	TakeoverCount      int                        `json:"takeover_count"`
	ConfidenceCounts   map[ConfidenceLevel]int    `json:"confidence_counts"`
	Categories         map[string]CategorySummary `json:"categories"`
	PatternCounts      map[string]int             `json:"pattern_counts"`
	TakeoverCandidates []TakeoverCandidate        `json:"takeover_candidates,omitempty"`
	Disclaimer         string                     `json:"disclaimer"`

	// Legacy backward compatibility counts
	XSS      int `json:"xss"`
	SQLi     int `json:"sqli"`
	LFI      int `json:"lfi"`
	SSRF     int `json:"ssrf"`
	Redirect int `json:"redirect"`
}

// AnalysisContext provides contextual intelligence metadata from preceding stages (Stage 01 DNS, Stage 02 HTTPX, Stage 06 HTTPX).
type AnalysisContext struct {
	TargetDomain     string
	VerifiedURLsFile string
	HTTPX2MetaFile   string
	HTTPX1MetaFile   string
	DNSRecordsFile   string
	SubdomainsFile   string
	LiveHostsFile    string
}
