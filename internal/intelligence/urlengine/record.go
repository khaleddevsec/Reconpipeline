// Package urlengine provides the structured URL data model and intelligence engine.
package urlengine

import (
	"time"
)

// VerificationState represents the explicit verification outcome of an endpoint.
type VerificationState string

const (
	VerificationUnverified   VerificationState = "unverified"
	VerificationCandidate    VerificationState = "candidate"
	VerificationCorroborated VerificationState = "corroborated"
	VerificationConfirmed    VerificationState = "confirmed"
	VerificationRejected     VerificationState = "rejected"
)

// SelectionDecision indicates why a URL was included, excluded, or deduplicated.
type SelectionDecision string

const (
	DecisionSelected         SelectionDecision = "selected"
	DecisionExcludedScope    SelectionDecision = "excluded_scope"
	DecisionExcludedStatic   SelectionDecision = "excluded_static"
	DecisionDeduplicated     SelectionDecision = "deduplicated"
	DecisionBudgetExceeded   SelectionDecision = "budget_exceeded"
)

// URLRecord is the structured, lossless representation of a discovered URL.
// It preserves original identity, source provenance, normalization decisions,
// canonical comparison keys, and verification outcomes.
type URLRecord struct {
	// Identity
	OriginalURL   string `json:"original_url"`
	NormalizedURL string `json:"normalized_url"`
	CanonicalKey  string `json:"canonical_key"`

	// Parsed Components
	Scheme   string `json:"scheme"`
	Host     string `json:"host"`
	Port     string `json:"port,omitempty"`
	Path     string `json:"path"`
	RawQuery string `json:"raw_query,omitempty"`
	Fragment string `json:"fragment,omitempty"`

	// Provenance & Collection Metadata
	Sources            []string  `json:"sources"`                       // e.g. ["katana", "gau"]
	DiscoveryTimestamp time.Time `json:"discovery_timestamp"`
	ExtractionMethod   string    `json:"extraction_method,omitempty"`   // "crawl", "archive", "js_route"
	ReferringURL       string    `json:"referring_url,omitempty"`

	// Intelligence & Classification
	IsAPI           bool                `json:"is_api"`
	IsJavaScript    bool                `json:"is_javascript"`
	IsParameterized bool                `json:"is_parameterized"`
	Parameters      map[string][]string `json:"parameters,omitempty"`
	ClusterPattern  string              `json:"cluster_pattern,omitempty"`

	// Prioritization
	PriorityScore int           `json:"priority_score"`
	Priority      PriorityLevel `json:"priority"`
	Reasons       []string      `json:"reasons,omitempty"`

	// Budget & Verification
	SelectionDecision SelectionDecision `json:"selection_decision"`
	SelectionReason   string            `json:"selection_reason,omitempty"`
	VerificationState VerificationState `json:"verification_state"`

	// HTTP Metadata (populated by HTTPX #2 verification)
	StatusCode    int      `json:"status_code,omitempty"`
	ContentType   string   `json:"content_type,omitempty"`
	ContentLength int      `json:"content_length,omitempty"`
	Server        string   `json:"server,omitempty"`
	Title         string   `json:"title,omitempty"`
	Technologies  []string `json:"technologies,omitempty"`
	FinalURL      string   `json:"final_url,omitempty"`
}

// NewURLRecord initializes a structured URLRecord from raw input.
func NewURLRecord(raw, source, extractionMethod string) *URLRecord {
	norm := NormalizeURL(raw)
	canon := CanonicalKey(raw)

	rec := &URLRecord{
		OriginalURL:        raw,
		NormalizedURL:      norm,
		CanonicalKey:       canon,
		Sources:            []string{source},
		DiscoveryTimestamp: time.Now().UTC(),
		ExtractionMethod:   extractionMethod,
		VerificationState:  VerificationUnverified,
		SelectionDecision:  DecisionSelected,
		Parameters:         make(map[string][]string),
	}

	return rec
}
