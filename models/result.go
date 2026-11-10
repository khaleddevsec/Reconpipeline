package models

import "time"

// CollectedData holds raw HTTP metadata from the collector. No analysis is performed here.
type CollectedData struct {
	Target       Target
	StatusCode   int
	Headers      map[string][]string
	Cookies      []*Cookie
	Redirects    []Redirect
	TLS          *TLSInfo
	Timing       TimingInfo
	RawBody      []byte
	ServerBanner string
	HTTPVersion  string
	Compression  string
	CollectedAt  time.Time
	Error        error
}

// Cookie represents an HTTP cookie.
type Cookie struct {
	Name     string
	Value    string
	Secure   bool
	HttpOnly bool
	SameSite string
	Path     string
	Domain   string
	Expires  time.Time
}

// Redirect represents one HTTP redirect hop.
type Redirect struct {
	From       string
	To         string
	StatusCode int
}

// TLSInfo holds TLS and certificate details.
type TLSInfo struct {
	Version          string
	CipherSuite      string
	Issuer           string
	Subject          string
	NotBefore        time.Time
	NotAfter         time.Time
	SelfSigned       bool
	Expired          bool
	WeakCipher       bool
	WeakProtocol     bool // true when < TLS 1.2
	SANs             []string
	CertificateChain int
}

// TimingInfo holds per-phase request timing.
type TimingInfo struct {
	DNSLookup    time.Duration
	TCPConnect   time.Duration
	TLSHandshake time.Duration
	FirstByte    time.Duration
	Total        time.Duration
}

// Fingerprint identifies a detected technology component.
type Fingerprint struct {
	Category   string // "server" | "framework" | "cms" | "cdn" | "waf" | "language"
	Name       string
	Version    string
	Confidence float64
	Evidence   string
}

// ScanResult holds all analysis results for a single target.
type ScanResult struct {
	ID            string
	Target        Target
	CollectedData CollectedData
	Fingerprints  []Fingerprint
	Findings      []Finding
	RiskScore     float64
	CollectedAt   time.Time
	AnalysedAt    time.Time
}
