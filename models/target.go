package models

// Target represents a URL to be analysed by ThreatLens.
type Target struct {
	URL      string
	Scheme   string
	Host     string
	Port     int
	Path     string
	Tags     []string
	Metadata map[string]string
}
