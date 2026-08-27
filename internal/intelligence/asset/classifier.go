// Package asset provides heuristic classification of discovered hostnames and assets.
package asset

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Classification represents the classified category of an asset.
type Classification string

const (
	ClassProduction  Classification = "production"
	ClassDevelopment Classification = "development"
	ClassStaging     Classification = "staging"
	ClassAPI         Classification = "api"
	ClassAdmin       Classification = "admin"
	ClassAuth        Classification = "auth"
	ClassCDN         Classification = "cdn"
	ClassMail        Classification = "mail"
	ClassStatic      Classification = "static"
	ClassUnknown     Classification = "unknown"
)

// AssetMetadata represents heuristic classification and context for a hostname.
type AssetMetadata struct {
	Hostname       string         `json:"hostname"`
	Classification Classification `json:"classification"`
	Confidence     string         `json:"confidence"` // "high", "medium", "low"
	Reason         string         `json:"reason"`
	Source         string         `json:"source"`
}

// Classifier provides asset classification functionality.
type Classifier struct{}

// NewClassifier creates an Asset Classifier.
func NewClassifier() *Classifier {
	return &Classifier{}
}

// ClassifyHostname analyzes a hostname using heuristic rule matching.
func (c *Classifier) ClassifyHostname(hostname string, source string) AssetMetadata {
	h := strings.ToLower(strings.TrimSpace(hostname))
	parts := strings.Split(h, ".")
	prefix := parts[0]

	// 1. Staging checks
	if hasPrefixAny(prefix, "stage", "staging", "stg", "preprod", "beta", "preview") ||
		containsAny(h, "stage-", "-stage", ".stage", "staging-", "-staging", ".staging", "stg-", "-stg", ".stg", "preprod-", "-preprod") {
		return AssetMetadata{
			Hostname:       hostname,
			Classification: ClassStaging,
			Confidence:     "high",
			Reason:         "hostname matches staging/preprod keyword patterns",
			Source:         source,
		}
	}

	// 2. Development checks
	if hasPrefixAny(prefix, "dev", "devel", "development", "test", "testing", "qa", "uat", "sandbox", "demo", "debug", "local") ||
		containsAny(h, "dev-", "-dev", ".dev", "test-", "-test", ".test", "qa-", "-qa", ".qa", "uat-", "-uat", "sandbox-", "demo-") {
		return AssetMetadata{
			Hostname:       hostname,
			Classification: ClassDevelopment,
			Confidence:     "high",
			Reason:         "hostname matches development/test/qa keyword patterns",
			Source:         source,
		}
	}

	// 3. API checks
	if hasPrefixAny(prefix, "api", "apis", "rest", "graphql", "grpc", "gateway", "service", "services", "ws", "v1", "v2", "v3") ||
		containsAny(h, "api-", "-api.", ".api.", "-gateway", "gateway-") {
		return AssetMetadata{
			Hostname:       hostname,
			Classification: ClassAPI,
			Confidence:     "high",
			Reason:         "hostname matches API/gateway keyword patterns",
			Source:         source,
		}
	}

	// 4. Admin / Management checks
	if hasPrefixAny(prefix, "admin", "administrator", "adm", "dashboard", "control", "manage", "manager", "management", "panel", "cpanel", "portal", "internal", "corp", "intra") ||
		containsAny(h, "admin-", "-admin", ".admin", "mgmt-", "-mgmt", ".mgmt", "panel-", "-panel") {
		return AssetMetadata{
			Hostname:       hostname,
			Classification: ClassAdmin,
			Confidence:     "high",
			Reason:         "hostname matches administrative/portal keyword patterns",
			Source:         source,
		}
	}

	// 5. Auth / Identity checks
	if hasPrefixAny(prefix, "auth", "login", "signin", "sso", "oauth", "identity", "accounts", "account", "saml", "cas", "secure", "idp") ||
		containsAny(h, "auth-", "-auth", ".auth", "sso-", "-sso", ".sso", "login-", "-login") {
		return AssetMetadata{
			Hostname:       hostname,
			Classification: ClassAuth,
			Confidence:     "high",
			Reason:         "hostname matches authentication/SSO keyword patterns",
			Source:         source,
		}
	}

	// 6. CDN / Static assets checks
	if hasPrefixAny(prefix, "cdn", "static", "assets", "asset", "media", "images", "img", "upload", "uploads", "files", "s3", "storage", "content") ||
		containsAny(h, "cdn-", "-cdn", ".cdn", "static-", "-static", ".static", "assets-", "-assets") {
		return AssetMetadata{
			Hostname:       hostname,
			Classification: ClassCDN,
			Confidence:     "high",
			Reason:         "hostname matches CDN/media/storage keyword patterns",
			Source:         source,
		}
	}

	// 7. Mail checks
	if hasPrefixAny(prefix, "mail", "email", "smtp", "pop", "pop3", "imap", "webmail", "mx", "autodiscover", "exchange") ||
		containsAny(h, "mail-", "-mail", ".mail") {
		return AssetMetadata{
			Hostname:       hostname,
			Classification: ClassMail,
			Confidence:     "high",
			Reason:         "hostname matches mail service keyword patterns",
			Source:         source,
		}
	}

	// 8. Static / General website
	if hasPrefixAny(prefix, "www", "docs", "documentation", "blog", "help", "support", "news", "status", "about", "info") {
		return AssetMetadata{
			Hostname:       hostname,
			Classification: ClassStatic,
			Confidence:     "medium",
			Reason:         "hostname matches public/static content keyword patterns",
			Source:         source,
		}
	}

	// 9. Production / Root heuristic
	if len(parts) <= 3 {
		return AssetMetadata{
			Hostname:       hostname,
			Classification: ClassProduction,
			Confidence:     "low",
			Reason:         "primary domain or standard top-level hostname",
			Source:         source,
		}
	}

	return AssetMetadata{
		Hostname:       hostname,
		Classification: ClassUnknown,
		Confidence:     "low",
		Reason:         "no specific keyword pattern matched",
		Source:         source,
	}
}

// ProcessSubdomains reads a subdomains file, classifies each hostname, and writes
// results to classified directory and metadata JSON.
func (c *Classifier) ProcessSubdomains(subdomainsFile, outDir string) ([]AssetMetadata, error) {
	classifiedDir := filepath.Join(outDir, "classified")
	if err := os.MkdirAll(classifiedDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create classified directory: %w", err)
	}

	f, err := os.Open(subdomainsFile)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open subdomains file: %w", err)
	}
	defer f.Close()

	var results []AssetMetadata
	categoryHosts := make(map[Classification][]string)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		host := strings.TrimSpace(scanner.Text())
		if host == "" {
			continue
		}

		meta := c.ClassifyHostname(host, "subfinder")
		results = append(results, meta)
		categoryHosts[meta.Classification] = append(categoryHosts[meta.Classification], host)
	}

	// Write category files
	for cat, hosts := range categoryHosts {
		sort.Strings(hosts)
		filePath := filepath.Join(classifiedDir, fmt.Sprintf("%s.txt", cat))
		if err := writeLines(filePath, hosts); err != nil {
			return nil, err
		}
	}

	// Write metadata.json in outDir
	metaJSON, _ := json.MarshalIndent(results, "", "  ")
	_ = os.WriteFile(filepath.Join(outDir, "metadata.json"), metaJSON, 0640)

	return results, nil
}

func hasPrefixAny(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func matchesAny(s string, targets ...string) bool {
	for _, t := range targets {
		if s == t {
			return true
		}
	}
	return false
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func writeLines(path string, lines []string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return fmt.Errorf("failed to write %q: %w", path, err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}
