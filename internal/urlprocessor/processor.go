// Package urlprocessor implements URL merging, normalisation, deduplication,
// and classification in pure Go — without shell utilities.
package urlprocessor

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/frozeniceee/Reconpipeline/internal/intelligence/urlengine"
	"github.com/frozeniceee/Reconpipeline/internal/scope"
)

// SelectForVerification wraps urlengine.SelectForVerification.
func SelectForVerification(uniqueURLs []string, target *scope.Target, maxURLs int) []string {
	return urlengine.SelectForVerification(uniqueURLs, target, maxURLs)
}

// IsStaticAsset wraps urlengine.IsStaticAsset.
func IsStaticAsset(raw string) bool {
	return urlengine.IsStaticAsset(raw)
}

// Results holds the counts from URL processing.
type Results struct {
	TotalMerged   int
	Normalised    int
	Unique        int
	API           int
	JavaScript    int
	Parameterised int
	Interesting   int

	// V2.0 Intelligent Core Extensions
	TotalClusters  int
	HighInterest   int
	MediumInterest int
	LowInterest    int
	HighPriority   int
	MediumPriority int
	LowPriority    int
}

// Process merges, normalises, deduplicates, and classifies URLs from
// katanaFile and gauFile using the Smart URL Engine.
func Process(katanaFile, gauFile, outDir string) (*Results, error) {
	engine := urlengine.NewEngine()
	res, err := engine.Process(katanaFile, gauFile, outDir)
	if err != nil {
		return nil, err
	}

	return &Results{
		TotalMerged:    res.TotalRaw,
		Normalised:     res.TotalNormalized,
		Unique:         res.TotalUnique,
		API:            res.APIEndpoints,
		JavaScript:     res.JavaScriptURLs,
		Parameterised:  res.Parameterized,
		Interesting:    res.HighInterest + res.MediumInterest,
		TotalClusters:  res.TotalClusters,
		HighInterest:   res.HighInterest,
		MediumInterest: res.MediumInterest,
		LowInterest:    res.LowInterest,
		HighPriority:   res.HighPriority,
		MediumPriority: res.MediumPriority,
		LowPriority:    res.LowPriority,
	}, nil
}

// merge reads lines from both files and returns all non-empty lines.
func merge(files ...string) ([]string, error) {
	seen := map[string]struct{}{}
	var lines []string

	for _, path := range files {
		f, err := os.Open(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("failed to open %q: %w", path, err)
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 512*1024), 512*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			if _, dup := seen[line]; !dup {
				seen[line] = struct{}{}
				lines = append(lines, line)
			}
		}
		f.Close()
	}
	return lines, nil
}

// normaliseAll normalises a slice of URL strings.
func normaliseAll(urls []string) []string {
	result := make([]string, 0, len(urls))
	for _, raw := range urls {
		n := normaliseURL(raw)
		if n != "" {
			result = append(result, n)
		}
	}
	return result
}

// normaliseURL performs URL normalisation:
//   - trims whitespace
//   - ensures scheme is present
//   - lowercases scheme and host
//   - preserves path, query parameters, and fragment
func normaliseURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	// Add scheme if missing so url.Parse works correctly.
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}

	if u.Host == "" {
		return ""
	}

	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)

	return u.String()
}

// deduplicate removes duplicate URLs deterministically.
func deduplicate(urls []string) []string {
	seen := make(map[string]struct{}, len(urls))
	result := make([]string, 0, len(urls))
	for _, u := range urls {
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			result = append(result, u)
		}
	}
	return result
}

// classify categorises URLs and writes category files to outDir.
func classify(urls []string, outDir string) (map[string]int, error) {
	categories := map[string][]string{
		"api":           {},
		"javascript":    {},
		"parameterized": {},
		"interesting":   {},
	}

	for _, u := range urls {
		lower := strings.ToLower(u)

		if isAPIURL(lower) {
			categories["api"] = append(categories["api"], u)
		}
		if isJavaScriptURL(lower) {
			categories["javascript"] = append(categories["javascript"], u)
		}
		if isParameterised(u) {
			categories["parameterized"] = append(categories["parameterized"], u)
		}
		if isInteresting(lower) {
			categories["interesting"] = append(categories["interesting"], u)
		}
	}

	files := map[string]string{
		"api":           "api-urls.txt",
		"javascript":    "javascript-urls.txt",
		"parameterized": "parameterized-urls.txt",
		"interesting":   "interesting-urls.txt",
	}

	counts := make(map[string]int)
	for cat, outFile := range files {
		path := filepath.Join(outDir, outFile)
		if err := writeLines(path, categories[cat]); err != nil {
			return nil, err
		}
		counts[cat] = len(categories[cat])
	}

	return counts, nil
}

// isAPIURL returns true if the URL looks like an API endpoint.
func isAPIURL(lower string) bool {
	apiIndicators := []string{
		"/api/", "/api?", "/v1/", "/v2/", "/v3/", "/graphql",
		"/rest/", "/json", ".json", "/rpc", "/endpoint",
	}
	for _, ind := range apiIndicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

// isJavaScriptURL returns true if the URL points to a JavaScript file.
func isJavaScriptURL(lower string) bool {
	return strings.HasSuffix(lower, ".js") ||
		strings.Contains(lower, ".js?") ||
		strings.Contains(lower, "/js/") ||
		strings.Contains(lower, "/javascript/") ||
		strings.Contains(lower, "/scripts/")
}

// isParameterised returns true if the URL contains query parameters.
func isParameterised(u string) bool {
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}
	return parsed.RawQuery != ""
}

// isInteresting returns true if the URL contains interesting reconnaissance targets.
func isInteresting(lower string) bool {
	interesting := []string{
		"/admin", "/login", "/signin", "/signup", "/register",
		"/upload", "/file", "/backup", "/.git", "/.env",
		"/config", "/debug", "/test", "/dev", "/staging",
		"/internal", "/private", "/secret", "/token",
		"/redirect", "/forward", "/proxy", "/ssrf",
		"/xml", "/soap", "/wsdl", "/swagger", "/openapi",
		"password", "passwd", "credential", "apikey", "api_key",
	}
	for _, ind := range interesting {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

// writeLines writes a slice of strings to a file, one per line.
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

// CountLines returns the number of non-empty lines in a file.
func CountLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	n := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 512*1024), 512*1024)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			n++
		}
	}
	return n
}
