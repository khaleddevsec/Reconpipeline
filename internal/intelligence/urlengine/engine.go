// Package urlengine implements the V2.0 Smart URL Engine for Reconpipeline.
// It performs deep normalization, deduplication, URL clustering, API detection,
// JavaScript endpoint extraction, parameter categorization, interesting endpoint
// detection, and deterministic priority scoring.
package urlengine

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/khaleddevsec/Reconpipeline/internal/scope"
)

// PriorityLevel defines the scored priority of an endpoint.
type PriorityLevel string

const (
	PriorityHigh   PriorityLevel = "high"
	PriorityMedium PriorityLevel = "medium"
	PriorityLow    PriorityLevel = "low"
)

// URLPriority holds the prioritization assessment for a URL.
type URLPriority struct {
	URL      string        `json:"url"`
	Score    int           `json:"score"`
	Priority PriorityLevel `json:"priority"`
	Reasons  []string      `json:"reasons"`
}

// ClusterGroup represents an endpoint family pattern and matching URLs.
type ClusterGroup struct {
	Pattern   string   `json:"pattern"`
	Count     int      `json:"count"`
	SampleURL string   `json:"sample_url"`
	URLs      []string `json:"urls"`
}

// ParamClassification represents classified query parameters in a URL.
type ParamClassification struct {
	URL        string            `json:"url"`
	Parameters map[string]string `json:"parameters"` // param_name -> category
}

// JSAnalysis holds JavaScript URLs and safely extracted route/endpoint patterns.
type JSAnalysis struct {
	JSURL              string   `json:"js_url"`
	ExtractedEndpoints []string `json:"extracted_endpoints,omitempty"`
}

// Results holds all output counts and metadata produced by the Smart URL Engine.
type Results struct {
	TotalRaw        int `json:"total_raw"`
	TotalNormalized int `json:"total_normalized"`
	TotalUnique     int `json:"total_unique"`

	// Category counts
	APIEndpoints   int `json:"api_endpoints"`
	JavaScriptURLs int `json:"javascript_urls"`
	Parameterized  int `json:"parameterized"`
	TotalClusters  int `json:"total_clusters"`

	// Interest counts
	HighInterest   int `json:"high_interest"`
	MediumInterest int `json:"medium_interest"`
	LowInterest    int `json:"low_interest"`

	// Priority counts
	HighPriority   int `json:"high_priority"`
	MediumPriority int `json:"medium_priority"`
	LowPriority    int `json:"low_priority"`
}

// Engine is the V2.0 Smart URL Processing Engine.
type Engine struct{}

// NewEngine creates a new Smart URL Engine.
func NewEngine() *Engine {
	return &Engine{}
}

// Process reads katana and gau result files, executes the full intelligence pipeline,
// and writes organized structured folders into outDir.
func (e *Engine) Process(katanaFile, gauFile, outDir string) (*Results, error) {
	// Prepare all subdirectories
	subdirs := []string{
		"raw",
		"normalized",
		"deduplicated",
		"api",
		"javascript",
		"parameters",
		"clusters",
		"interesting",
		"priority",
	}
	for _, d := range subdirs {
		if err := os.MkdirAll(filepath.Join(outDir, d), 0750); err != nil {
			return nil, fmt.Errorf("failed to create directory %q: %w", d, err)
		}
	}

	// 1. Raw Merge & Storage
	rawURLs, err := mergeFiles(katanaFile, gauFile)
	if err != nil {
		return nil, fmt.Errorf("failed to merge raw URLs: %w", err)
	}
	_ = writeLines(filepath.Join(outDir, "raw", "all-urls.txt"), rawURLs)
	// Backward compatible path:
	_ = writeLines(filepath.Join(outDir, "all-urls.txt"), rawURLs)

	// 2. Deep Normalization
	normalizedMap := make(map[string]string) // normalized -> original
	var normalizedURLs []string
	for _, raw := range rawURLs {
		norm := NormalizeURL(raw)
		if norm != "" {
			normalizedURLs = append(normalizedURLs, norm)
			if _, exists := normalizedMap[norm]; !exists {
				normalizedMap[norm] = raw
			}
		}
	}
	_ = writeLines(filepath.Join(outDir, "normalized", "normalized-urls.txt"), normalizedURLs)
	// Backward compatible path:
	_ = writeLines(filepath.Join(outDir, "normalized-urls.txt"), normalizedURLs)

	// 3. Deterministic Deduplication
	uniqueURLs := deduplicateSlice(normalizedURLs)
	sort.Strings(uniqueURLs)
	_ = writeLines(filepath.Join(outDir, "deduplicated", "unique-urls.txt"), uniqueURLs)
	// Backward compatible path:
	_ = writeLines(filepath.Join(outDir, "unique-urls.txt"), uniqueURLs)

	// 4. URL Clustering (Endpoint Families)
	clusters, clusterPatterns := ClusterURLs(uniqueURLs)
	clusterJSON, _ := json.MarshalIndent(clusters, "", "  ")
	_ = os.WriteFile(filepath.Join(outDir, "clusters", "endpoint-clusters.json"), clusterJSON, 0640)
	_ = writeLines(filepath.Join(outDir, "clusters", "clustered-patterns.txt"), clusterPatterns)

	// 5. API Endpoint Detection
	apiURLs, apiPatterns := ClassifyAPI(uniqueURLs)
	_ = writeLines(filepath.Join(outDir, "api", "api-urls.txt"), apiURLs)
	_ = writeLines(filepath.Join(outDir, "api-urls.txt"), apiURLs)
	apiJSON, _ := json.MarshalIndent(apiPatterns, "", "  ")
	_ = os.WriteFile(filepath.Join(outDir, "api", "api-patterns.json"), apiJSON, 0640)

	// 6. JavaScript Intelligence
	jsURLs, jsAnalyses, extractedEndpoints := AnalyzeJavaScriptURLs(uniqueURLs)
	_ = writeLines(filepath.Join(outDir, "javascript", "javascript-urls.txt"), jsURLs)
	_ = writeLines(filepath.Join(outDir, "javascript-urls.txt"), jsURLs)
	_ = writeLines(filepath.Join(outDir, "javascript", "extracted-endpoints.txt"), extractedEndpoints)
	jsJSON, _ := json.MarshalIndent(jsAnalyses, "", "  ")
	_ = os.WriteFile(filepath.Join(outDir, "javascript", "javascript-analysis.json"), jsJSON, 0640)

	// 7. Parameter Intelligence
	paramURLs, paramAnalyses := AnalyzeParameters(uniqueURLs)
	_ = writeLines(filepath.Join(outDir, "parameters", "parameterized-urls.txt"), paramURLs)
	_ = writeLines(filepath.Join(outDir, "parameterized-urls.txt"), paramURLs)
	paramJSON, _ := json.MarshalIndent(paramAnalyses, "", "  ")
	_ = os.WriteFile(filepath.Join(outDir, "parameters", "parameter-analysis.json"), paramJSON, 0640)

	// 8. Interesting Endpoint Detection
	highInterest, medInterest, lowInterest := ClassifyInterest(uniqueURLs)
	_ = writeLines(filepath.Join(outDir, "interesting", "high-interest.txt"), highInterest)
	_ = writeLines(filepath.Join(outDir, "interesting", "medium-interest.txt"), medInterest)
	_ = writeLines(filepath.Join(outDir, "interesting", "low-interest.txt"), lowInterest)
	var allInteresting []string
	allInteresting = append(allInteresting, highInterest...)
	allInteresting = append(allInteresting, medInterest...)
	_ = writeLines(filepath.Join(outDir, "interesting", "interesting-urls.txt"), allInteresting)
	_ = writeLines(filepath.Join(outDir, "interesting-urls.txt"), allInteresting)

	// 9. Smart Prioritization
	priorities, highPrio, medPrio, lowPrio := PrioritizeURLs(uniqueURLs)
	_ = writeLines(filepath.Join(outDir, "priority", "high-priority.txt"), highPrio)
	_ = writeLines(filepath.Join(outDir, "priority", "medium-priority.txt"), medPrio)
	_ = writeLines(filepath.Join(outDir, "priority", "low-priority.txt"), lowPrio)
	prioJSON, _ := json.MarshalIndent(priorities, "", "  ")
	_ = os.WriteFile(filepath.Join(outDir, "priority", "priority-scores.json"), prioJSON, 0640)

	return &Results{
		TotalRaw:        len(rawURLs),
		TotalNormalized: len(normalizedURLs),
		TotalUnique:     len(uniqueURLs),
		APIEndpoints:    len(apiURLs),
		JavaScriptURLs:  len(jsURLs),
		Parameterized:   len(paramURLs),
		TotalClusters:   len(clusters),
		HighInterest:    len(highInterest),
		MediumInterest:  len(medInterest),
		LowInterest:     len(lowInterest),
		HighPriority:    len(highPrio),
		MediumPriority:  len(medPrio),
		LowPriority:     len(lowPrio),
	}, nil
}

// NormalizeURL performs consistent, deterministic URL normalization without altering semantics:
// - trims whitespace
// - strips URL fragments (#...)
// - lowercases scheme and host
// - removes default ports (:80, :443)
// - sorts query parameters alphabetically by key
// - standardizes path separators
func NormalizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	// Remove fragment
	if idx := strings.IndexByte(raw, '#'); idx != -1 {
		raw = raw[:idx]
	}

	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}

	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)

	// Remove standard default ports
	if u.Scheme == "http" && strings.HasSuffix(u.Host, ":80") {
		u.Host = strings.TrimSuffix(u.Host, ":80")
	} else if u.Scheme == "https" && strings.HasSuffix(u.Host, ":443") {
		u.Host = strings.TrimSuffix(u.Host, ":443")
	}

	// Clean path
	path := u.Path
	if path == "" {
		path = "/"
	} else if len(path) > 1 && strings.HasSuffix(path, "/") {
		path = strings.TrimSuffix(path, "/")
	}
	u.Path = path

	// Normalize query parameter ordering
	if u.RawQuery != "" {
		q := u.Query()
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		var queryParts []string
		for _, k := range keys {
			vals := q[k]
			for _, v := range vals {
				queryParts = append(queryParts, fmt.Sprintf("%s=%s", url.QueryEscape(k), url.QueryEscape(v)))
			}
		}
		u.RawQuery = strings.Join(queryParts, "&")
	}

	return u.String()
}

var (
	numRE  = regexp.MustCompile(`^\d+$`)
	uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hashRE = regexp.MustCompile(`^[0-9a-fA-F]{32,64}$`)
	dateRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$|^\d{4}/\d{2}/\d{2}$`)
)

// ClusterURLs groups endpoints into structural endpoint families (e.g. /api/user/{id}).
func ClusterURLs(urls []string) ([]ClusterGroup, []string) {
	clusterMap := make(map[string][]string)

	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}

		segments := strings.Split(strings.Trim(u.Path, "/"), "/")
		var clusteredSegments []string
		for _, seg := range segments {
			if seg == "" {
				continue
			}
			switch {
			case uuidRE.MatchString(seg):
				clusteredSegments = append(clusteredSegments, "{uuid}")
			case hashRE.MatchString(seg):
				clusteredSegments = append(clusteredSegments, "{hash}")
			case numRE.MatchString(seg):
				clusteredSegments = append(clusteredSegments, "{id}")
			case dateRE.MatchString(seg):
				clusteredSegments = append(clusteredSegments, "{date}")
			default:
				clusteredSegments = append(clusteredSegments, seg)
			}
		}

		patternPath := "/" + strings.Join(clusteredSegments, "/")
		pattern := fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, patternPath)
		clusterMap[pattern] = append(clusterMap[pattern], raw)
	}

	var groups []ClusterGroup
	var patternList []string

	for pattern, matchedURLs := range clusterMap {
		patternList = append(patternList, pattern)
		sample := ""
		if len(matchedURLs) > 0 {
			sample = matchedURLs[0]
		}
		groups = append(groups, ClusterGroup{
			Pattern:   pattern,
			Count:     len(matchedURLs),
			SampleURL: sample,
			URLs:      matchedURLs,
		})
	}

	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Count != groups[j].Count {
			return groups[i].Count > groups[j].Count
		}
		return groups[i].Pattern < groups[j].Pattern
	})
	sort.Strings(patternList)

	return groups, patternList
}

// ClassifyAPI detects API endpoints using safe heuristics.
func ClassifyAPI(urls []string) ([]string, []string) {
	var apiURLs []string
	patternSet := make(map[string]struct{})

	apiIndicators := []string{
		"/api/", "/api?", "/v1/", "/v2/", "/v3/", "/v4/",
		"/graphql", "/rest/", "/json", ".json", "/rpc", "/endpoint",
		"/swagger", "/openapi", "/service/", "/gateway/",
	}

	for _, u := range urls {
		lower := strings.ToLower(u)
		for _, ind := range apiIndicators {
			if strings.Contains(lower, ind) {
				apiURLs = append(apiURLs, u)
				patternSet[ind] = struct{}{}
				break
			}
		}
	}

	var patterns []string
	for p := range patternSet {
		patterns = append(patterns, p)
	}
	sort.Strings(patterns)
	sort.Strings(apiURLs)

	return apiURLs, patterns
}

// AnalyzeJavaScriptURLs identifies JS files and safely extracts route/endpoint patterns.
func AnalyzeJavaScriptURLs(urls []string) ([]string, []JSAnalysis, []string) {
	var jsURLs []string
	var analyses []JSAnalysis
	endpointSet := make(map[string]struct{})

	for _, u := range urls {
		lower := strings.ToLower(u)
		if isJS(lower) {
			jsURLs = append(jsURLs, u)

			// Heuristic extracted routes from file naming (e.g. app-dashboard.js -> /dashboard)
			parsed, err := url.Parse(u)
			var extracted []string
			if err == nil {
				filename := filepath.Base(parsed.Path)
				base := strings.TrimSuffix(filename, filepath.Ext(filename))
				parts := strings.Split(base, "-")
				for _, part := range parts {
					if len(part) >= 4 && !numRE.MatchString(part) && !hashRE.MatchString(part) {
						route := "/" + strings.ToLower(part)
						extracted = append(extracted, route)
						endpointSet[route] = struct{}{}
					}
				}
			}

			analyses = append(analyses, JSAnalysis{
				JSURL:              u,
				ExtractedEndpoints: extracted,
			})
		}
	}

	var extractedList []string
	for ep := range endpointSet {
		extractedList = append(extractedList, ep)
	}
	sort.Strings(extractedList)
	sort.Strings(jsURLs)

	return jsURLs, analyses, extractedList
}

func isJS(lower string) bool {
	return strings.HasSuffix(lower, ".js") ||
		strings.Contains(lower, ".js?") ||
		strings.Contains(lower, "/js/") ||
		strings.Contains(lower, "/javascript/") ||
		strings.Contains(lower, "/scripts/")
}

// AnalyzeParameters classifies query parameters into functional reconnaissance categories.
func AnalyzeParameters(urls []string) ([]string, []ParamClassification) {
	var paramURLs []string
	var analyses []ParamClassification

	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.RawQuery == "" {
			continue
		}

		paramURLs = append(paramURLs, raw)
		paramMap := make(map[string]string)

		for key := range u.Query() {
			paramMap[key] = classifyParamKey(key)
		}

		analyses = append(analyses, ParamClassification{
			URL:        raw,
			Parameters: paramMap,
		})
	}

	sort.Strings(paramURLs)
	return paramURLs, analyses
}

func classifyParamKey(k string) string {
	lower := strings.ToLower(k)
	switch {
	case containsAny(lower, "id", "uid", "user_id", "account_id", "item_id", "doc_id", "uuid", "num", "no"):
		return "identifier"
	case containsAny(lower, "url", "uri", "dest", "destination", "host", "domain", "callback", "return_to", "endpoint", "feed", "site"):
		return "url"
	case containsAny(lower, "file", "doc", "path", "template", "page", "include", "dir", "load", "folder", "root"):
		return "file_path"
	case containsAny(lower, "redirect", "next", "return", "checkout_url", "goto", "forward", "target"):
		return "redirect"
	case containsAny(lower, "q", "s", "search", "query", "keyword", "filter", "find", "term"):
		return "search"
	case containsAny(lower, "page", "p", "offset", "limit", "size", "count", "start", "per_page"):
		return "pagination"
	case containsAny(lower, "token", "auth", "key", "apikey", "secret", "jwt", "access_token", "pass", "pwd", "hash"):
		return "auth_token"
	default:
		return "unknown"
	}
}

// ClassifyInterest groups URLs into high, medium, and low interest.
func ClassifyInterest(urls []string) (high []string, med []string, low []string) {
	highIndicators := []string{
		"/admin", "/login", "/signin", "/signup", "/auth", "/dashboard",
		"/upload", "/backup", "/.git", "/.env", "/config", "/secret",
		"/token", "/graphql", "/swagger", "/openapi", "/portal", "/internal",
		"/passwd", "/credentials", "/api-keys",
	}

	medIndicators := []string{
		"/api/", "/v1/", "/v2/", "/v3/", "/dev", "/staging", "/test",
		"/user", "/users", "/account", "/accounts", "/search", "/query",
		"/download", "/profile", "/order", "/orders",
	}

	for _, u := range urls {
		lower := strings.ToLower(u)
		isHigh := false
		for _, hi := range highIndicators {
			if strings.Contains(lower, hi) {
				high = append(high, u)
				isHigh = true
				break
			}
		}
		if isHigh {
			continue
		}

		isMed := false
		for _, mi := range medIndicators {
			if strings.Contains(lower, mi) {
				med = append(med, u)
				isMed = true
				break
			}
		}
		if isMed {
			continue
		}

		low = append(low, u)
	}

	sort.Strings(high)
	sort.Strings(med)
	sort.Strings(low)

	return high, med, low
}

// IsStaticAsset returns true if the URL points to a low-value static asset (image, font, css, media, archive).
func IsStaticAsset(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	// If query parameters exist, don't blindly treat as purely static
	if u.RawQuery != "" {
		return false
	}
	path := strings.ToLower(u.Path)
	ext := filepath.Ext(path)
	if ext == "" {
		return false
	}
	staticExts := map[string]struct{}{
		".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".ico": {}, ".svg": {}, ".bmp": {}, ".webp": {}, ".tiff": {}, ".tif": {},
		".css": {}, ".less": {}, ".scss": {},
		".woff": {}, ".woff2": {}, ".ttf": {}, ".eot": {}, ".otf": {},
		".mp4": {}, ".mp3": {}, ".wav": {}, ".ogg": {}, ".avi": {}, ".mov": {}, ".wmv": {}, ".flv": {}, ".m4a": {}, ".m4v": {},
		".pdf": {}, ".zip": {}, ".tar": {}, ".gz": {}, ".rar": {}, ".7z": {}, ".iso": {}, ".exe": {}, ".bin": {},
	}
	_, isStatic := staticExts[ext]
	return isStatic
}

// SelectForVerification conservatively filters and prioritizes unique URLs for HTTPX #2 verification.
// It strictly validates target scope, filters out purely static resource noise, prioritizes high and medium
// interest security endpoints (APIs, parameters, login/admin, JSON, GraphQL, Swagger), and bounds output by maxURLs.
func SelectForVerification(uniqueURLs []string, target *scope.Target, maxURLs int) []string {
	var highList []string
	var medList []string
	var lowList []string

	for _, raw := range uniqueURLs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if target != nil && !scope.InScope(raw, target) {
			continue
		}
		if IsStaticAsset(raw) {
			continue
		}

		lower := strings.ToLower(raw)
		score := 0

		// 1. High Interest keywords
		if containsAny(lower, "/admin", "/login", "/signin", "/signup", "/auth", "/dashboard", "/upload", "/backup", "/.git", "/.env", "/config", "/secret", "/private", "/internal", "/token", "password", "passwd", "credential", "apikey", "api_key", "/graphql", "/swagger", "/openapi", "/api-docs") {
			score += 4
		}

		// 2. API keywords & JSON
		if containsAny(lower, "/api/", "/v1/", "/v2/", "/v3/", "/v4/", "/rest/", "/rpc/", "/json", ".json", "/gateway/", "/service/", "/endpoint") {
			score += 3
		}

		// 3. Parameters presence
		if strings.Contains(raw, "?") {
			score += 2
			if containsAny(lower, "redirect=", "url=", "dest=", "file=", "path=", "template=", "next=", "token=", "key=", "auth=", "secret=", "graphql=", "query=", "id=", "user=") {
				score += 3
			}
		}

		switch {
		case score >= 4:
			highList = append(highList, raw)
		case score >= 2:
			medList = append(medList, raw)
		default:
			// Normal HTML/application routes
			lowList = append(lowList, raw)
		}
	}

	sort.Strings(highList)
	sort.Strings(medList)
	sort.Strings(lowList)

	var selected []string
	if maxURLs <= 0 {
		selected = append(selected, highList...)
		selected = append(selected, medList...)
		selected = append(selected, lowList...)
		return deduplicateSlice(selected)
	}

	// Bounded selection prioritizing High > Med > Low
	var bounded []string
	bounded = append(bounded, highList...)
	if len(bounded) < maxURLs {
		remaining := maxURLs - len(bounded)
		if len(medList) <= remaining {
			bounded = append(bounded, medList...)
		} else {
			bounded = append(bounded, medList[:remaining]...)
		}
	}
	if len(bounded) < maxURLs {
		remaining := maxURLs - len(bounded)
		if len(lowList) <= remaining {
			bounded = append(bounded, lowList...)
		} else {
			bounded = append(bounded, lowList[:remaining]...)
		}
	}

	selected = deduplicateSlice(bounded)
	if len(selected) > maxURLs {
		selected = selected[:maxURLs]
	}
	return selected
}

// SelectForVerification method on Engine.
func (e *Engine) SelectForVerification(uniqueURLs []string, target *scope.Target, maxURLs int) []string {
	return SelectForVerification(uniqueURLs, target, maxURLs)
}

// PrioritizeURLs calculates a deterministic priority score and reasons for each URL.
func PrioritizeURLs(urls []string) (assessments []URLPriority, high []string, med []string, low []string) {
	for _, raw := range urls {
		score := 0
		var reasons []string
		lower := strings.ToLower(raw)

		// 1. High Interest keywords
		if containsAny(lower, "/admin", "/login", "/signin", "/signup", "/auth", "/dashboard", "/upload", "/backup", "/.git", "/.env", "/config", "/secret", "/private", "/internal", "/token", "password", "passwd", "credential", "apikey", "api_key", "/graphql", "/swagger", "/openapi", "/api-docs") {
			score += 4
			reasons = append(reasons, "matches high-interest security keyword")
		}

		// 2. API keywords
		if containsAny(lower, "/api/", "/v1/", "/v2/", "/v3/", "/v4/", "/rest/", "/rpc/", "/json", ".json", "/gateway/", "/service/", "/endpoint") {
			score += 3
			reasons = append(reasons, "API endpoint structure")
		}

		// 3. Parameters presence
		if strings.Contains(raw, "?") {
			score += 2
			reasons = append(reasons, "contains query parameters")

			// Check parameter names
			if containsAny(lower, "redirect=", "url=", "dest=", "file=", "path=", "template=", "next=") {
				score += 3
				reasons = append(reasons, "contains redirect or file path parameters")
			}
			if containsAny(lower, "token=", "key=", "apikey=", "auth=", "secret=") {
				score += 3
				reasons = append(reasons, "contains authentication/token parameters")
			}
		}

		// 4. Static asset penalty
		if containsAny(lower, ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".css", ".woff", ".woff2", ".ttf", ".eot") {
			score -= 3
			reasons = append(reasons, "static image/styling asset")
		}

		var level PriorityLevel
		switch {
		case score >= 4:
			level = PriorityHigh
			high = append(high, raw)
		case score >= 2:
			level = PriorityMedium
			med = append(med, raw)
		default:
			level = PriorityLow
			low = append(low, raw)
		}

		assessments = append(assessments, URLPriority{
			URL:      raw,
			Score:    score,
			Priority: level,
			Reasons:  reasons,
		})
	}

	sort.Strings(high)
	sort.Strings(med)
	sort.Strings(low)

	return assessments, high, med, low
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func deduplicateSlice(urls []string) []string {
	seen := make(map[string]struct{}, len(urls))
	var result []string
	for _, u := range urls {
		if _, exists := seen[u]; !exists {
			seen[u] = struct{}{}
			result = append(result, u)
		}
	}
	return result
}

func mergeFiles(files ...string) ([]string, error) {
	seen := make(map[string]struct{})
	var lines []string

	for _, path := range files {
		f, err := os.Open(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 512*1024), 512*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				if _, ok := seen[line]; !ok {
					seen[line] = struct{}{}
					lines = append(lines, line)
				}
			}
		}
		f.Close()
	}
	return lines, nil
}

func writeLines(path string, lines []string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	return w.Flush()
}
