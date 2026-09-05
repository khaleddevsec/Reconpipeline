// Package gf implements the high-performance pattern intelligence analysis engine.
package gf

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/frozeniceee/Reconpipeline/internal/tools/httpx"
)

// Engine runs advanced pattern analysis and intelligence scoring.
type Engine struct {
	definitions []PatternDefinition
}

// NewEngine creates a new pattern intelligence engine with all loaded definitions.
func NewEngine() *Engine {
	return &Engine{
		definitions: GetAllDefinitions(),
	}
}

// EvaluateConfidence assigns a confidence level and analytical context to a match.
func (e *Engine) EvaluateConfidence(rawURL string, def *PatternDefinition, meta *httpx.URLMeta) (ConfidenceLevel, string) {
	switch def.Category {
	case CategoryVulnerability:
		switch def.Name {
		case "redirect":
			if meta != nil && meta.StatusCode >= 300 && meta.StatusCode < 400 && meta.Location != "" {
				return ConfidenceHigh, fmt.Sprintf("HTTP %d redirect with Location header '%s'", meta.StatusCode, meta.Location)
			}
			if strings.Contains(rawURL, "=http://") || strings.Contains(rawURL, "=https://") || strings.Contains(rawURL, "=//") {
				return ConfidenceHigh, "External absolute URL passed in redirect parameter"
			}
			if meta != nil && meta.StatusCode == 200 {
				return ConfidenceMedium, "Active HTTP 200 endpoint with redirect parameter"
			}
			return ConfidenceLow, "Redirect parameter candidate"

		case "rfi":
			if strings.Contains(rawURL, "://") {
				return ConfidenceHigh, "Remote URL scheme detected in file inclusion parameter"
			}
			return ConfidenceMedium, "File inclusion parameter candidate"

		case "traversal":
			if strings.Contains(rawURL, "../") || strings.Contains(rawURL, "..\\") || strings.Contains(rawURL, "%2e%2e") {
				return ConfidenceHigh, "Directory traversal sequence detected in URL path or parameters"
			}
			return ConfidenceMedium, "Traversal sequence candidate"

		case "lfi":
			if strings.Contains(rawURL, "../") || strings.Contains(rawURL, "..\\") || strings.Contains(rawURL, "/etc/") || strings.Contains(rawURL, "win.ini") {
				return ConfidenceHigh, "LFI path traversal pattern detected in parameter value"
			}
			if meta != nil && meta.StatusCode == 200 {
				return ConfidenceMedium, "Active HTTP 200 endpoint with file loading parameter"
			}
			return ConfidenceLow, "LFI parameter candidate"

		case "ssrf":
			if strings.Contains(rawURL, "=http://") || strings.Contains(rawURL, "=https://") || strings.Contains(rawURL, "=127.0.0.1") || strings.Contains(rawURL, "=169.254.") {
				return ConfidenceHigh, "Outbound URL or IP address in SSRF parameter value"
			}
			if meta != nil && meta.StatusCode == 200 {
				return ConfidenceMedium, "Active HTTP 200 endpoint with outbound request parameter"
			}
			return ConfidenceLow, "SSRF parameter candidate"

		case "xss":
			if meta != nil && strings.Contains(strings.ToLower(meta.ContentType), "application/json") {
				return ConfidenceLow, "JSON API response context (low reflection likelihood)"
			}
			if meta != nil && strings.Contains(strings.ToLower(meta.ContentType), "text/html") {
				return ConfidenceMedium, "HTML response context with user-controllable parameter"
			}
			if meta != nil && meta.StatusCode == 200 {
				return ConfidenceMedium, "Active HTTP 200 endpoint with XSS candidate parameter"
			}
			return ConfidenceLow, "XSS parameter candidate"

		case "sqli":
			if meta != nil && meta.StatusCode >= 500 {
				return ConfidenceMedium, fmt.Sprintf("Server error HTTP %d on database query parameter", meta.StatusCode)
			}
			if meta != nil && meta.StatusCode == 200 {
				return ConfidenceMedium, "Active database query parameter on live endpoint"
			}
			return ConfidenceLow, "SQL parameter candidate"

		default:
			if meta != nil && meta.StatusCode == 200 {
				return ConfidenceMedium, "Active parameter candidate"
			}
			return ConfidenceLow, "Parameter candidate"
		}

	case CategoryAPI:
		if meta != nil && strings.Contains(strings.ToLower(meta.ContentType), "application/json") {
			return ConfidenceHigh, "Verified JSON API endpoint"
		}
		if def.Name == "api-swagger" {
			return ConfidenceHigh, "API documentation / schema console endpoint"
		}
		if meta != nil && meta.StatusCode == 200 {
			return ConfidenceHigh, "Active 200 OK API endpoint"
		}
		return ConfidenceMedium, "API route candidate"

	case CategoryAuth:
		if meta != nil && (meta.StatusCode == 200 || (meta.StatusCode >= 300 && meta.StatusCode < 400)) {
			return ConfidenceHigh, fmt.Sprintf("Active authentication portal (HTTP %d)", meta.StatusCode)
		}
		return ConfidenceMedium, "Authentication flow endpoint"

	case CategoryAuthorization:
		if meta != nil && meta.StatusCode == 200 {
			return ConfidenceMedium, "Active direct object reference candidate (requires authorization check)"
		}
		return ConfidenceLow, "Direct object reference parameter candidate"

	case CategoryAdmin:
		if meta != nil && (meta.StatusCode == 200 || meta.StatusCode == 401 || meta.StatusCode == 403) {
			return ConfidenceHigh, fmt.Sprintf("Administrative console detected (HTTP %d)", meta.StatusCode)
		}
		return ConfidenceMedium, "Administrative route candidate"

	case CategoryDebug:
		if meta != nil && meta.StatusCode == 200 {
			return ConfidenceHigh, "Exposed debug or metric monitoring endpoint (HTTP 200)"
		}
		if meta != nil && (meta.StatusCode == 401 || meta.StatusCode == 403) {
			return ConfidenceMedium, fmt.Sprintf("Protected debug endpoint (HTTP %d)", meta.StatusCode)
		}
		return ConfidenceLow, "Debug route candidate"

	case CategorySensitiveFile:
		if meta != nil && meta.StatusCode == 200 {
			return ConfidenceHigh, "Sensitive file exposure confirmed live (HTTP 200)"
		}
		if meta != nil && (meta.StatusCode == 401 || meta.StatusCode == 403) {
			return ConfidenceMedium, fmt.Sprintf("Protected sensitive file path (HTTP %d)", meta.StatusCode)
		}
		return ConfidenceLow, "Sensitive file candidate"

	case CategoryBackup:
		if meta != nil && meta.StatusCode == 200 {
			return ConfidenceHigh, "Exposed backup archive or legacy file (HTTP 200)"
		}
		return ConfidenceMedium, "Backup or legacy artifact candidate"

	case CategorySecret:
		return ConfidenceHigh, "Potential secret or credential token parameter"

	case CategoryCloud:
		return ConfidenceHigh, "Cloud infrastructure asset indicator"

	case CategoryFileOps:
		if meta != nil && meta.StatusCode == 200 {
			return ConfidenceHigh, "Active file operation endpoint (HTTP 200)"
		}
		return ConfidenceMedium, "File operation candidate"

	default:
		return ConfidenceLow, "Pattern candidate"
	}
}

// LoadHTTPXMetadata loads Stage 06 URL verification metadata if available.
func LoadHTTPXMetadata(metaPath string) map[string]httpx.URLMeta {
	metaMap := make(map[string]httpx.URLMeta)
	if metaPath == "" {
		return metaMap
	}

	data, err := os.ReadFile(metaPath)
	if err != nil {
		return metaMap
	}

	var metas []httpx.URLMeta
	if err := json.Unmarshal(data, &metas); err == nil {
		for _, m := range metas {
			metaMap[m.URL] = m
			metaMap[strings.TrimRight(m.URL, "/")] = m
		}
	}

	return metaMap
}

// RunAnalysis performs the comprehensive pattern intelligence scan.
func (e *Engine) RunAnalysis(ctx context.Context, actx *AnalysisContext, urlsFile string, outDir string) (*IntelligenceSummary, map[string]int, error) {
	summary := &IntelligenceSummary{
		Target:             actx.TargetDomain,
		GeneratedAt:        time.Now().UTC().Format(time.RFC3339),
		ConfidenceCounts:   map[ConfidenceLevel]int{ConfidenceHigh: 0, ConfidenceMedium: 0, ConfidenceLow: 0},
		Categories:         make(map[string]CategorySummary),
		PatternCounts:      make(map[string]int),
		TakeoverCandidates: make([]TakeoverCandidate, 0),
		Disclaimer:         "Pattern matches indicate potential security candidates and areas of interest, not confirmed vulnerabilities.",
	}

	patternsDir := filepath.Join(outDir, "patterns")
	gfDir := filepath.Join(outDir, "gf")
	_ = os.MkdirAll(outDir, 0750)
	_ = os.MkdirAll(patternsDir, 0750)
	_ = os.MkdirAll(gfDir, 0750)

	// Load HTTPX metadata
	metaMap := LoadHTTPXMetadata(actx.HTTPX2MetaFile)

	// Read URLs
	inFile, err := os.Open(urlsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return summary, make(map[string]int), nil
		}
		return nil, nil, fmt.Errorf("failed to open URLs file: %w", err)
	}
	defer inFile.Close()

	var urls []string
	scanner := bufio.NewScanner(inFile)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		u := strings.TrimSpace(scanner.Text())
		if u != "" {
			urls = append(urls, u)
		}
	}

	// Prepare match collectors
	patternMatches := make(map[string][]CandidateMatch)
	patternURLs := make(map[string][]string)
	for _, def := range e.definitions {
		patternMatches[def.Name] = make([]CandidateMatch, 0)
		patternURLs[def.Name] = make([]string, 0)
	}

	allCandidateMatches := make([]CandidateMatch, 0)
	uniqueCandidateURLs := make(map[string]bool)

	// Match URLs
	for _, rawURL := range urls {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}

		isStatic := IsStaticNoise(rawURL)

		for _, def := range e.definitions {
			// Suppress static assets on query fuzzing candidates
			if isStatic && !def.IsPathPattern {
				continue
			}

			if def.Regex.MatchString(rawURL) {
				var meta *httpx.URLMeta
				if m, ok := metaMap[rawURL]; ok {
					meta = &m
				} else if m, ok := metaMap[strings.TrimRight(rawURL, "/")]; ok {
					meta = &m
				}

				conf, reasoning := e.EvaluateConfidence(rawURL, &def, meta)
				matchedParam := ExtractParamName(rawURL, &def)

				match := CandidateMatch{
					URL:           rawURL,
					Pattern:       def.Name,
					Category:      def.Category,
					Confidence:    conf,
					MatchedParam:  matchedParam,
					Context:       reasoning,
					SecurityFocus: def.SecurityFocus,
				}

				if meta != nil {
					match.StatusCode = meta.StatusCode
					match.ContentType = meta.ContentType
					match.Server = meta.Server
					match.ContentLength = meta.ContentLength
					match.Location = meta.Location
					match.Technologies = meta.Technologies
				}

				patternMatches[def.Name] = append(patternMatches[def.Name], match)
				patternURLs[def.Name] = append(patternURLs[def.Name], rawURL)
				allCandidateMatches = append(allCandidateMatches, match)
				uniqueCandidateURLs[rawURL] = true

				summary.ConfidenceCounts[conf]++
			}
		}
	}

	// 2. Run Subdomain Takeover Analysis
	takeovers, _ := RunTakeoverEngine(ctx, actx, outDir)
	summary.TakeoverCandidates = takeovers
	summary.TakeoverCount = len(takeovers)
	for _, t := range takeovers {
		summary.ConfidenceCounts[t.Confidence]++
	}

	// 3. Write individual pattern .txt files and compute category metrics
	counts := make(map[string]int)
	for _, def := range e.definitions {
		uList := patternURLs[def.Name]
		counts[def.Name] = len(uList)
		summary.PatternCounts[def.Name] = len(uList)

		// Aggregate into category summary
		catKey := string(def.Category)
		catSum := summary.Categories[catKey]
		catSum.Category = def.Category
		catSum.TotalMatches += len(uList)
		for _, m := range patternMatches[def.Name] {
			switch m.Confidence {
			case ConfidenceHigh:
				catSum.HighConfidence++
			case ConfidenceMedium:
				catSum.MediumConfidence++
			case ConfidenceLow:
				catSum.LowConfidence++
			}
		}
		summary.Categories[catKey] = catSum

		// Write to main output dir
		outFile := filepath.Join(outDir, def.OutFile)
		_ = writeLines(outFile, uList)

		// Also copy to gf/ directory
		gfOutFile := filepath.Join(gfDir, def.OutFile)
		_ = writeLines(gfOutFile, uList)
	}

	// Add Takeover category to categories summary
	if len(takeovers) > 0 {
		tKey := string(CategoryTakeover)
		tSum := CategorySummary{
			Category:     CategoryTakeover,
			TotalMatches: len(takeovers),
		}
		for _, t := range takeovers {
			switch t.Confidence {
			case ConfidenceHigh:
				tSum.HighConfidence++
			case ConfidenceMedium:
				tSum.MediumConfidence++
			case ConfidenceLow:
				tSum.LowConfidence++
			}
		}
		summary.Categories[tKey] = tSum
	}

	// Legacy 5 compatibility counts
	summary.XSS = counts["xss"]
	summary.SQLi = counts["sqli"]
	summary.LFI = counts["lfi"]
	summary.SSRF = counts["ssrf"]
	summary.Redirect = counts["redirect"]

	summary.TotalCandidateURLs = len(uniqueCandidateURLs)
	summary.TotalMatches = len(allCandidateMatches) + len(takeovers)

	// Write structured JSON outputs
	resultsPath := filepath.Join(patternsDir, "pattern-results.json")
	if rData, err := json.MarshalIndent(allCandidateMatches, "", "  "); err == nil {
		_ = os.WriteFile(resultsPath, rData, 0640)
	}

	summaryPath := filepath.Join(patternsDir, "pattern-summary.json")
	if sData, err := json.MarshalIndent(summary, "", "  "); err == nil {
		_ = os.WriteFile(summaryPath, sData, 0640)
	}

	// Write other-patterns.txt summary index of additional candidates
	otherPath := filepath.Join(outDir, "other-patterns.txt")
	writeOtherPatternsIndex(otherPath, summary)

	return summary, counts, nil
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

func writeOtherPatternsIndex(path string, s *IntelligenceSummary) {
	var sb strings.Builder
	sb.WriteString("# Reconpipeline Pattern Intelligence Index\n")
	sb.WriteString(fmt.Sprintf("# Total Candidates: %d across %d categories\n\n", s.TotalMatches, len(s.Categories)))

	// Sort category names
	var catNames []string
	for name := range s.Categories {
		catNames = append(catNames, name)
	}
	sort.Strings(catNames)

	for _, catName := range catNames {
		cat := s.Categories[catName]
		sb.WriteString(fmt.Sprintf("[%s] Total: %d (HIGH: %d, MED: %d, LOW: %d)\n",
			cat.Category, cat.TotalMatches, cat.HighConfidence, cat.MediumConfidence, cat.LowConfidence))
	}

	sb.WriteString("\n# Subdomain Takeover Candidates\n")
	if len(s.TakeoverCandidates) == 0 {
		sb.WriteString("None detected.\n")
	} else {
		for _, t := range s.TakeoverCandidates {
			sb.WriteString(fmt.Sprintf("- [%s] %s -> %s (%s)\n", t.Confidence, t.Subdomain, t.CNAME, t.Service))
		}
	}

	_ = os.WriteFile(path, []byte(sb.String()), 0640)
}
