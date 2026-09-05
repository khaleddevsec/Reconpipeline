// Package gf provides subdomain takeover intelligence matching CNAME targets and service fingerprints.
package gf

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/frozeniceee/Reconpipeline/internal/intelligence/dns"
	"github.com/frozeniceee/Reconpipeline/internal/tools/httpx"
)

// TakeoverSignature defines fingerprint characteristics for potentially vulnerable third-party services.
type TakeoverSignature struct {
	Service      string
	CNAMERegex   *regexp.Regexp
	Fingerprint  string
	StatusChecks []int
}

// Known takeover service signatures based on established takeover knowledgebases.
var takeoverSignatures = []TakeoverSignature{
	{
		Service:      "GitHub Pages",
		CNAMERegex:   regexp.MustCompile(`(?i)(github\.io|github\.map\.fastly\.net)`),
		Fingerprint:  "There isn't a GitHub Pages site here",
		StatusChecks: []int{404},
	},
	{
		Service:      "AWS S3 Bucket",
		CNAMERegex:   regexp.MustCompile(`(?i)(s3\.amazonaws\.com|\.s3-[a-z0-9-]+\.amazonaws\.com|s3-website)`),
		Fingerprint:  "NoSuchBucket",
		StatusChecks: []int{404},
	},
	{
		Service:      "Heroku",
		CNAMERegex:   regexp.MustCompile(`(?i)(herokudns\.com|herokuapp\.com|herokussl\.com)`),
		Fingerprint:  "No such app",
		StatusChecks: []int{404, 503},
	},
	{
		Service:      "Microsoft Azure",
		CNAMERegex:   regexp.MustCompile(`(?i)(azurewebsites\.net|cloudapp\.net|trafficmanager\.net|blob\.core\.windows\.net)`),
		Fingerprint:  "Web App - Unavailable",
		StatusChecks: []int{404, 503},
	},
	{
		Service:      "CloudFront",
		CNAMERegex:   regexp.MustCompile(`(?i)cloudfront\.net`),
		Fingerprint:  "Bad Request: CloudFront distribution does not exist",
		StatusChecks: []int{403, 404},
	},
	{
		Service:      "Shopify",
		CNAMERegex:   regexp.MustCompile(`(?i)myshopify\.com`),
		Fingerprint:  "Sorry, this shop is currently unavailable",
		StatusChecks: []int{404},
	},
	{
		Service:      "Fastly",
		CNAMERegex:   regexp.MustCompile(`(?i)fastly\.net`),
		Fingerprint:  "Fastly error: unknown domain",
		StatusChecks: []int{404, 500},
	},
	{
		Service:      "Surge.sh",
		CNAMERegex:   regexp.MustCompile(`(?i)surge\.sh`),
		Fingerprint:  "project not found",
		StatusChecks: []int{404},
	},
	{
		Service:      "Bitbucket",
		CNAMERegex:   regexp.MustCompile(`(?i)bitbucket\.io`),
		Fingerprint:  "Repository not found",
		StatusChecks: []int{404},
	},
	{
		Service:      "Ghost",
		CNAMERegex:   regexp.MustCompile(`(?i)ghost\.io`),
		Fingerprint:  "The thing you were looking for is no longer here",
		StatusChecks: []int{404},
	},
	{
		Service:      "Pantheon",
		CNAMERegex:   regexp.MustCompile(`(?i)pantheonsite\.io`),
		Fingerprint:  "The gods are wise, but do not know of the site which you seek",
		StatusChecks: []int{404},
	},
	{
		Service:      "Tumblr",
		CNAMERegex:   regexp.MustCompile(`(?i)domains\.tumblr\.com`),
		Fingerprint:  "Whatever you were looking for doesn't seem to exist",
		StatusChecks: []int{404},
	},
	{
		Service:      "WordPress",
		CNAMERegex:   regexp.MustCompile(`(?i)wordpress\.com`),
		Fingerprint:  "Do you want to register",
		StatusChecks: []int{404},
	},
	{
		Service:      "Zendesk",
		CNAMERegex:   regexp.MustCompile(`(?i)zendesk\.com`),
		Fingerprint:  "Help Center Closed",
		StatusChecks: []int{404},
	},
	{
		Service:      "Unbounce",
		CNAMERegex:   regexp.MustCompile(`(?i)unbouncepages\.com`),
		Fingerprint:  "The requested URL was not found",
		StatusChecks: []int{404},
	},
	{
		Service:      "Readme.io",
		CNAMERegex:   regexp.MustCompile(`(?i)readme\.io`),
		Fingerprint:  "Project doesnt exist",
		StatusChecks: []int{404},
	},
}

// EvaluateTakeover evaluates whether a subdomain with a given CNAME and HTTP response is a takeover candidate.
func EvaluateTakeover(subdomain, cname string, statusCode int, title, server, responseEvidence string) (TakeoverCandidate, bool) {
	if cname == "" {
		return TakeoverCandidate{}, false
	}

	cleanedCNAME := strings.TrimSuffix(strings.ToLower(cname), ".")
	evidenceCombined := strings.ToLower(fmt.Sprintf("%s %s %s", title, server, responseEvidence))

	for _, sig := range takeoverSignatures {
		if !sig.CNAMERegex.MatchString(cleanedCNAME) {
			continue
		}

		// Check for fingerprint match in response
		hasFingerprint := strings.Contains(strings.ToLower(evidenceCombined), strings.ToLower(sig.Fingerprint))

		// Check status code
		statusMatch := false
		for _, sc := range sig.StatusChecks {
			if sc == statusCode {
				statusMatch = true
				break
			}
		}

		var conf ConfidenceLevel
		var evidence string

		if hasFingerprint {
			conf = ConfidenceHigh
			evidence = fmt.Sprintf("CNAME %s matches %s, and response contains exact signature '%s' (HTTP %d)",
				cleanedCNAME, sig.Service, sig.Fingerprint, statusCode)
		} else if statusMatch || statusCode == 404 || statusCode == 503 {
			conf = ConfidenceMedium
			evidence = fmt.Sprintf("CNAME %s matches %s with HTTP %d error state, but fingerprint was unverified",
				cleanedCNAME, sig.Service, statusCode)
		} else {
			conf = ConfidenceLow
			evidence = fmt.Sprintf("CNAME %s points to %s (HTTP %d)", cleanedCNAME, sig.Service, statusCode)
		}

		return TakeoverCandidate{
			Subdomain:   subdomain,
			CNAME:       cleanedCNAME,
			Service:     sig.Service,
			Fingerprint: sig.Fingerprint,
			Confidence:  conf,
			StatusCode:  statusCode,
			Evidence:    evidence,
		}, true
	}

	return TakeoverCandidate{}, false
}

// RunTakeoverEngine processes DNS records and Host metadata to generate takeover candidates.
func RunTakeoverEngine(ctx context.Context, actx *AnalysisContext, outDir string) ([]TakeoverCandidate, error) {
	candidates := make([]TakeoverCandidate, 0)
	if actx == nil {
		return candidates, nil
	}

	// 1. Load DNS records if available
	dnsMap := make(map[string]string) // hostname -> cname
	if actx.DNSRecordsFile != "" {
		if data, err := os.ReadFile(actx.DNSRecordsFile); err == nil {
			var records []dns.Record
			if jsonErr := json.Unmarshal(data, &records); jsonErr == nil {
				for _, r := range records {
					if r.CNAME != "" {
						dnsMap[strings.ToLower(r.Hostname)] = r.CNAME
					}
				}
			}
		}
	}

	// 2. Load Stage 02 Host Metadata if available
	hostMetaMap := make(map[string]httpx.HostMeta)
	if actx.HTTPX1MetaFile != "" {
		if data, err := os.ReadFile(actx.HTTPX1MetaFile); err == nil {
			var metas []httpx.HostMeta
			if jsonErr := json.Unmarshal(data, &metas); jsonErr == nil {
				for _, m := range metas {
					cleanHost := strings.TrimPrefix(m.URL, "http://")
					cleanHost = strings.TrimPrefix(cleanHost, "https://")
					cleanHost = strings.TrimRight(cleanHost, "/")
					if idx := strings.Index(cleanHost, ":"); idx != -1 {
						cleanHost = cleanHost[:idx]
					}
					hostMetaMap[strings.ToLower(cleanHost)] = m
				}
			}
		}
	}

	// 3. Fallback: if DNS records file wasn't found, try parsing SubdomainsFile
	if len(dnsMap) == 0 && actx.SubdomainsFile != "" {
		if f, err := os.Open(actx.SubdomainsFile); err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				sub := strings.TrimSpace(scanner.Text())
				if sub != "" {
					dnsMap[strings.ToLower(sub)] = ""
				}
			}
		}
	}

	// 4. Evaluate all discovered hosts with CNAMEs
	seen := make(map[string]bool)
	for host, cname := range dnsMap {
		select {
		case <-ctx.Done():
			return candidates, ctx.Err()
		default:
		}

		if seen[host] {
			continue
		}

		meta, hasMeta := hostMetaMap[host]
		var statusCode int
		var title, server, evidence string
		if hasMeta {
			statusCode = meta.StatusCode
			title = meta.Title
			server = meta.Server
			evidence = meta.Technology
		}

		cand, matched := EvaluateTakeover(host, cname, statusCode, title, server, evidence)
		if matched {
			candidates = append(candidates, cand)
			seen[host] = true
		}
	}

	// Write takeover-candidates.json and takeover-candidates.txt
	patternsDir := filepath.Join(outDir, "patterns")
	_ = os.MkdirAll(patternsDir, 0750)
	_ = os.MkdirAll(outDir, 0750)

	jsonPath := filepath.Join(patternsDir, "takeover-candidates.json")
	if jsonData, err := json.MarshalIndent(candidates, "", "  "); err == nil {
		_ = os.WriteFile(jsonPath, jsonData, 0640)
	}

	txtPath := filepath.Join(outDir, "takeover-candidates.txt")
	var txtContent strings.Builder
	for _, c := range candidates {
		txtContent.WriteString(fmt.Sprintf("[%s] %s -> %s (%s) - %s\n", c.Confidence, c.Subdomain, c.CNAME, c.Service, c.Evidence))
	}
	_ = os.WriteFile(txtPath, []byte(txtContent.String()), 0640)

	return candidates, nil
}
