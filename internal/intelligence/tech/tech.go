// Package tech provides technology classification and grouping based on HTTPX metadata.
package tech

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/frozeniceee/Reconpipeline/internal/tools/httpx"
)

// TechGroup represents a technology grouping with associated host URLs.
type TechGroup struct {
	Technology string   `json:"technology"`
	Category   string   `json:"category"` // "web-server", "cms", "framework", "cdn-cloud", "language"
	Hosts      []string `json:"hosts"`
}

// Engine processes live host metadata to classify and group technologies.
type Engine struct{}

// NewEngine creates a new Technology Intelligence Engine.
func NewEngine() *Engine {
	return &Engine{}
}

// ProcessMetadata analyzes HTTPX metadata and writes technology-specific lists to techDir.
func (e *Engine) ProcessMetadata(metadataFile, techDir string) ([]TechGroup, error) {
	if err := os.MkdirAll(techDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create technologies directory: %w", err)
	}

	data, err := os.ReadFile(metadataFile)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata file: %w", err)
	}

	var metas []httpx.HostMeta
	if err := json.Unmarshal(data, &metas); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	techHosts := map[string]map[string]struct{}{
		"nginx":     {},
		"apache":    {},
		"wordpress": {},
		"nodejs":    {},
		"php":       {},
		"cdn":       {},
		"cloud":     {},
		"unknown":   {},
	}

	for _, m := range metas {
		matchedAny := false
		serverLower := strings.ToLower(m.Server)
		techLower := strings.ToLower(m.Technology)
		titleLower := strings.ToLower(m.Title)

		// 1. Nginx
		if strings.Contains(serverLower, "nginx") || strings.Contains(techLower, "nginx") {
			techHosts["nginx"][m.URL] = struct{}{}
			matchedAny = true
		}

		// 2. Apache
		if strings.Contains(serverLower, "apache") || strings.Contains(serverLower, "httpd") || strings.Contains(techLower, "apache") {
			techHosts["apache"][m.URL] = struct{}{}
			matchedAny = true
		}

		// 3. WordPress
		if strings.Contains(techLower, "wordpress") || strings.Contains(titleLower, "wordpress") {
			techHosts["wordpress"][m.URL] = struct{}{}
			matchedAny = true
		}

		// 4. Node.js
		if strings.Contains(serverLower, "express") || strings.Contains(techLower, "node.js") || strings.Contains(techLower, "express") || strings.Contains(techLower, "next.js") {
			techHosts["nodejs"][m.URL] = struct{}{}
			matchedAny = true
		}

		// 5. PHP
		if strings.Contains(serverLower, "php") || strings.Contains(techLower, "php") {
			techHosts["php"][m.URL] = struct{}{}
			matchedAny = true
		}

		// 6. CDN
		if strings.Contains(serverLower, "cloudflare") || strings.Contains(serverLower, "cloudfront") || strings.Contains(serverLower, "akamai") || strings.Contains(serverLower, "fastly") || strings.Contains(techLower, "cdn") {
			techHosts["cdn"][m.URL] = struct{}{}
			matchedAny = true
		}

		// 7. Cloud
		if strings.Contains(serverLower, "aws") || strings.Contains(serverLower, "amazon") || strings.Contains(serverLower, "gcp") || strings.Contains(serverLower, "azure") || strings.Contains(techLower, "amazon") {
			techHosts["cloud"][m.URL] = struct{}{}
			matchedAny = true
		}

		// Unknown if no known tech detected
		if !matchedAny {
			techHosts["unknown"][m.URL] = struct{}{}
		}
	}

	var groups []TechGroup
	for tech, hostsSet := range techHosts {
		var list []string
		for h := range hostsSet {
			list = append(list, h)
		}
		sort.Strings(list)

		groups = append(groups, TechGroup{
			Technology: tech,
			Category:   getCategory(tech),
			Hosts:      list,
		})

		// Write individual tech file
		filePath := filepath.Join(techDir, fmt.Sprintf("%s.txt", tech))
		_ = writeLines(filePath, list)
	}

	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Technology < groups[j].Technology
	})

	// Write technologies.json
	jsonData, _ := json.MarshalIndent(groups, "", "  ")
	_ = os.WriteFile(filepath.Join(techDir, "technologies.json"), jsonData, 0640)

	return groups, nil
}

func getCategory(tech string) string {
	switch tech {
	case "nginx", "apache":
		return "web-server"
	case "wordpress":
		return "cms"
	case "nodejs":
		return "runtime"
	case "php":
		return "language"
	case "cdn":
		return "cdn"
	case "cloud":
		return "cloud-infrastructure"
	default:
		return "unknown"
	}
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
