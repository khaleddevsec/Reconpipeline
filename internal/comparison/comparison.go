// Package comparison implements the scan change detection and comparison engine.
package comparison

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/khaleddevsec/Reconpipeline/internal/history"
	"github.com/khaleddevsec/Reconpipeline/internal/tools/httpx"
)

// AssetChange represents a changed observation (status code, title, server) for a live host.
type AssetChange struct {
	URL       string `json:"url"`
	OldStatus int    `json:"old_status,omitempty"`
	NewStatus int    `json:"new_status,omitempty"`
	OldTitle  string `json:"old_title,omitempty"`
	NewTitle  string `json:"new_title,omitempty"`
	OldServer string `json:"old_server,omitempty"`
	NewServer string `json:"new_server,omitempty"`
}

// Result holds the detailed diff and change counts between two scans.
type Result struct {
	HasPrevious       bool          `json:"has_previous"`
	PreviousScanID    string        `json:"previous_scan_id,omitempty"`
	CurrentScanID     string        `json:"current_scan_id,omitempty"`
	PreviousTime      string        `json:"previous_time,omitempty"`
	CurrentTime       string        `json:"current_time,omitempty"`
	NewSubdomains     []string      `json:"new_subdomains,omitempty"`
	RemovedSubdomains []string      `json:"removed_subdomains,omitempty"`
	NewHosts          []string      `json:"new_hosts,omitempty"`
	RemovedHosts      []string      `json:"removed_hosts,omitempty"`
	NewURLs           []string      `json:"new_urls,omitempty"`
	RemovedURLs       []string      `json:"removed_urls,omitempty"`
	NewAPIs           []string      `json:"new_apis,omitempty"`
	NewJS             []string      `json:"new_js,omitempty"`
	ChangedAssets     []AssetChange `json:"changed_assets,omitempty"`
}

// Engine performs delta analysis between scan directories.
type Engine struct{}

// NewEngine creates a new Comparison Engine.
func NewEngine() *Engine {
	return &Engine{}
}

// CompareScans compares a previous scan directory with the current scan directory and writes
// comparison artifacts into targetDir/comparison.
func (e *Engine) CompareScans(prevScanDir, currScanDir, targetDir string, prevMeta, currMeta *history.ScanMeta) (*Result, error) {
	compDir := filepath.Join(targetDir, "comparison")
	if err := os.MkdirAll(compDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create comparison directory: %w", err)
	}

	if prevScanDir == "" || prevMeta == nil {
		// First scan ever: create clean "no previous scan" report
		res := &Result{
			HasPrevious:   false,
			CurrentScanID: currMeta.ScanID,
			CurrentTime:   history.FormatTime(currMeta.StartTime),
		}
		e.writeNoPreviousSummary(compDir, res)
		return res, nil
	}

	res := &Result{
		HasPrevious:    true,
		PreviousScanID: prevMeta.ScanID,
		CurrentScanID:  currMeta.ScanID,
		PreviousTime:   history.FormatTime(prevMeta.StartTime),
		CurrentTime:    history.FormatTime(currMeta.StartTime),
	}

	// 1. Subdomains diff
	prevSubs := readLines(filepath.Join(prevScanDir, "subdomains.txt"))
	currSubs := readLines(filepath.Join(currScanDir, "subdomains.txt"))
	res.NewSubdomains, res.RemovedSubdomains = diffLines(prevSubs, currSubs)

	// 2. Live Hosts diff
	prevHosts := readLines(filepath.Join(prevScanDir, "live-hosts.txt"))
	currHosts := readLines(filepath.Join(currScanDir, "live-hosts.txt"))
	res.NewHosts, res.RemovedHosts = diffLines(prevHosts, currHosts)

	// 3. Unique URLs diff
	prevURLs := readLines(filepath.Join(prevScanDir, "unique-urls.txt"))
	currURLs := readLines(filepath.Join(currScanDir, "unique-urls.txt"))
	res.NewURLs, res.RemovedURLs = diffLines(prevURLs, currURLs)

	// 4. API & JS diffs
	prevAPIs := readLines(filepath.Join(prevScanDir, "api-urls.txt"))
	currAPIs := readLines(filepath.Join(currScanDir, "api-urls.txt"))
	res.NewAPIs, _ = diffLines(prevAPIs, currAPIs)

	prevJS := readLines(filepath.Join(prevScanDir, "javascript-urls.txt"))
	currJS := readLines(filepath.Join(currScanDir, "javascript-urls.txt"))
	res.NewJS, _ = diffLines(prevJS, currJS)

	// 5. Host metadata changes
	prevMetaList := readHostMetadata(filepath.Join(prevScanDir, "hosts-metadata.json"))
	currMetaList := readHostMetadata(filepath.Join(currScanDir, "hosts-metadata.json"))
	if len(currMetaList) == 0 {
		currMetaList = readHostMetadata(filepath.Join(targetDir, "02-live-host-detection", "metadata.json"))
	}
	res.ChangedAssets = detectAssetChanges(prevMetaList, currMetaList)

	// Write comparison output files
	_ = writeLines(filepath.Join(compDir, "new-subdomains.txt"), res.NewSubdomains)
	_ = writeLines(filepath.Join(compDir, "removed-subdomains.txt"), res.RemovedSubdomains)
	_ = writeLines(filepath.Join(compDir, "new-hosts.txt"), res.NewHosts)
	_ = writeLines(filepath.Join(compDir, "removed-hosts.txt"), res.RemovedHosts)
	_ = writeLines(filepath.Join(compDir, "new-urls.txt"), res.NewURLs)
	_ = writeLines(filepath.Join(compDir, "removed-urls.txt"), res.RemovedURLs)

	changedJSON, _ := json.MarshalIndent(res.ChangedAssets, "", "  ")
	_ = os.WriteFile(filepath.Join(compDir, "changed-assets.json"), changedJSON, 0640)

	compJSON, _ := json.MarshalIndent(res, "", "  ")
	_ = os.WriteFile(filepath.Join(compDir, "comparison.json"), compJSON, 0640)

	compTxt := e.FormatTextSummary(res)
	_ = os.WriteFile(filepath.Join(compDir, "comparison.txt"), []byte(compTxt), 0640)

	return res, nil
}

func (e *Engine) writeNoPreviousSummary(compDir string, res *Result) {
	data, _ := json.MarshalIndent(res, "", "  ")
	_ = os.WriteFile(filepath.Join(compDir, "comparison.json"), data, 0640)

	txt := "Changes Since Previous Scan\n────────────────────────────────────────\nNo previous scan available for comparison.\n"
	_ = os.WriteFile(filepath.Join(compDir, "comparison.txt"), []byte(txt), 0640)
}

// FormatTextSummary returns a clean, human-readable comparison summary string.
func (e *Engine) FormatTextSummary(r *Result) string {
	if !r.HasPrevious {
		return "Changes Since Previous Scan\n────────────────────────────────────────\nNo previous scan available for comparison.\n"
	}

	var sb strings.Builder
	sb.WriteString("Changes Since Previous Scan\n")
	sb.WriteString("────────────────────────────────────────\n\n")
	sb.WriteString(fmt.Sprintf("Previous Scan : %s (%s)\n", r.PreviousScanID, r.PreviousTime))
	sb.WriteString(fmt.Sprintf("Current Scan  : %s (%s)\n\n", r.CurrentScanID, r.CurrentTime))

	sb.WriteString(fmt.Sprintf("New Subdomains     : %d\n", len(r.NewSubdomains)))
	sb.WriteString(fmt.Sprintf("Removed Subdomains : %d\n", len(r.RemovedSubdomains)))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("New Live Hosts     : %d\n", len(r.NewHosts)))
	sb.WriteString(fmt.Sprintf("Removed Live Hosts : %d\n", len(r.RemovedHosts)))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("New URLs           : %d\n", len(r.NewURLs)))
	sb.WriteString(fmt.Sprintf("Removed URLs       : %d\n", len(r.RemovedURLs)))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("New API Endpoints  : %d\n", len(r.NewAPIs)))
	sb.WriteString(fmt.Sprintf("New JS Endpoints   : %d\n", len(r.NewJS)))
	sb.WriteString(fmt.Sprintf("Asset Metadata Chg : %d\n", len(r.ChangedAssets)))

	if len(r.ChangedAssets) > 0 {
		sb.WriteString("\nObserved Asset Changes:\n")
		for _, ca := range r.ChangedAssets {
			var details []string
			if ca.OldStatus != ca.NewStatus && ca.OldStatus != 0 && ca.NewStatus != 0 {
				details = append(details, fmt.Sprintf("status: %d -> %d", ca.OldStatus, ca.NewStatus))
			}
			if ca.OldTitle != ca.NewTitle && ca.OldTitle != "" && ca.NewTitle != "" {
				details = append(details, fmt.Sprintf("title: %q -> %q", ca.OldTitle, ca.NewTitle))
			}
			if ca.OldServer != ca.NewServer && ca.OldServer != "" && ca.NewServer != "" {
				details = append(details, fmt.Sprintf("server: %q -> %q", ca.OldServer, ca.NewServer))
			}
			if len(details) > 0 {
				sb.WriteString(fmt.Sprintf("  - %s (%s)\n", ca.URL, strings.Join(details, ", ")))
			}
		}
	}

	return sb.String()
}

func diffLines(prev, curr []string) (added, removed []string) {
	prevSet := make(map[string]struct{}, len(prev))
	for _, l := range prev {
		if l != "" {
			prevSet[l] = struct{}{}
		}
	}

	currSet := make(map[string]struct{}, len(curr))
	for _, l := range curr {
		if l != "" {
			currSet[l] = struct{}{}
		}
	}

	for l := range currSet {
		if _, exists := prevSet[l]; !exists {
			added = append(added, l)
		}
	}

	for l := range prevSet {
		if _, exists := currSet[l]; !exists {
			removed = append(removed, l)
		}
	}

	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func detectAssetChanges(prev, curr []httpx.HostMeta) []AssetChange {
	prevMap := make(map[string]httpx.HostMeta, len(prev))
	for _, m := range prev {
		prevMap[m.URL] = m
	}

	var changes []AssetChange
	for _, c := range curr {
		p, exists := prevMap[c.URL]
		if !exists {
			continue
		}

		statusChanged := p.StatusCode != c.StatusCode && p.StatusCode != 0 && c.StatusCode != 0
		titleChanged := p.Title != c.Title && p.Title != "" && c.Title != ""
		serverChanged := p.Server != c.Server && p.Server != "" && c.Server != ""

		if statusChanged || titleChanged || serverChanged {
			changes = append(changes, AssetChange{
				URL:       c.URL,
				OldStatus: p.StatusCode,
				NewStatus: c.StatusCode,
				OldTitle:  p.Title,
				NewTitle:  c.Title,
				OldServer: p.Server,
				NewServer: c.Server,
			})
		}
	}

	sort.Slice(changes, func(i, j int) bool {
		return changes[i].URL < changes[j].URL
	})
	return changes
}

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		t := strings.TrimSpace(scanner.Text())
		if t != "" {
			lines = append(lines, t)
		}
	}
	return lines
}

func readHostMetadata(path string) []httpx.HostMeta {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var list []httpx.HostMeta
	_ = json.Unmarshal(data, &list)
	return list
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
