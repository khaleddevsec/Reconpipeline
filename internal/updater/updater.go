// Package updater implements self-update functionality for Reconpipeline.
// It queries GitHub Releases, compares semantic versions, and atomically
// replaces the running binary.
package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/khaleddevsec/Reconpipeline/internal/version"
)

const (
	githubOwner     = "khaleddevsec"
	githubRepo      = "Reconpipeline"
	githubAPIBase   = "https://api.github.com"
	downloadTimeout = 5 * time.Minute
)

// Release represents a GitHub release.
type Release struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// CheckResult is the result of an update check.
type CheckResult struct {
	CurrentVersion  string
	LatestVersion   string
	UpdateAvailable bool
	AssetURL        string
	AssetName       string
}

// GetVersionStatus returns the version string with status:
// "v2.5.0 (Latest)" or "v2.5.0 (Update available: v2.6.0 -> Run 'reconpipeline update')"
// or "v2.5.0" if offline.
func GetVersionStatus(ctx context.Context) string {
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	result, err := Check(checkCtx)
	if err != nil || result == nil {
		return version.Version
	}

	if result.UpdateAvailable {
		return fmt.Sprintf("%s (Update available: %s -> Run 'reconpipeline update')", result.CurrentVersion, result.LatestVersion)
	}

	if result.LatestVersion != "" {
		return fmt.Sprintf("%s (Latest)", result.CurrentVersion)
	}

	return version.Version
}

// Check queries GitHub for the latest release and compares versions.
func Check(ctx context.Context) (*CheckResult, error) {
	apiURL := fmt.Sprintf("%s/repos/%s/%s/releases/latest", githubAPIBase, githubOwner, githubRepo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "Reconpipeline/"+version.Version)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to reach GitHub: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no releases found at https://github.com/%s/%s", githubOwner, githubRepo)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to parse release: %w", err)
	}

	current := version.Version
	latest := release.TagName

	result := &CheckResult{
		CurrentVersion:  current,
		LatestVersion:   latest,
		UpdateAvailable: IsNewer(latest, current),
	}

	if result.UpdateAvailable {
		goos := runtime.GOOS
		goarch := runtime.GOARCH

		for _, asset := range release.Assets {
			name := strings.ToLower(asset.Name)
			if strings.Contains(name, goos) && strings.Contains(name, goarch) {
				result.AssetURL = asset.BrowserDownloadURL
				result.AssetName = asset.Name
				break
			}
		}
		// Fallback: match by architecture string alias.
		if result.AssetURL == "" {
			archAlias := goarch
			if goarch == "amd64" {
				archAlias = "x86_64"
			} else if goarch == "arm64" {
				archAlias = "aarch64"
			}
			for _, asset := range release.Assets {
				name := strings.ToLower(asset.Name)
				if strings.Contains(name, goos) && strings.Contains(name, archAlias) {
					result.AssetURL = asset.BrowserDownloadURL
					result.AssetName = asset.Name
					break
				}
			}
		}
	}

	return result, nil
}

// Apply downloads the new binary and atomically replaces the current executable.
// Configuration, results, cache, and managed dependencies are preserved.
func Apply(ctx context.Context, result *CheckResult) error {
	if result.AssetURL == "" {
		return fmt.Errorf("no download URL available for this platform")
	}

	// Determine current executable path.
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine executable path: %w", err)
	}

	dlCtx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(dlCtx, http.MethodGet, result.AssetURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Reconpipeline/"+version.Version)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}

	// Write to a temp file alongside the existing binary.
	tmp := exePath + ".update.tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0750)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	if _, err := io.Copy(out, resp.Body); err != nil {
		out.Close()
		os.Remove(tmp)
		return fmt.Errorf("failed to write update: %w", err)
	}
	out.Close()

	// Atomic replace.
	backup := exePath + ".bak"
	_ = os.Rename(exePath, backup)

	if err := os.Rename(tmp, exePath); err != nil {
		// Restore backup.
		_ = os.Rename(backup, exePath)
		os.Remove(tmp)
		return fmt.Errorf("failed to replace binary: %w", err)
	}

	// Remove backup on success.
	os.Remove(backup)
	return nil
}

// IsNewer returns true if version a is newer than version b.
// Both are expected to be in "vMAJOR.MINOR.PATCH" format.
func IsNewer(a, b string) bool {
	av := ParseVersion(a)
	bv := ParseVersion(b)
	if av[0] != bv[0] {
		return av[0] > bv[0]
	}
	if av[1] != bv[1] {
		return av[1] > bv[1]
	}
	return av[2] > bv[2]
}

// ParseVersion parses a "vMAJOR.MINOR.PATCH" string into [3]int.
func ParseVersion(v string) [3]int {
	v = strings.TrimPrefix(v, "v")
	var major, minor, patch int
	fmt.Sscanf(v, "%d.%d.%d", &major, &minor, &patch)
	return [3]int{major, minor, patch}
}
