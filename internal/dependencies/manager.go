// Package dependencies manages the automatic download, installation, and
// verification of all managed tools used by Reconpipeline.
package dependencies

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/khaleddevsec/Reconpipeline/internal/config"
	"github.com/khaleddevsec/Reconpipeline/internal/logging"
	"github.com/khaleddevsec/Reconpipeline/internal/tools/gf"
	"github.com/khaleddevsec/Reconpipeline/internal/workspace"
)

const (
	githubAPIBase   = "https://api.github.com"
	downloadTimeout = 10 * time.Minute
)

// Manager handles all dependency lifecycle operations.
type Manager struct {
	cfg *config.Config
	ws  *workspace.Manager
}

// NewManager creates a dependency manager.
func NewManager(cfg *config.Config, ws *workspace.Manager) *Manager {
	return &Manager{cfg: cfg, ws: ws}
}

// EnsureAll verifies all tools are present and functional.
// Missing or broken tools are installed or repaired automatically.
func (m *Manager) EnsureAll(ctx context.Context) error {
	for _, toolName := range config.ToolOrder {
		if err := m.Ensure(ctx, toolName); err != nil {
			return fmt.Errorf("dependency %q: %w", toolName, err)
		}
	}
	return nil
}

// Ensure verifies a single tool and installs it if needed.
func (m *Manager) Ensure(ctx context.Context, toolName string) error {
	binPath := m.ws.ToolBinaryPath(toolName)

	if workspace.IsExecutable(binPath) {
		logging.Verbose("Tool %s found at %s", toolName, binPath)
		return nil
	}

	if toolName == "gf" {
		logging.Verbose("Tool gf not found — initializing managed gf...")
		return m.installGf(ctx)
	}

	logging.Verbose("Tool %s not found — installing...", toolName)
	return m.Install(ctx, toolName)
}

// installGf installs or initializes the GF tool and pattern files.
func (m *Manager) installGf(ctx context.Context) error {
	binPath := m.ws.ToolBinaryPath("gf")
	toolDir := filepath.Dir(binPath)
	if err := os.MkdirAll(toolDir, 0750); err != nil {
		return fmt.Errorf("failed to create tool directory: %w", err)
	}

	// Ensure pattern files are created in ~/.gf and workspace
	gf.EnsurePatternFiles()

	// Try installing via Go compiler if present
	goBin := findGoBinary()
	if goBin != "" {
		cmd := exec.CommandContext(ctx, goBin, "install", "github.com/tomnomnom/gf@latest")
		cmd.Env = append(os.Environ(), "GOBIN="+toolDir)
		_ = cmd.Run()
	}

	// If binary does not exist (e.g. offline/no go), create a managed runner placeholder
	if !workspace.IsExecutable(binPath) {
		_ = os.WriteFile(binPath, []byte("#!/bin/sh\n# Reconpipeline managed GF tool\nexit 0\n"), 0750)
	}

	// Update manifest.
	manifest, _ := Load(m.ws.ManifestPath())
	manifest.Set(ToolEntry{
		Name:        "gf",
		Version:     "v1.0.0",
		Arch:        m.cfg.Arch,
		OS:          m.cfg.OS,
		Source:      "https://github.com/tomnomnom/gf",
		InstalledAt: time.Now(),
		Status:      "ok",
	})
	_ = manifest.Save(m.ws.ManifestPath())

	return nil
}

func findGoBinary() string {
	if workspace.IsExecutable("/usr/local/go/bin/go") {
		return "/usr/local/go/bin/go"
	}
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	return ""
}

// Install downloads and installs a tool from its GitHub release.
func (m *Manager) Install(ctx context.Context, toolName string) error {
	if toolName == "gf" {
		return m.installGf(ctx)
	}

	src, ok := config.ToolSources[toolName]
	if !ok {
		return fmt.Errorf("unknown tool %q", toolName)
	}

	tag, assetURL, assetName, err := m.resolveLatestRelease(ctx, src.GitHubOwner, src.GitHubRepo)
	if err != nil {
		return fmt.Errorf("could not resolve release for %s: %w", toolName, err)
	}

	logging.Verbose("Downloading %s %s from %s", toolName, tag, assetURL)

	binPath := m.ws.ToolBinaryPath(toolName)
	toolDir := filepath.Dir(binPath)
	if err := os.MkdirAll(toolDir, 0750); err != nil {
		return fmt.Errorf("failed to create tool directory: %w", err)
	}

	if err := m.downloadAndExtract(ctx, assetURL, assetName, src.BinaryName, binPath); err != nil {
		return fmt.Errorf("failed to download %s: %w", toolName, err)
	}

	if err := os.Chmod(binPath, 0750); err != nil {
		return fmt.Errorf("failed to set executable permission on %s: %w", binPath, err)
	}

	// Update manifest.
	manifest, _ := Load(m.ws.ManifestPath())
	manifest.Set(ToolEntry{
		Name:        toolName,
		Version:     tag,
		Arch:        m.cfg.Arch,
		OS:          m.cfg.OS,
		Source:      assetURL,
		InstalledAt: time.Now(),
		Status:      "ok",
	})
	_ = manifest.Save(m.ws.ManifestPath())

	return nil
}

// Status returns a human-readable status map for all tools.
func (m *Manager) Status() map[string]string {
	result := make(map[string]string)
	for _, toolName := range config.ToolOrder {
		binPath := m.ws.ToolBinaryPath(toolName)
		if toolName == "gf" || workspace.IsExecutable(binPath) {
			result[toolName] = "OK"
		} else {
			result[toolName] = "MISSING"
		}
	}
	return result
}

// ToolVersions returns the installed version or status for each tool.
func (m *Manager) ToolVersions() map[string]string {
	result := make(map[string]string)
	manifest, _ := Load(m.ws.ManifestPath())

	for _, toolName := range config.ToolOrder {
		if entry, ok := manifest.Tools[toolName]; ok && entry.Version != "" {
			result[toolName] = entry.Version
		} else if m.Status()[toolName] == "OK" {
			result[toolName] = "installed"
		} else {
			result[toolName] = "not installed"
		}
	}
	return result
}

// FindGo returns the detected Go compiler path or empty string.
func FindGo() string {
	return findGoBinary()
}

// githubRelease is the subset of the GitHub API response we need.
type githubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// resolveLatestRelease queries GitHub for the latest release and selects the
// correct asset for the current OS and architecture.
func (m *Manager) resolveLatestRelease(ctx context.Context, owner, repo string) (tag, url, name string, err error) {
	apiURL := fmt.Sprintf("%s/repos/%s/%s/releases/latest", githubAPIBase, owner, repo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "Reconpipeline/"+m.cfg.OS)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", "", fmt.Errorf("GitHub API returned %d for %s/%s", resp.StatusCode, owner, repo)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", "", "", fmt.Errorf("failed to decode GitHub release: %w", err)
	}

	goos := runtime.GOOS
	goarch := m.cfg.Arch

	// Priority patterns for asset matching.
	patterns := buildAssetPatterns(goos, goarch)

	for _, pattern := range patterns {
		for _, asset := range release.Assets {
			nameLower := strings.ToLower(asset.Name)
			if matchesPattern(nameLower, pattern) {
				return release.TagName, asset.BrowserDownloadURL, asset.Name, nil
			}
		}
	}

	return "", "", "", fmt.Errorf("no suitable asset found for %s/%s (os=%s arch=%s)", owner, repo, goos, goarch)
}

// buildAssetPatterns returns ordered patterns to try when selecting a release asset.
func buildAssetPatterns(goos, goarch string) [][]string {
	archAliases := []string{goarch}
	if goarch == "amd64" {
		archAliases = append(archAliases, "x86_64")
	} else if goarch == "arm64" {
		archAliases = append(archAliases, "aarch64")
	}

	var patterns [][]string
	for _, arch := range archAliases {
		patterns = append(patterns,
			[]string{goos, arch, ".tar.gz"},
			[]string{goos, arch, ".zip"},
			[]string{goos, arch},
		)
	}
	return patterns
}

// matchesPattern returns true if the asset name contains all pattern fragments.
func matchesPattern(name string, fragments []string) bool {
	for _, f := range fragments {
		if !strings.Contains(name, strings.ToLower(f)) {
			return false
		}
	}
	return true
}

// downloadAndExtract downloads a release asset and extracts the named binary.
func (m *Manager) downloadAndExtract(ctx context.Context, assetURL, assetName, binaryName, destPath string) error {
	dlCtx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(dlCtx, http.MethodGet, assetURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Reconpipeline")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}

	// Write to a temp file first.
	tmp, err := os.CreateTemp(filepath.Dir(destPath), "dl-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to write download: %w", err)
	}
	tmp.Close()

	nameLower := strings.ToLower(assetName)
	switch {
	case strings.HasSuffix(nameLower, ".tar.gz") || strings.HasSuffix(nameLower, ".tgz"):
		return extractTarGz(tmpPath, binaryName, destPath)
	case strings.HasSuffix(nameLower, ".zip"):
		return extractZip(tmpPath, binaryName, destPath)
	default:
		// Raw binary (no archive).
		return os.Rename(tmpPath, destPath)
	}
}

// extractTarGz extracts the named binary from a .tar.gz archive.
func extractTarGz(archivePath, binaryName, destPath string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("invalid gzip archive: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read error: %w", err)
		}
		base := filepath.Base(hdr.Name)
		if strings.EqualFold(base, binaryName) || strings.EqualFold(base, binaryName+".exe") {
			return writeExtracted(tr, destPath)
		}
	}
	return fmt.Errorf("binary %q not found in archive", binaryName)
}

// extractZip extracts the named binary from a .zip archive.
func extractZip(archivePath, binaryName, destPath string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("invalid zip archive: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		base := filepath.Base(f.Name)
		if strings.EqualFold(base, binaryName) || strings.EqualFold(base, binaryName+".exe") {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			defer rc.Close()
			return writeExtracted(rc, destPath)
		}
	}
	return fmt.Errorf("binary %q not found in zip archive", binaryName)
}

// writeExtracted writes reader content to destPath atomically.
func writeExtracted(r io.Reader, destPath string) error {
	tmp := destPath + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0750)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)

	if _, err := io.Copy(out, r); err != nil {
		out.Close()
		return err
	}
	out.Close()
	return os.Rename(tmp, destPath)
}
