// Package config provides internal configuration for Reconpipeline.
// Users should not need to modify these settings.
package config

import (
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	// AppName is the application name.
	AppName = "reconpipeline"

	// DefaultTimeout is the default scan timeout.
	DefaultTimeout = 30 * time.Minute

	// DefaultThreads is the default worker thread count.
	DefaultThreads = 10

	// DefaultMode is the default scan mode.
	DefaultMode = "full"

	// ManifestFile is the dependency manifest filename.
	ManifestFile = "manifest.json"

	// RunFile is the per-scan state filename.
	RunFile = "run.json"
)

// ToolSource defines the download configuration for a managed tool.
type ToolSource struct {
	// Name is the tool identifier.
	Name string
	// GitHubOwner is the GitHub repository owner.
	GitHubOwner string
	// GitHubRepo is the GitHub repository name.
	GitHubRepo string
	// BinaryName is the binary filename within the release archive.
	BinaryName string
	// ReleaseTag is the pinned release tag (empty = latest).
	ReleaseTag string
}

// ToolSources defines the managed tool download sources.
var ToolSources = map[string]ToolSource{
	"subfinder": {
		Name:        "subfinder",
		GitHubOwner: "projectdiscovery",
		GitHubRepo:  "subfinder",
		BinaryName:  "subfinder",
	},
	"httpx": {
		Name:        "httpx",
		GitHubOwner: "projectdiscovery",
		GitHubRepo:  "httpx",
		BinaryName:  "httpx",
	},
	"katana": {
		Name:        "katana",
		GitHubOwner: "projectdiscovery",
		GitHubRepo:  "katana",
		BinaryName:  "katana",
	},
	"gau": {
		Name:        "gau",
		GitHubOwner: "lc",
		GitHubRepo:  "gau",
		BinaryName:  "gau",
	},
	"gf": {
		Name:        "gf",
		GitHubOwner: "tomnomnom",
		GitHubRepo:  "gf",
		BinaryName:  "gf",
	},
}

// ToolOrder defines the ordered list of managed tools.
var ToolOrder = []string{"subfinder", "httpx", "katana", "gau", "gf"}

// Config holds the runtime configuration.
type Config struct {
	// WorkDir is the managed runtime directory (~/.reconpipeline).
	WorkDir string
	// ToolsDir is the managed tools directory.
	ToolsDir string
	// VersionsDir is the dependency manifest directory.
	VersionsDir string
	// CacheDir is the cache directory.
	CacheDir string
	// ConfigDir is the config directory.
	ConfigDir string
	// LogsDir is the logs directory.
	LogsDir string
	// ResultsDir is the default results directory.
	ResultsDir string

	// Arch is the current CPU architecture (amd64, arm64).
	Arch string
	// OS is the current operating system (linux).
	OS string
}

// NewConfig creates a Config with all paths resolved.
func NewConfig() *Config {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/root"
	}

	workDir := filepath.Join(home, ".reconpipeline")
	return &Config{
		WorkDir:     workDir,
		ToolsDir:    filepath.Join(workDir, "tools"),
		VersionsDir: filepath.Join(workDir, "versions"),
		CacheDir:    filepath.Join(workDir, "cache"),
		ConfigDir:   filepath.Join(workDir, "config"),
		LogsDir:     filepath.Join(workDir, "logs"),
		ResultsDir:  "results",
		Arch:        normaliseArch(runtime.GOARCH),
		OS:          runtime.GOOS,
	}
}

// normaliseArch maps Go GOARCH values to the architecture strings used in
// release artifact filenames.
func normaliseArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	case "386":
		return "386"
	default:
		return goarch
	}
}
