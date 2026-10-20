// Package config provides internal configuration and profile management for Reconpipeline.
package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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

	// DefaultProfile is the default execution profile.
	DefaultProfile = "full"

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

// ProfileConfig represents the execution profile configuration.
type ProfileConfig struct {
	Name             string        `json:"name"`
	Mode             string        `json:"mode"`
	Threads          int           `json:"threads"`
	Timeout          time.Duration `json:"timeout"`
	CrawlDepth       int           `json:"crawl_depth"`
	EnableHistorical bool          `json:"enable_historical"`
	EnablePatterns   bool          `json:"enable_patterns"`
	VerifyURLs       bool          `json:"verify_urls"`
	MaxVerifyURLs    int           `json:"max_verify_urls"`
}

// DefaultProfiles holds the built-in profile definitions.
var DefaultProfiles = map[string]ProfileConfig{
	"full": {
		Name:             "full",
		Mode:             "full",
		Threads:          10,
		Timeout:          30 * time.Minute,
		CrawlDepth:       3,
		EnableHistorical: true,
		EnablePatterns:   true,
		VerifyURLs:       true,
		MaxVerifyURLs:    5000,
	},
	"fast": {
		Name:             "fast",
		Mode:             "full",
		Threads:          15,
		Timeout:          15 * time.Minute,
		CrawlDepth:       1,
		EnableHistorical: true,
		EnablePatterns:   true,
		VerifyURLs:       true,
		MaxVerifyURLs:    2500,
	},
	"passive": {
		Name:             "passive",
		Mode:             "passive",
		Threads:          10,
		Timeout:          15 * time.Minute,
		CrawlDepth:       0,
		EnableHistorical: true,
		EnablePatterns:   true,
		VerifyURLs:       false,
		MaxVerifyURLs:    0,
	},
}

// UserSettings represents optional user-configured preferences.
type UserSettings struct {
	DefaultProfile   string `json:"default_profile"`
	DefaultThreads   int    `json:"default_threads"`
	DefaultTimeout   string `json:"default_timeout"`
	DefaultOutput    string `json:"default_output"`
	LogLevel         string `json:"log_level"`
	CacheEnabled     bool   `json:"cache_enabled"`
	HistoryRetention int    `json:"history_retention"`
	VerifyURLs       bool   `json:"verify_urls"`
	MaxVerifyURLs    int    `json:"max_verify_urls"`
}

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

	// UserSettings contains preferences loaded from config files.
	UserSettings UserSettings

	// Arch is the current CPU architecture (amd64, arm64).
	Arch string
	// OS is the current operating system (linux).
	OS string
}

// NewConfig creates a Config with all paths resolved and loads user settings if available.
func NewConfig() *Config {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/root"
	}

	workDir := filepath.Join(home, ".reconpipeline")
	cfg := &Config{
		WorkDir:     workDir,
		ToolsDir:    filepath.Join(workDir, "tools"),
		VersionsDir: filepath.Join(workDir, "versions"),
		CacheDir:    filepath.Join(workDir, "cache"),
		ConfigDir:   filepath.Join(workDir, "config"),
		LogsDir:     filepath.Join(workDir, "logs"),
		ResultsDir:  "ReconResults",
		UserSettings: UserSettings{
			DefaultProfile:   "full",
			DefaultThreads:   10,
			DefaultTimeout:   "30m",
			DefaultOutput:    "ReconResults",
			LogLevel:         "info",
			CacheEnabled:     true,
			HistoryRetention: 0,
			VerifyURLs:       true,
			MaxVerifyURLs:    5000,
		},
		Arch: normaliseArch(runtime.GOARCH),
		OS:   runtime.GOOS,
	}

	cfg.loadUserSettings(home)
	return cfg
}

// loadUserSettings attempts to load configuration from ~/.config/reconpipeline/config.yaml
// or ~/.reconpipeline/config/config.yaml or json equivalents.
func (c *Config) loadUserSettings(home string) {
	paths := []string{
		filepath.Join(home, ".config", "reconpipeline", "config.yaml"),
		filepath.Join(home, ".config", "reconpipeline", "config.json"),
		filepath.Join(c.ConfigDir, "config.yaml"),
		filepath.Join(c.ConfigDir, "config.json"),
	}

	for _, path := range paths {
		if data, err := os.ReadFile(path); err == nil {
			if strings.HasSuffix(path, ".json") {
				_ = json.Unmarshal(data, &c.UserSettings)
			} else {
				parseSimpleYAML(string(data), &c.UserSettings)
			}
			return
		}
	}
}

// parseSimpleYAML parses basic key-value configuration lines.
func parseSimpleYAML(content string, s *UserSettings) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, `"'`)

		switch key {
		case "default_profile", "profile":
			s.DefaultProfile = val
		case "default_threads", "threads", "workers", "concurrency":
			if n, err := strconv.Atoi(val); err == nil && n > 0 {
				s.DefaultThreads = n
			}
		case "default_timeout", "timeout":
			s.DefaultTimeout = val
		case "default_output", "output":
			s.DefaultOutput = val
		case "log_level", "logging":
			s.LogLevel = val
		case "cache_enabled", "cache":
			s.CacheEnabled = strings.ToLower(val) == "true" || val == "1" || strings.ToLower(val) == "yes"
		case "verify_urls", "url_verification", "verify":
			s.VerifyURLs = strings.ToLower(val) == "true" || val == "1" || strings.ToLower(val) == "yes"
		case "max_verify_urls", "max_urls":
			if n, err := strconv.Atoi(val); err == nil && n >= 0 {
				s.MaxVerifyURLs = n
			}
		case "history_retention", "retention":
			if n, err := strconv.Atoi(val); err == nil && n >= 0 {
				s.HistoryRetention = n
			}
		}
	}
}

// GetProfile returns a ProfileConfig for the given profile name.
// Falls back to "full" if the profile is unknown.
func GetProfile(name string) ProfileConfig {
	pName := strings.ToLower(strings.TrimSpace(name))
	if p, ok := DefaultProfiles[pName]; ok {
		return p
	}
	return DefaultProfiles["full"]
}

// ValidateProfile checks if the profile name is supported.
func ValidateProfile(name string) error {
	pName := strings.ToLower(strings.TrimSpace(name))
	if _, ok := DefaultProfiles[pName]; !ok {
		return fmt.Errorf("invalid profile %q (supported: full, fast, passive)", name)
	}
	return nil
}

// ValidateOptions checks if runtime options are within valid boundaries.
func ValidateOptions(threads int, timeoutStr string, mode string, profile string) error {
	if threads <= 0 {
		return fmt.Errorf("concurrency threads must be greater than 0, got %d", threads)
	}
	if threads > 200 {
		return fmt.Errorf("concurrency threads must not exceed 200 to prevent denial of service, got %d", threads)
	}
	if timeoutStr != "" {
		dur, err := time.ParseDuration(timeoutStr)
		if err != nil {
			return fmt.Errorf("invalid timeout format %q: %w (example: 30m, 1h)", timeoutStr, err)
		}
		if dur <= 0 {
			return fmt.Errorf("timeout must be greater than 0, got %s", timeoutStr)
		}
	}
	if mode != "" && mode != "full" && mode != "active" && mode != "passive" {
		return fmt.Errorf("invalid mode %q (supported: full, active, passive)", mode)
	}
	if profile != "" {
		if err := ValidateProfile(profile); err != nil {
			return err
		}
	}
	return nil
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
