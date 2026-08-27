// Package workspace manages the Reconpipeline runtime directory structure.
// All managed tool storage, logs, cache, config, and per-scan results are
// located within the workspace.
package workspace

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/frozeniceee/Reconpipeline/internal/config"
)

// Manager manages the workspace directory structure.
type Manager struct {
	cfg *config.Config
}

// NewManager creates a workspace manager from a config.
func NewManager(cfg *config.Config) *Manager {
	return &Manager{cfg: cfg}
}

// Init creates all required workspace directories.
func (m *Manager) Init() error {
	dirs := []string{
		m.cfg.WorkDir,
		m.cfg.ToolsDir,
		m.cfg.VersionsDir,
		m.cfg.CacheDir,
		m.cfg.ConfigDir,
		m.cfg.LogsDir,
	}

	for _, tool := range config.ToolOrder {
		dirs = append(dirs, filepath.Join(m.cfg.ToolsDir, tool))
	}

	for _, d := range dirs {
		if err := os.MkdirAll(d, 0750); err != nil {
			return fmt.Errorf("failed to create workspace directory %q: %w", d, err)
		}
	}
	return nil
}

// TargetDir returns the result directory for the given domain and output path.
func (m *Manager) TargetDir(outputRoot, domain string) string {
	root := outputRoot
	if root == "" {
		root = m.cfg.ResultsDir
	}
	return filepath.Join(root, domain)
}

// StageDir returns the stage-specific result directory.
func (m *Manager) StageDir(targetDir string, stage int, name string) string {
	return filepath.Join(targetDir, fmt.Sprintf("%02d-%s", stage, name))
}

// InitTargetDirs creates all stage directories and intelligence subdirectories for a target.
func (m *Manager) InitTargetDirs(targetDir string) error {
	dirs := []string{
		filepath.Join(targetDir, "01-subdomain-discovery"),
		filepath.Join(targetDir, "01-subdomain-discovery", "dns"),
		filepath.Join(targetDir, "01-subdomain-discovery", "classified"),
		filepath.Join(targetDir, "02-live-host-detection"),
		filepath.Join(targetDir, "02-live-host-detection", "status"),
		filepath.Join(targetDir, "02-live-host-detection", "technologies"),
		filepath.Join(targetDir, "03-active-crawling"),
		filepath.Join(targetDir, "03-active-crawling", "katana"),
		filepath.Join(targetDir, "04-historical-url-discovery"),
		filepath.Join(targetDir, "04-historical-url-discovery", "gau"),
		filepath.Join(targetDir, "05-url-processing"),
		filepath.Join(targetDir, "05-url-processing", "raw"),
		filepath.Join(targetDir, "05-url-processing", "normalized"),
		filepath.Join(targetDir, "05-url-processing", "deduplicated"),
		filepath.Join(targetDir, "05-url-processing", "api"),
		filepath.Join(targetDir, "05-url-processing", "javascript"),
		filepath.Join(targetDir, "05-url-processing", "parameters"),
		filepath.Join(targetDir, "05-url-processing", "clusters"),
		filepath.Join(targetDir, "05-url-processing", "interesting"),
		filepath.Join(targetDir, "05-url-processing", "priority"),
		filepath.Join(targetDir, "06-pattern-analysis"),
		filepath.Join(targetDir, "06-pattern-analysis", "gf"),
		filepath.Join(targetDir, "06-pattern-analysis", "patterns"),
		filepath.Join(targetDir, "summary"),
	}

	for _, d := range dirs {
		if err := os.MkdirAll(d, 0750); err != nil {
			return fmt.Errorf("failed to create directory %q: %w", d, err)
		}
	}
	return nil
}

// ToolBinaryPath returns the absolute path to a managed tool binary.
func (m *Manager) ToolBinaryPath(toolName string) string {
	return filepath.Join(m.cfg.ToolsDir, toolName, toolName)
}

// ManifestPath returns the path to the dependency manifest file.
func (m *Manager) ManifestPath() string {
	return filepath.Join(m.cfg.VersionsDir, config.ManifestFile)
}

// LogsDir returns the logs directory path.
func (m *Manager) LogsDir() string {
	return m.cfg.LogsDir
}

// RunFilePath returns the path to run.json for a target directory.
func RunFilePath(targetDir string) string {
	return filepath.Join(targetDir, config.RunFile)
}

// Exists returns true if the path exists.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// IsExecutable returns true if the file at path exists and is executable.
func IsExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode()&0111 != 0
}
