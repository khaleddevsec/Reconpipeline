// Package cache implements smart caching for Reconpipeline stages.
// Caching avoids redundant execution across repeated scans while maintaining
// strict isolation and safe invalidation when inputs change.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/frozeniceee/Reconpipeline/internal/version"
)

// Entry represents metadata about a cached stage output.
type Entry struct {
	Key        string            `json:"key"`
	Target     string            `json:"target"`
	Stage      string            `json:"stage"`
	Version    string            `json:"version"`
	InputHash  string            `json:"input_hash"`
	CreatedAt  time.Time         `json:"created_at"`
	Files      map[string]string `json:"files"` // relative filename -> content hash
	ItemCounts map[string]int    `json:"item_counts,omitempty"`
}

// Manager orchestrates stage artifact caching and retrieval.
type Manager struct {
	cacheDir string
	enabled  bool
	mu       sync.RWMutex
}

// NewManager creates a cache manager.
func NewManager(cacheDir string, enabled bool) *Manager {
	_ = os.MkdirAll(cacheDir, 0750)
	return &Manager{
		cacheDir: cacheDir,
		enabled:  enabled,
	}
}

// IsEnabled returns true if caching is enabled.
func (m *Manager) IsEnabled() bool {
	return m.enabled
}

// SetEnabled enables or disables caching.
func (m *Manager) SetEnabled(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = enabled
}

// ComputeHash computes a SHA256 hex string over multiple files and extra string inputs.
func ComputeHash(extraData string, files ...string) string {
	h := sha256.New()
	h.Write([]byte(extraData))
	h.Write([]byte(version.Version))

	for _, file := range files {
		if file == "" {
			continue
		}
		if f, err := os.Open(file); err == nil {
			_, _ = io.Copy(h, f)
			_ = f.Close()
		}
	}

	return hex.EncodeToString(h.Sum(nil))
}

// CacheKey generates a deterministic cache key.
func CacheKey(target, stage, inputHash string) string {
	raw := fmt.Sprintf("%s:%s:%s:%s", target, stage, version.Version, inputHash)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// Get checks if a valid cache entry exists and returns it.
func (m *Manager) Get(target, stage, inputHash string) (*Entry, string, bool) {
	if !m.enabled {
		return nil, "", false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	key := CacheKey(target, stage, inputHash)
	entryDir := filepath.Join(m.cacheDir, target, stage, key)
	metaFile := filepath.Join(entryDir, "meta.json")

	data, err := os.ReadFile(metaFile)
	if err != nil {
		return nil, "", false
	}

	var entry Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, "", false
	}

	// Verify target, version, and input hash
	if entry.Target != target || entry.Stage != stage || entry.InputHash != inputHash || entry.Version != version.Version {
		return nil, "", false
	}

	// Verify all cached files exist
	for fname := range entry.Files {
		fpath := filepath.Join(entryDir, fname)
		if _, statErr := os.Stat(fpath); os.IsNotExist(statErr) {
			return nil, "", false
		}
	}

	return &entry, entryDir, true
}

// Put saves stage output files and metadata into the cache.
func (m *Manager) Put(target, stage, inputHash string, files map[string][]byte, counts map[string]int) error {
	if !m.enabled {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := CacheKey(target, stage, inputHash)
	entryDir := filepath.Join(m.cacheDir, target, stage, key)
	if err := os.MkdirAll(entryDir, 0750); err != nil {
		return fmt.Errorf("failed to create cache entry directory: %w", err)
	}

	fileHashes := make(map[string]string)
	for fname, content := range files {
		fpath := filepath.Join(entryDir, fname)
		dir := filepath.Dir(fpath)
		_ = os.MkdirAll(dir, 0750)

		if err := os.WriteFile(fpath, content, 0640); err != nil {
			return fmt.Errorf("failed to write cache file %s: %w", fname, err)
		}
		sum := sha256.Sum256(content)
		fileHashes[fname] = hex.EncodeToString(sum[:])
	}

	entry := Entry{
		Key:        key,
		Target:     target,
		Stage:      stage,
		Version:    version.Version,
		InputHash:  inputHash,
		CreatedAt:  time.Now().UTC(),
		Files:      fileHashes,
		ItemCounts: counts,
	}

	metaData, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}

	metaFile := filepath.Join(entryDir, "meta.json")
	return os.WriteFile(metaFile, metaData, 0640)
}

// RestoreArtifacts copies cached files into destination stage directory.
func (m *Manager) RestoreArtifacts(entryDir string, destDir string) error {
	metaFile := filepath.Join(entryDir, "meta.json")
	data, err := os.ReadFile(metaFile)
	if err != nil {
		return err
	}

	var entry Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		return err
	}

	for fname := range entry.Files {
		src := filepath.Join(entryDir, fname)
		dst := filepath.Join(destDir, fname)
		_ = os.MkdirAll(filepath.Dir(dst), 0750)

		content, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("failed to read cached artifact %s: %w", fname, err)
		}
		if err := os.WriteFile(dst, content, 0640); err != nil {
			return fmt.Errorf("failed to restore cached artifact to %s: %w", dst, err)
		}
	}

	return nil
}

// InvalidateTarget purges all cached entries for a target.
func (m *Manager) InvalidateTarget(target string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	targetDir := filepath.Join(m.cacheDir, target)
	return os.RemoveAll(targetDir)
}

// Clear purges all cache entries across all targets.
func (m *Manager) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return os.RemoveAll(m.cacheDir)
}
