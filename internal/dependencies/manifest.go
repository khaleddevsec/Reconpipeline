// Package dependencies manages the manifest file for tracked tool versions.
package dependencies

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// ToolEntry represents a single managed tool in the manifest.
type ToolEntry struct {
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Arch        string    `json:"arch"`
	OS          string    `json:"os"`
	Source      string    `json:"source"`
	InstalledAt time.Time `json:"installed_at"`
	Status      string    `json:"status"` // "ok", "missing", "error"
}

// Manifest is the dependency manifest tracking all managed tools.
type Manifest struct {
	UpdatedAt time.Time            `json:"updated_at"`
	Tools     map[string]ToolEntry `json:"tools"`
}

// NewManifest creates an empty manifest.
func NewManifest() *Manifest {
	return &Manifest{
		UpdatedAt: time.Now(),
		Tools:     make(map[string]ToolEntry),
	}
}

// Load reads a manifest from disk. Returns an empty manifest if the file
// does not exist.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return NewManifest(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest %q: %w", path, err)
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		// Corrupt manifest — return fresh one rather than hard-failing.
		return NewManifest(), nil
	}
	if m.Tools == nil {
		m.Tools = make(map[string]ToolEntry)
	}
	return &m, nil
}

// Save writes the manifest to disk atomically.
func (m *Manifest) Save(path string) error {
	m.UpdatedAt = time.Now()
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0640); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("failed to finalise manifest: %w", err)
	}
	return nil
}

// Set records a tool entry.
func (m *Manifest) Set(entry ToolEntry) {
	m.Tools[entry.Name] = entry
}

// Get retrieves a tool entry. Returns false if not found.
func (m *Manifest) Get(name string) (ToolEntry, bool) {
	e, ok := m.Tools[name]
	return e, ok
}
