package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/khaleddevsec/Reconpipeline/v2/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefault_Values(t *testing.T) {
	cfg := config.Default()
	assert.Equal(t, 5, cfg.Concurrency)
	assert.Equal(t, 30, cfg.TimeoutSecs)
	assert.Equal(t, 3, cfg.Retries)
	assert.Equal(t, "ThreatLens/1.0", cfg.UserAgent)
}

func TestLoad_OverridesDefaults(t *testing.T) {
	yaml := `
concurrency: 20
timeout_seconds: 10
user_agent: "Custom/2.0"
knowledge_db_path: "/data/kb"
`
	f := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(f, []byte(yaml), 0600))

	cfg, err := config.Load(f)
	require.NoError(t, err)
	assert.Equal(t, 20, cfg.Concurrency)
	assert.Equal(t, 10, cfg.TimeoutSecs)
	assert.Equal(t, "Custom/2.0", cfg.UserAgent)
	assert.Equal(t, "/data/kb", cfg.KnowledgeDB)
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := config.Load("/nonexistent/config.yaml")
	assert.Error(t, err)
}

func TestLoad_InvalidYAML(t *testing.T) {
	f := filepath.Join(t.TempDir(), "bad.yaml")
	require.NoError(t, os.WriteFile(f, []byte(":\tinvalid: yaml: ["), 0600))

	_, err := config.Load(f)
	assert.Error(t, err)
}

func TestValidate_InvalidConcurrency(t *testing.T) {
	cfg := config.Default()
	cfg.Concurrency = 0
	assert.Error(t, cfg.Validate())
}

func TestValidate_InvalidTimeout(t *testing.T) {
	cfg := config.Default()
	cfg.TimeoutSecs = -1
	assert.Error(t, cfg.Validate())
}

func TestValidate_Valid(t *testing.T) {
	assert.NoError(t, config.Default().Validate())
}
