package knowledge_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/khaleddevsec/Reconpipeline/internal/knowledge"
	"github.com/khaleddevsec/Reconpipeline/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const testDB = `
- id: CSP-MISSING
  title: Missing Content-Security-Policy
  description: No CSP header
  severity: HIGH
  confidence: 0.9
  header_name: Content-Security-Policy
  owasp: ["A05:2021"]
  remediation: Add a Content-Security-Policy header

- id: TLS-WEAK-PROTO
  title: Weak TLS Protocol
  description: TLS version below 1.2
  severity: HIGH
  confidence: 0.95
  tls_weak_protocol: true
  remediation: Disable TLS 1.0 and 1.1

- id: SERVER-DISCLOSURE
  title: Server Version Disclosure
  description: Server header reveals version
  severity: LOW
  confidence: 0.8
  fingerprint_category: server
  remediation: Remove or obscure the Server header
`

func TestYAMLDatabase_Load(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "findings.yaml"), []byte(testDB), 0600))

	db := knowledge.NewYAMLDatabase(zap.NewNop())
	require.NoError(t, db.Load(dir))
}

func TestYAMLDatabase_FindingsForHeader(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "findings.yaml"), []byte(testDB), 0600))

	db := knowledge.NewYAMLDatabase(zap.NewNop())
	require.NoError(t, db.Load(dir))

	findings, err := db.FindingsForHeader("Content-Security-Policy", "")
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "CSP-MISSING", findings[0].ID)
	assert.Equal(t, models.SeverityHigh, findings[0].Severity)
}

func TestYAMLDatabase_FindingsForTLS(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "findings.yaml"), []byte(testDB), 0600))

	db := knowledge.NewYAMLDatabase(zap.NewNop())
	require.NoError(t, db.Load(dir))

	findings, err := db.FindingsForTLS(&models.TLSInfo{WeakProtocol: true})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "TLS-WEAK-PROTO", findings[0].ID)
}

func TestYAMLDatabase_LoadEmbedded(t *testing.T) {
	db := knowledge.NewYAMLDatabase(zap.NewNop())
	require.NoError(t, db.LoadEmbedded())
	require.NoError(t, db.Integrity())
	assert.NotEmpty(t, db.Version())

	findings, err := db.FindingsForHeader("Content-Security-Policy", "")
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	tlsFindings, err := db.FindingsForTLS(&models.TLSInfo{Expired: true, SelfSigned: true})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(tlsFindings), 2)
}

func TestYAMLDatabase_FindingsForFingerprint(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "findings.yaml"), []byte(testDB), 0600))

	db := knowledge.NewYAMLDatabase(zap.NewNop())
	require.NoError(t, db.Load(dir))

	findings, err := db.FindingsForFingerprint(models.Fingerprint{Category: "server", Name: "nginx"})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "SERVER-DISCLOSURE", findings[0].ID)
}
