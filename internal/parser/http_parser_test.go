package parser_test

import (
	"context"
	"testing"

	"github.com/khaleddevsec/Reconpipeline/v2/internal/parser"
	"github.com/khaleddevsec/Reconpipeline/v2/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestHTTPParser_Parse_MissingSecurityHeaders(t *testing.T) {
	data := &models.CollectedData{
		Target:  models.Target{URL: "http://example.com"},
		Headers: map[string][]string{"Content-Type": {"text/html"}},
	}

	p := parser.NewHTTPParser(zap.NewNop())
	result, err := p.Parse(context.Background(), data)
	require.NoError(t, err)

	assert.Contains(t, result.Headers, "_missing_strict-transport-security")
	assert.Contains(t, result.Headers, "_missing_content-security-policy")
}

func TestHTTPParser_Parse_WeakTLS(t *testing.T) {
	data := &models.CollectedData{
		Target:  models.Target{URL: "https://example.com"},
		Headers: map[string][]string{},
		TLS:     &models.TLSInfo{Version: "TLS 1.0", CipherSuite: "AES_256_GCM"},
	}

	p := parser.NewHTTPParser(zap.NewNop())
	result, err := p.Parse(context.Background(), data)
	require.NoError(t, err)

	require.NotNil(t, result.TLS)
	assert.True(t, result.TLS.WeakProtocol)
	assert.False(t, result.TLS.WeakCipher)
}

func TestHTTPParser_Parse_NilData(t *testing.T) {
	p := parser.NewHTTPParser(zap.NewNop())
	_, err := p.Parse(context.Background(), nil)
	assert.Error(t, err)
}
