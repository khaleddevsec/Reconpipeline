package fingerprint_test

import (
	"context"
	"testing"

	"github.com/khaleddevsec/Reconpipeline/internal/fingerprint"
	"github.com/khaleddevsec/Reconpipeline/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestHeaderEngine_Identify(t *testing.T) {
	tests := []struct {
		name         string
		headers      map[string][]string
		wantCategory string
		wantName     string
	}{
		{
			name:         "nginx server",
			headers:      map[string][]string{"Server": {"nginx/1.25.0"}},
			wantCategory: "server",
			wantName:     "nginx",
		},
		{
			name:         "apache server",
			headers:      map[string][]string{"Server": {"Apache/2.4.51 (Ubuntu)"}},
			wantCategory: "server",
			wantName:     "Apache",
		},
		{
			name:         "php language",
			headers:      map[string][]string{"X-Powered-By": {"PHP/8.1.0"}},
			wantCategory: "language",
			wantName:     "PHP",
		},
		{
			name:         "cloudflare cdn",
			headers:      map[string][]string{"Server": {"cloudflare"}},
			wantCategory: "cdn",
			wantName:     "Cloudflare",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &models.CollectedData{
				Target:  models.Target{URL: "http://example.com"},
				Headers: tt.headers,
			}
			fps, err := fingerprint.NewHeaderEngine(zap.NewNop()).Identify(context.Background(), data)
			require.NoError(t, err)
			require.NotEmpty(t, fps)

			found := false
			for _, fp := range fps {
				if fp.Category == tt.wantCategory && fp.Name == tt.wantName {
					found = true
				}
			}
			assert.True(t, found, "expected %s/%s in %+v", tt.wantCategory, tt.wantName, fps)
		})
	}
}
