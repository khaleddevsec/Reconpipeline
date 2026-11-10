package fingerprint

import (
	"context"
	"fmt"
	"strings"

	"github.com/khaleddevsec/Reconpipeline/v2/models"
	"go.uber.org/zap"
)

// HeaderEngine implements Engine using HTTP response headers.
type HeaderEngine struct {
	log *zap.Logger
}

// NewHeaderEngine constructs a HeaderEngine.
func NewHeaderEngine(log *zap.Logger) *HeaderEngine {
	return &HeaderEngine{log: log}
}

// Identify detects technologies from response headers.
func (e *HeaderEngine) Identify(_ context.Context, data *models.CollectedData) ([]models.Fingerprint, error) {
	if data == nil {
		return nil, fmt.Errorf("fingerprint: nil collected data")
	}

	var fps []models.Fingerprint

	header := func(name string) string {
		vals := data.Headers[name]
		if len(vals) == 0 {
			// try canonical form
			for k, v := range data.Headers {
				if strings.EqualFold(k, name) && len(v) > 0 {
					return v[0]
				}
			}
			return ""
		}
		return vals[0]
	}

	if v := header("Server"); v != "" {
		fps = append(fps, detectServer(v)...)
	}
	if v := header("X-Powered-By"); v != "" {
		fps = append(fps, detectPoweredBy(v)...)
	}
	if v := header("Via"); v != "" {
		if fp, ok := detectCDN(v); ok {
			fps = append(fps, fp)
		}
	}
	if v := header("X-Generator"); v != "" {
		fps = append(fps, models.Fingerprint{
			Category:   "cms",
			Name:       v,
			Confidence: 0.9,
			Evidence:   "X-Generator: " + v,
		})
	}
	if v := header("CF-Ray"); v != "" {
		fps = append(fps, models.Fingerprint{
			Category:   "cdn",
			Name:       "Cloudflare",
			Confidence: 0.99,
			Evidence:   "CF-Ray: " + v,
		})
	}
	if v := header("X-Amz-Cf-Id"); v != "" {
		fps = append(fps, models.Fingerprint{
			Category:   "cdn",
			Name:       "AWS CloudFront",
			Confidence: 0.99,
			Evidence:   "X-Amz-Cf-Id: " + v,
		})
	}
	if v := header("X-Vercel-Id"); v != "" {
		fps = append(fps, models.Fingerprint{
			Category:   "cdn",
			Name:       "Vercel",
			Confidence: 0.99,
			Evidence:   "X-Vercel-Id: " + v,
		})
	}
	if v := header("X-AspNet-Version"); v != "" {
		fps = append(fps, models.Fingerprint{
			Category:   "framework",
			Name:       "ASP.NET",
			Version:    v,
			Confidence: 0.98,
			Evidence:   "X-AspNet-Version: " + v,
		})
	}

	e.log.Debug("fingerprinted",
		zap.String("url", data.Target.URL),
		zap.Int("count", len(fps)))
	return fps, nil
}

func detectServer(server string) []models.Fingerprint {
	l := strings.ToLower(server)
	var fps []models.Fingerprint
	switch {
	case strings.Contains(l, "nginx"):
		fps = append(fps, models.Fingerprint{Category: "server", Name: "nginx",
			Version: extractVersion(server), Confidence: 0.95, Evidence: "Server: " + server})
	case strings.Contains(l, "apache"):
		fps = append(fps, models.Fingerprint{Category: "server", Name: "Apache",
			Version: extractVersion(server), Confidence: 0.95, Evidence: "Server: " + server})
	case strings.Contains(l, "microsoft-iis"):
		fps = append(fps, models.Fingerprint{Category: "server", Name: "IIS",
			Version: extractVersion(server), Confidence: 0.95, Evidence: "Server: " + server})
	case strings.Contains(l, "litespeed"):
		fps = append(fps, models.Fingerprint{Category: "server", Name: "LiteSpeed",
			Version: extractVersion(server), Confidence: 0.95, Evidence: "Server: " + server})
	case strings.Contains(l, "caddy"):
		fps = append(fps, models.Fingerprint{Category: "server", Name: "Caddy",
			Version: extractVersion(server), Confidence: 0.95, Evidence: "Server: " + server})
	case strings.Contains(l, "openresty"):
		fps = append(fps, models.Fingerprint{Category: "server", Name: "OpenResty",
			Version: extractVersion(server), Confidence: 0.95, Evidence: "Server: " + server})
	case strings.Contains(l, "envoy"):
		fps = append(fps, models.Fingerprint{Category: "server", Name: "Envoy",
			Version: extractVersion(server), Confidence: 0.95, Evidence: "Server: " + server})
	case strings.Contains(l, "cloudflare"):
		fps = append(fps, models.Fingerprint{Category: "cdn", Name: "Cloudflare",
			Confidence: 0.99, Evidence: "Server: " + server})
	default:
		if server != "" {
			fps = append(fps, models.Fingerprint{Category: "server", Name: server,
				Version: extractVersion(server), Confidence: 0.6, Evidence: "Server: " + server})
		}
	}
	return fps
}

func detectPoweredBy(xpb string) []models.Fingerprint {
	l := strings.ToLower(xpb)
	var fps []models.Fingerprint
	switch {
	case strings.Contains(l, "php"):
		fps = append(fps, models.Fingerprint{Category: "language", Name: "PHP",
			Version: extractVersion(xpb), Confidence: 0.95, Evidence: "X-Powered-By: " + xpb})
	case strings.Contains(l, "express"):
		fps = append(fps, models.Fingerprint{Category: "framework", Name: "Express",
			Version: extractVersion(xpb), Confidence: 0.9, Evidence: "X-Powered-By: " + xpb})
	case strings.Contains(l, "asp.net"):
		fps = append(fps, models.Fingerprint{Category: "framework", Name: "ASP.NET",
			Version: extractVersion(xpb), Confidence: 0.95, Evidence: "X-Powered-By: " + xpb})
	case strings.Contains(l, "next.js"):
		fps = append(fps, models.Fingerprint{Category: "framework", Name: "Next.js",
			Version: extractVersion(xpb), Confidence: 0.95, Evidence: "X-Powered-By: " + xpb})
	default:
		if xpb != "" {
			fps = append(fps, models.Fingerprint{Category: "framework", Name: xpb,
				Version: extractVersion(xpb), Confidence: 0.7, Evidence: "X-Powered-By: " + xpb})
		}
	}
	return fps
}

func detectCDN(via string) (models.Fingerprint, bool) {
	l := strings.ToLower(via)
	switch {
	case strings.Contains(l, "cloudflare"):
		return models.Fingerprint{Category: "cdn", Name: "Cloudflare", Confidence: 0.9, Evidence: "Via: " + via}, true
	case strings.Contains(l, "akamai"):
		return models.Fingerprint{Category: "cdn", Name: "Akamai", Confidence: 0.9, Evidence: "Via: " + via}, true
	case strings.Contains(l, "fastly"):
		return models.Fingerprint{Category: "cdn", Name: "Fastly", Confidence: 0.9, Evidence: "Via: " + via}, true
	case strings.Contains(l, "varnish"):
		return models.Fingerprint{Category: "cdn", Name: "Varnish", Confidence: 0.85, Evidence: "Via: " + via}, true
	case strings.Contains(l, "cloudfront"):
		return models.Fingerprint{Category: "cdn", Name: "AWS CloudFront", Confidence: 0.9, Evidence: "Via: " + via}, true
	default:
		return models.Fingerprint{}, false
	}
}

// extractVersion pulls the first /version token from a string.
func extractVersion(s string) string {
	parts := strings.Fields(s)
	for _, p := range parts {
		if idx := strings.Index(p, "/"); idx >= 0 && idx < len(p)-1 {
			return p[idx+1:]
		}
	}
	return ""
}
