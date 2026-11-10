package parser

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/khaleddevsec/Reconpipeline/models"
	"go.uber.org/zap"
)

// securityHeaders are expected in every secure HTTP response.
var securityHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Permissions-Policy",
}

// weakProtocols lists TLS version strings considered insecure.
var weakProtocols = map[string]bool{
	"SSL 3.0": true,
	"TLS 1.0": true,
	"TLS 1.1": true,
}

// weakCiphers contains substrings indicating a weak cipher suite.
var weakCiphers = []string{"RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "ANON"}

// HTTPParser implements Parser for HTTP collected data.
type HTTPParser struct {
	log *zap.Logger
}

// NewHTTPParser constructs an HTTPParser.
func NewHTTPParser(log *zap.Logger) *HTTPParser {
	return &HTTPParser{log: log}
}

// Parse enriches CollectedData: marks missing or misconfigured security headers,
// flags weak TLS / expired certs, and annotates cookie issues.
func (p *HTTPParser) Parse(_ context.Context, data *models.CollectedData) (*models.CollectedData, error) {
	if data == nil {
		return nil, fmt.Errorf("parser: nil collected data")
	}

	if data.Headers == nil {
		data.Headers = make(map[string][]string)
	}

	// mark missing security headers by injecting sentinel values
	present := make(map[string]string, len(data.Headers))
	for k, vals := range data.Headers {
		if len(vals) > 0 {
			present[strings.ToLower(k)] = vals[0]
		} else {
			present[strings.ToLower(k)] = ""
		}
	}
	for _, h := range securityHeaders {
		if _, ok := present[strings.ToLower(h)]; !ok {
			data.Headers["_missing_"+strings.ToLower(h)] = []string{""}
		}
	}

	// check header value misconfigurations
	if hsts, ok := present["strict-transport-security"]; ok {
		lowerHSTS := strings.ToLower(hsts)
		if strings.Contains(lowerHSTS, "max-age=0") || !strings.Contains(lowerHSTS, "max-age=") {
			data.Headers["_missing_weak-strict-transport-security"] = []string{hsts}
		}
	}
	if csp, ok := present["content-security-policy"]; ok {
		lowerCSP := strings.ToLower(csp)
		if strings.Contains(lowerCSP, "unsafe-inline") || strings.Contains(lowerCSP, "unsafe-eval") || strings.Contains(lowerCSP, " *") {
			data.Headers["_missing_unsafe-content-security-policy"] = []string{csp}
		}
	}
	if cors, ok := present["access-control-allow-origin"]; ok {
		if strings.TrimSpace(cors) == "*" {
			data.Headers["_missing_permissive-cors"] = []string{cors}
		}
	}

	// analyse cookies
	for _, c := range data.Cookies {
		if !c.Secure {
			data.Headers["_missing_cookie-missing-secure"] = []string{c.Name}
		}
		if !c.HttpOnly {
			data.Headers["_missing_cookie-missing-httponly"] = []string{c.Name}
		}
		if c.SameSite == "" {
			data.Headers["_missing_cookie-missing-samesite"] = []string{c.Name}
		}
	}

	// analyse TLS
	if data.TLS != nil {
		data.TLS.WeakProtocol = weakProtocols[data.TLS.Version]
		data.TLS.WeakCipher = isWeakCipher(data.TLS.CipherSuite)
		data.TLS.SelfSigned = data.TLS.SelfSigned || (data.TLS.Subject != "" && data.TLS.Subject == data.TLS.Issuer)

		if !data.TLS.NotAfter.IsZero() && time.Now().After(data.TLS.NotAfter) {
			data.TLS.Expired = true
			data.Headers["_cert_expired"] = []string{"true"}
		}
	}

	p.log.Debug("parsed",
		zap.String("url", data.Target.URL),
		zap.Int("status", data.StatusCode))
	return data, nil
}

func isWeakCipher(cipher string) bool {
	upper := strings.ToUpper(cipher)
	for _, w := range weakCiphers {
		if strings.Contains(upper, w) {
			return true
		}
	}
	return false
}
