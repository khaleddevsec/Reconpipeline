package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/khaleddevsec/Reconpipeline/v2/models"
)

// NewID returns a cryptographically random 32-character hex ID.
func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// NormalizeURL parses raw into a models.Target, prepending https:// when no scheme is present.
func NormalizeURL(raw string) (models.Target, error) {
	// only prepend when there is no scheme separator in the input at all
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return models.Target{}, fmt.Errorf("utils: invalid URL %q: %w", raw, err)
	}
	if u.Host == "" {
		return models.Target{}, fmt.Errorf("utils: URL missing host: %q", raw)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return models.Target{}, fmt.Errorf("utils: unsupported scheme %q in %q (only http and https supported)", u.Scheme, raw)
	}

	port := 0
	if pStr := u.Port(); pStr != "" {
		if p, err := strconv.Atoi(pStr); err == nil && p > 0 && p <= 65535 {
			port = p
		} else {
			return models.Target{}, fmt.Errorf("utils: invalid port %q in %q", pStr, raw)
		}
	} else {
		if scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}

	return models.Target{
		URL:    u.String(),
		Scheme: scheme,
		Host:   u.Hostname(),
		Port:   port,
		Path:   u.Path,
	}, nil
}

// Truncate limits s to n runes, appending "…" when truncated.
func Truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}
