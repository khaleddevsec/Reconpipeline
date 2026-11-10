package collector

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"

	"github.com/khaleddevsec/Reconpipeline/internal/config"
	"github.com/khaleddevsec/Reconpipeline/models"
	"go.uber.org/zap"
)

type redirectCtxKey struct{}

// HTTPCollector implements Collector using the standard net/http client.
type HTTPCollector struct {
	cfg            *config.Config
	client         *http.Client
	insecureClient *http.Client
	log            *zap.Logger
}

// NewHTTPCollector constructs an HTTPCollector with the provided config and logger.
func NewHTTPCollector(cfg *config.Config, log *zap.Logger) (*HTTPCollector, error) {
	proxyFunc := http.ProxyFromEnvironment
	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("collector: invalid proxy URL %q: %w", cfg.Proxy, err)
		}
		proxyFunc = http.ProxyURL(proxyURL)
	}

	timeout := time.Duration(cfg.TimeoutSecs) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	buildClient := func(skipVerify bool) *http.Client {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS10,
				InsecureSkipVerify: skipVerify, //nolint:gosec // required for security assessment of self-signed/expired certs
			},
			Proxy:                  proxyFunc,
			MaxResponseHeaderBytes: 1 << 20, // 1 MB limit against header bombs
			ResponseHeaderTimeout:  timeout,
		}
		return &http.Client{
			Timeout:   timeout,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) > 0 {
					if hops, ok := via[0].Context().Value(redirectCtxKey{}).(*[]models.Redirect); ok && hops != nil {
						prev := via[len(via)-1]
						code := 0
						if req.Response != nil {
							code = req.Response.StatusCode
						}
						*hops = append(*hops, models.Redirect{
							From:       prev.URL.String(),
							To:         req.URL.String(),
							StatusCode: code,
						})
					}
				}
				if len(via) >= 10 {
					return fmt.Errorf("collector: stopped after 10 redirects")
				}
				return nil
			},
		}
	}

	return &HTTPCollector{
		cfg:            cfg,
		client:         buildClient(cfg.Insecure),
		insecureClient: buildClient(true),
		log:            log,
	}, nil
}

// Collect performs an HTTP GET against target and returns raw metadata.
func (c *HTTPCollector) Collect(ctx context.Context, target models.Target) (*models.CollectedData, error) {
	if c.cfg.BlockPrivateIPs {
		if err := validatePublicTarget(target.URL); err != nil {
			return nil, err
		}
	}

	maxAttempts := 1
	if c.cfg.Retries > 0 {
		maxAttempts = c.cfg.Retries
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		data, err := c.doCollect(ctx, target, c.client)
		if err == nil {
			return data, nil
		}
		// If certificate verification failed (expired, self-signed, untrusted root),
		// fallback to insecureClient so we still inspect the bad cert and report findings.
		if strings.Contains(err.Error(), "x509:") || strings.Contains(err.Error(), "certificate") {
			if data, fallbackErr := c.doCollect(ctx, target, c.insecureClient); fallbackErr == nil {
				return data, nil
			}
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
		if attempt < maxAttempts {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt*100) * time.Millisecond):
			}
		}
	}
	return nil, lastErr
}

func (c *HTTPCollector) doCollect(ctx context.Context, target models.Target, client *http.Client) (*models.CollectedData, error) {
	var redirects []models.Redirect
	reqCtx := context.WithValue(ctx, redirectCtxKey{}, &redirects)

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("collector: build request for %q: %w", target.URL, err)
	}
	req.Header.Set("User-Agent", c.cfg.UserAgent)
	for k, v := range c.cfg.Headers {
		req.Header.Set(k, v)
	}

	// timing probes
	var (
		dnsStart, dnsDone time.Time
		tcpStart, tcpDone time.Time
		tlsStart, tlsDone time.Time
		firstByte         time.Time
		tlsState          *tls.ConnectionState
	)

	trace := &httptrace.ClientTrace{
		DNSStart:          func(_ httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:           func(_ httptrace.DNSDoneInfo) { dnsDone = time.Now() },
		ConnectStart:      func(_, _ string) { tcpStart = time.Now() },
		ConnectDone:       func(_, _ string, _ error) { tcpDone = time.Now() },
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			tlsDone = time.Now()
			if err == nil {
				tlsState = &state
			}
		},
		GotFirstResponseByte: func() { firstByte = time.Now() },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	reqStart := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("collector: request %q: %w", target.URL, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // cap body at 64 KB
	total := time.Since(reqStart)

	if tlsState == nil && resp.TLS != nil {
		tlsState = resp.TLS
	}

	data := &models.CollectedData{
		Target:       target,
		StatusCode:   resp.StatusCode,
		Headers:      map[string][]string(resp.Header),
		Redirects:    redirects,
		RawBody:      body,
		HTTPVersion:  resp.Proto,
		Compression:  resp.Header.Get("Content-Encoding"),
		ServerBanner: resp.Header.Get("Server"),
		CollectedAt:  time.Now(),
		Timing: models.TimingInfo{
			DNSLookup:    safeDur(dnsStart, dnsDone),
			TCPConnect:   safeDur(tcpStart, tcpDone),
			TLSHandshake: safeDur(tlsStart, tlsDone),
			FirstByte:    safeDur(reqStart, firstByte),
			Total:        total,
		},
	}

	for _, rc := range resp.Cookies() {
		data.Cookies = append(data.Cookies, &models.Cookie{
			Name:     rc.Name,
			Value:    rc.Value,
			Secure:   rc.Secure,
			HttpOnly: rc.HttpOnly,
			SameSite: sameSiteString(rc.SameSite),
			Path:     rc.Path,
			Domain:   rc.Domain,
			Expires:  rc.Expires,
		})
	}

	if tlsState != nil {
		data.TLS = mapTLSState(tlsState)
	}

	c.log.Debug("collected",
		zap.String("url", target.URL),
		zap.Int("status", resp.StatusCode),
		zap.Int("redirects", len(redirects)),
		zap.Duration("total", total))
	return data, nil
}

func validatePublicTarget(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("collector: parse URL: %w", err)
	}
	host := u.Hostname()
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("collector: resolve host %q: %w", host, err)
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("collector: target %q resolves to blocked private/internal IP %s", host, ip.String())
		}
	}
	return nil
}

func mapTLSState(state *tls.ConnectionState) *models.TLSInfo {
	info := &models.TLSInfo{
		Version:     tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
	}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info.Subject = cert.Subject.String()
		info.Issuer = cert.Issuer.String()
		info.NotBefore = cert.NotBefore
		info.NotAfter = cert.NotAfter
		info.SelfSigned = cert.Subject.String() == cert.Issuer.String()
		info.SANs = cert.DNSNames
		info.CertificateChain = len(state.PeerCertificates)
	}
	return info
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown(0x%04x)", v)
	}
}

func sameSiteString(s http.SameSite) string {
	switch s {
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return ""
	}
}

func safeDur(start, end time.Time) time.Duration {
	if start.IsZero() || end.IsZero() {
		return 0
	}
	return end.Sub(start)
}

// weakCiphers contains cipher suite substrings considered weak.
var weakCiphers = []string{"RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "ANON"}

func isWeakCipher(cipher string) bool {
	upper := strings.ToUpper(cipher)
	for _, w := range weakCiphers {
		if strings.Contains(upper, w) {
			return true
		}
	}
	return false
}
