// Package scope validates and normalises scan targets.
// It enforces strict domain scope to prevent unintended scope expansion.
package scope

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// validDomainRE matches a safe, normalised domain name.
var validDomainRE = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)

// Target holds the normalised target and scope information.
type Target struct {
	// Raw is the original input string.
	Raw string
	// Domain is the normalised root domain (e.g. "example.com").
	Domain string
	// Scheme is the detected scheme, if any (http/https).
	Scheme string
}

// Normalise parses and normalises the user-supplied target string.
// It accepts bare domains (example.com) and URLs (https://example.com).
func Normalise(input string) (*Target, error) {
	input = strings.TrimSpace(input)
	input = strings.Trim(input, `"'`)
	if input == "" {
		return nil, fmt.Errorf("target cannot be empty")
	}

	t := &Target{Raw: input}

	// Add a temporary scheme if missing so url.Parse works.
	s := input
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		s = "https://" + s
	}

	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: %w", input, err)
	}

	// Capture the original scheme if the user supplied one.
	if strings.HasPrefix(input, "https://") {
		t.Scheme = "https"
	} else if strings.HasPrefix(input, "http://") {
		t.Scheme = "http"
	}

	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("could not determine host from target %q", input)
	}

	t.Domain = strings.ToLower(host)

	if err := validateDomain(t.Domain); err != nil {
		return nil, err
	}

	return t, nil
}

// Normalize is an alias for Normalise for American English compatibility.
func Normalize(input string) (*Target, error) {
	return Normalise(input)
}

// validateDomain checks that a domain is safe to use as a scan target.
func validateDomain(domain string) error {
	if len(domain) == 0 || len(domain) > 253 {
		return fmt.Errorf("domain %q has invalid length", domain)
	}
	if !validDomainRE.MatchString(domain) {
		return fmt.Errorf("domain %q contains invalid characters", domain)
	}
	// Reject IP addresses
	if isIPAddress(domain) {
		return fmt.Errorf("IP address targets are not currently supported: %q", domain)
	}
	return nil
}

// isIPAddress returns true if the domain looks like an IPv4 or IPv6 address.
func isIPAddress(s string) bool {
	ipv4RE := regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	return ipv4RE.MatchString(s) || strings.Contains(s, ":")
}

// Policy encapsulates all authorization and scoping rules for a scan.
type Policy struct {
	Target          *Target
	AllowedDomains  []string
	ExcludedHosts   []string
	ExcludedCIDRs   []*net.IPNet
	AllowedPorts    []int
	AllowPrivateIPs bool
}

// NewPolicy creates a Policy with default restrictions (private IPs disallowed).
func NewPolicy(target *Target, exclusions ...string) *Policy {
	p := &Policy{
		Target:          target,
		AllowPrivateIPs: false,
	}
	if target != nil && target.Domain != "" {
		p.AllowedDomains = []string{target.Domain}
	}
	for _, excl := range exclusions {
		excl = strings.TrimSpace(strings.ToLower(excl))
		if excl == "" {
			continue
		}
		if _, ipNet, err := net.ParseCIDR(excl); err == nil {
			p.ExcludedCIDRs = append(p.ExcludedCIDRs, ipNet)
		} else {
			p.ExcludedHosts = append(p.ExcludedHosts, excl)
		}
	}
	return p
}

// IsPrivateOrRestrictedIP returns true if the IP is loopback, link-local, private,
// multicast, unspecified, or cloud metadata (169.254.169.254).
func IsPrivateOrRestrictedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return true
	}
	if ip.Equal(net.ParseIP("169.254.169.254")) {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 0 || ip4[0] == 255 {
			return true
		}
	}
	return false
}

// IsHostInScope evaluates whether a hostname is authorized.
func (p *Policy) IsHostInScope(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return false
	}

	// Strip port if present
	if h, portStr, err := net.SplitHostPort(host); err == nil {
		host = h
		if len(p.AllowedPorts) > 0 {
			if port, pErr := strconv.Atoi(portStr); pErr == nil {
				portAllowed := false
				for _, ap := range p.AllowedPorts {
					if ap == port {
						portAllowed = true
						break
					}
				}
				if !portAllowed {
					return false
				}
			}
		}
	}

	// Reject IP address targets if private/restricted
	if ip := net.ParseIP(host); ip != nil {
		if !p.AllowPrivateIPs && IsPrivateOrRestrictedIP(ip) {
			return false
		}
		for _, cidr := range p.ExcludedCIDRs {
			if cidr.Contains(ip) {
				return false
			}
		}
		return false
	}

	// Check exclusion list (exact match or subdomain of excluded host)
	for _, excl := range p.ExcludedHosts {
		if host == excl || strings.HasSuffix(host, "."+excl) {
			return false
		}
	}

	// Check permitted domains
	for _, domain := range p.AllowedDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}

	return false
}

// IsURLInScope checks whether a URL is valid, uses http/https, and matches the authorized scope.
func (p *Policy) IsURLInScope(rawURL string) bool {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false
	}

	// Port check if present in URL
	if u.Port() != "" && len(p.AllowedPorts) > 0 {
		if port, err := strconv.Atoi(u.Port()); err == nil {
			allowed := false
			for _, ap := range p.AllowedPorts {
				if ap == port {
					allowed = true
					break
				}
			}
			if !allowed {
				return false
			}
		}
	}

	return p.IsHostInScope(host)
}

// IsIPAllowed validates if an IP address is permissible according to policy.
func (p *Policy) IsIPAllowed(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if !p.AllowPrivateIPs && IsPrivateOrRestrictedIP(ip) {
		return false
	}
	for _, cidr := range p.ExcludedCIDRs {
		if cidr.Contains(ip) {
			return false
		}
	}
	return true
}

// ValidateHostResolution performs a DNS lookup to ensure the host does not resolve to forbidden IPs.
func (p *Policy) ValidateHostResolution(ctx context.Context, host string) ([]string, error) {
	host = strings.TrimSpace(strings.ToLower(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	if !p.IsHostInScope(host) {
		return nil, fmt.Errorf("host %q is out of scope", host)
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(lookupCtx, "ip", host)
	if err != nil {
		return nil, err
	}

	var allowedIPs []string
	for _, ip := range ips {
		if !p.IsIPAllowed(ip) {
			return nil, fmt.Errorf("host %q resolves to restricted IP %s", host, ip.String())
		}
		allowedIPs = append(allowedIPs, ip.String())
	}
	return allowedIPs, nil
}

// InScope returns true if the given URL is within the target's domain scope.
// Only subdomains of the root domain are considered in-scope.
func InScope(rawURL string, target *Target) bool {
	if target == nil {
		return false
	}
	p := NewPolicy(target)
	return p.IsURLInScope(rawURL)
}

// SafeFilename converts a domain to a safe directory/filename component.
// Rejects path traversal attempts.
func SafeFilename(domain string) (string, error) {
	// Disallow any path separators or traversal sequences.
	if strings.Contains(domain, "/") ||
		strings.Contains(domain, "\\") ||
		strings.Contains(domain, "..") ||
		strings.HasPrefix(domain, ".") {
		return "", fmt.Errorf("unsafe domain name for filesystem use: %q", domain)
	}
	return domain, nil
}

// RootDomain extracts the root registrable domain from a potentially multi-level subdomain.
// Handles multi-part ccTLDs like .co.th, .co.uk, .com.au, .co.in, etc.
func RootDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}

	// Check for 2-part public suffixes (e.g. co.uk, com.au, co.th, org.uk, net.au, etc.)
	if len(parts) >= 3 {
		secondLast := parts[len(parts)-2]
		last := parts[len(parts)-1]
		if len(last) == 2 { // ccTLD (uk, th, au, in, jp, br, etc.)
			switch secondLast {
			case "co", "com", "org", "net", "edu", "gov", "ac", "or", "go", "ne", "gen", "in":
				return strings.Join(parts[len(parts)-3:], ".")
			}
		}
	}

	return strings.Join(parts[len(parts)-2:], ".")
}
