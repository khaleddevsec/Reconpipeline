// Package scope validates and normalises scan targets.
// It enforces strict domain scope to prevent unintended scope expansion.
package scope

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
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

	// Strip www. prefix for the root domain comparison, but keep host as-is.
	// The domain used for scope is the deepest registrable part.
	t.Domain = strings.ToLower(host)

	if err := validateDomain(t.Domain); err != nil {
		return nil, err
	}

	return t, nil
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

// InScope returns true if the given URL is within the target's domain scope.
// Only subdomains of the root domain are considered in-scope.
func InScope(rawURL string, target *Target) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false
	}

	rootDomain := target.Domain
	return host == rootDomain || strings.HasSuffix(host, "."+rootDomain)
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
