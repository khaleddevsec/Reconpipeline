package tests

import (
	"testing"

	"github.com/khaleddevsec/Reconpipeline/internal/scope"
)

func TestNormalise_BareDomain(t *testing.T) {
	target, err := scope.Normalise("example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.Domain != "example.com" {
		t.Errorf("expected domain 'example.com', got %q", target.Domain)
	}
}

func TestNormalise_HTTPS(t *testing.T) {
	target, err := scope.Normalise("https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.Domain != "example.com" {
		t.Errorf("expected domain 'example.com', got %q", target.Domain)
	}
	if target.Scheme != "https" {
		t.Errorf("expected scheme 'https', got %q", target.Scheme)
	}
}

func TestNormalise_HTTP(t *testing.T) {
	target, err := scope.Normalise("http://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.Domain != "example.com" {
		t.Errorf("expected domain 'example.com', got %q", target.Domain)
	}
	if target.Scheme != "http" {
		t.Errorf("expected scheme 'http', got %q", target.Scheme)
	}
}

func TestNormalise_Subdomain(t *testing.T) {
	target, err := scope.Normalise("api.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.Domain != "api.example.com" {
		t.Errorf("expected domain 'api.example.com', got %q", target.Domain)
	}
}

func TestNormalise_EmptyTarget(t *testing.T) {
	_, err := scope.Normalise("")
	if err == nil {
		t.Error("expected error for empty target, got nil")
	}
}

func TestInScope_SubdomainInScope(t *testing.T) {
	target, _ := scope.Normalise("example.com")
	if !scope.InScope("https://api.example.com/v1/endpoint", target) {
		t.Error("expected api.example.com to be in scope of example.com")
	}
}

func TestInScope_RootInScope(t *testing.T) {
	target, _ := scope.Normalise("example.com")
	if !scope.InScope("https://example.com/", target) {
		t.Error("expected example.com to be in scope of example.com")
	}
}

func TestInScope_OutOfScope(t *testing.T) {
	target, _ := scope.Normalise("example.com")
	if scope.InScope("https://evil.com/", target) {
		t.Error("expected evil.com to be out of scope of example.com")
	}
}

func TestInScope_SimilarDomainOutOfScope(t *testing.T) {
	target, _ := scope.Normalise("example.com")
	// notexample.com must not be in scope.
	if scope.InScope("https://notexample.com/", target) {
		t.Error("expected notexample.com to be out of scope")
	}
}

func TestSafeFilename_Valid(t *testing.T) {
	name, err := scope.SafeFilename("example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "example.com" {
		t.Errorf("expected 'example.com', got %q", name)
	}
}

func TestSafeFilename_PathTraversal(t *testing.T) {
	_, err := scope.SafeFilename("../../etc/passwd")
	if err == nil {
		t.Error("expected error for path traversal, got nil")
	}
}

func TestSafeFilename_AbsolutePath(t *testing.T) {
	_, err := scope.SafeFilename("/etc/passwd")
	if err == nil {
		t.Error("expected error for absolute path, got nil")
	}
}

func TestRootDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"api.example.com", "example.com"},
		{"v2.api.example.com", "example.com"},
		{"sub.sub.sub.example.co.uk", "example.co.uk"},
		{"www.ingenium.co.th", "ingenium.co.th"},
	}
	for _, tt := range tests {
		got := scope.RootDomain(tt.input)
		if got != tt.expected {
			t.Errorf("RootDomain(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestScopePolicy_LookalikeAndBypassAttempts(t *testing.T) {
	target, err := scope.Normalise("example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	policy := scope.NewPolicy(target, "internal.example.com", "10.0.0.0/8")

	bypasses := []string{
		"example.com.attacker.test",
		"example.com.evil.com",
		"attacker-example.com",
		"attackerexample.com",
		"internal.example.com",
		"sub.internal.example.com",
		"evil.com",
		"10.1.2.3",
		"127.0.0.1",
		"169.254.169.254",
	}

	for _, bypass := range bypasses {
		if policy.IsHostInScope(bypass) {
			t.Errorf("Security check failed: host %q was permitted under policy, expected rejected", bypass)
		}
	}

	validHosts := []string{
		"example.com",
		"api.example.com",
		"app.v1.example.com",
	}
	for _, vh := range validHosts {
		if !policy.IsHostInScope(vh) {
			t.Errorf("Valid host %q was rejected under policy, expected permitted", vh)
		}
	}
}

func TestScopePolicy_URLSchemesAndExclusions(t *testing.T) {
	target, _ := scope.Normalise("example.com")
	policy := scope.NewPolicy(target, "dev.example.com")

	tests := []struct {
		url      string
		inScope  bool
	}{
		{"https://example.com/api/v1", true},
		{"http://sub.example.com/login", true},
		{"https://dev.example.com/test", false}, // explicitly excluded
		{"https://sub.dev.example.com/test", false}, // subdomain of excluded
		{"javascript:alert(1)", false},
		{"file:///etc/passwd", false},
		{"ftp://example.com/files", false},
		{"https://example.com.attacker.com/path", false},
		{"https://127.0.0.1/status", false},
		{"https://169.254.169.254/latest/meta-data/", false},
	}

	for _, tt := range tests {
		got := policy.IsURLInScope(tt.url)
		if got != tt.inScope {
			t.Errorf("IsURLInScope(%q) = %v, want %v", tt.url, got, tt.inScope)
		}
	}
}
