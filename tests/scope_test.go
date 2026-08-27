package tests

import (
	"testing"

	"github.com/frozeniceee/Reconpipeline/internal/scope"
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
		{"sub.sub.sub.example.co.uk", "co.uk"},
	}
	for _, tt := range tests {
		got := scope.RootDomain(tt.input)
		if got != tt.expected {
			t.Errorf("RootDomain(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
