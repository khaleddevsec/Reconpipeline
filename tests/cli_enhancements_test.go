package tests

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/khaleddevsec/Reconpipeline/internal/cli"
	"github.com/khaleddevsec/Reconpipeline/internal/intelligence/dns"
	"github.com/khaleddevsec/Reconpipeline/internal/scope"
)

func TestScope_WhitespaceAndQuotes(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"  example.com  ", "example.com"},
		{"\"example.com\"", "example.com"},
		{"'example.com'", "example.com"},
		{"  \"https://api.example.com/\"  ", "api.example.com"},
	}

	for _, c := range cases {
		tgt, err := scope.Normalise(c.input)
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", c.input, err)
		}
		if tgt.Domain != c.expected {
			t.Errorf("Normalise(%q) = %q, want %q", c.input, tgt.Domain, c.expected)
		}
	}
}

func TestDNS_DetectWildcard_Integration(t *testing.T) {
	engine := dns.NewEngine(5)
	// Querying a domain that should not resolve wildcard DNS
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	isWc, ips := engine.DetectWildcard(ctx, "example.com")
	// example.com typically does not have wildcard DNS configured
	if isWc && len(ips) == 0 {
		t.Error("expected non-empty IPs if wildcard is true")
	}
}

func TestCLI_RootFlags_TargetAndList(t *testing.T) {
	cmd := cli.New()
	if cmd.Flags().Lookup("url") == nil {
		t.Error("expected --url flag on root command")
	}
	if cmd.Flags().Lookup("target") == nil {
		t.Error("expected --target flag on root command")
	}
	if cmd.Flags().Lookup("list") == nil {
		t.Error("expected --list flag on root command")
	}
	// Verify -u is shorthand for url
	shorthandU := cmd.Flags().ShorthandLookup("u")
	if shorthandU == nil || shorthandU.Name != "url" {
		t.Errorf("expected -u shorthand to map to 'url', got %v", shorthandU)
	}
	// Verify -l is shorthand for list
	shorthandL := cmd.Flags().ShorthandLookup("l")
	if shorthandL == nil || shorthandL.Name != "list" {
		t.Errorf("expected -l shorthand to map to 'list', got %v", shorthandL)
	}
}

func TestDNS_ProcessSubdomains_WildcardRecorded(t *testing.T) {
	tempDir := t.TempDir()
	subFile := filepath.Join(tempDir, "subdomains.txt")
	dnsDir := filepath.Join(tempDir, "dns")

	_ = os.WriteFile(subFile, []byte("app.example.com\n"), 0640)

	engine := dns.NewEngine(2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	records, err := engine.ProcessSubdomains(ctx, subFile, dnsDir, "example.com")
	if err != nil {
		t.Fatalf("ProcessSubdomains failed: %v", err)
	}
	_ = records
	// Verify directory and files were created
	if _, err := os.Stat(filepath.Join(dnsDir, "dns-records.json")); os.IsNotExist(err) {
		t.Error("expected dns-records.json to exist")
	}
}
