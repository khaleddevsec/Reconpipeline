package tests

import (
	"testing"
	"time"

	"github.com/khaleddevsec/Reconpipeline/internal/config"
)

func TestConfig_Defaults(t *testing.T) {
	cfg := config.NewConfig()
	if cfg.UserSettings.DefaultProfile != "full" {
		t.Errorf("expected default profile 'full', got %q", cfg.UserSettings.DefaultProfile)
	}
	if cfg.UserSettings.DefaultThreads != 10 {
		t.Errorf("expected default threads 10, got %d", cfg.UserSettings.DefaultThreads)
	}
	if !cfg.UserSettings.CacheEnabled {
		t.Error("expected cache to be enabled by default")
	}
}

func TestConfig_Profiles(t *testing.T) {
	full := config.GetProfile("full")
	if full.Mode != "full" || full.Threads != 10 {
		t.Errorf("unexpected full profile settings: %+v", full)
	}

	fast := config.GetProfile("fast")
	if fast.CrawlDepth != 1 || fast.Timeout != 15*time.Minute {
		t.Errorf("unexpected fast profile settings: %+v", fast)
	}

	passive := config.GetProfile("passive")
	if passive.Mode != "passive" || passive.CrawlDepth != 0 {
		t.Errorf("unexpected passive profile settings: %+v", passive)
	}
}

func TestConfig_ValidateOptions(t *testing.T) {
	// Valid options
	if err := config.ValidateOptions(10, "30m", "full", "full"); err != nil {
		t.Errorf("expected valid options, got: %v", err)
	}
	if err := config.ValidateOptions(15, "1h", "passive", "passive"); err != nil {
		t.Errorf("expected valid options, got: %v", err)
	}

	// Invalid threads <= 0
	if err := config.ValidateOptions(0, "30m", "full", "full"); err == nil {
		t.Error("expected error for threads <= 0")
	}

	// Invalid threads > 200
	if err := config.ValidateOptions(500, "30m", "full", "full"); err == nil {
		t.Error("expected error for threads > 200")
	}

	// Invalid timeout format
	if err := config.ValidateOptions(10, "invalid-time", "full", "full"); err == nil {
		t.Error("expected error for invalid timeout format")
	}

	// Invalid mode
	if err := config.ValidateOptions(10, "30m", "invalid-mode", "full"); err == nil {
		t.Error("expected error for invalid mode")
	}

	// Invalid profile
	if err := config.ValidateOptions(10, "30m", "full", "unknown-profile"); err == nil {
		t.Error("expected error for unknown profile")
	}
}
