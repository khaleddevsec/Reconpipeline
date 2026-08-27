package tests

import (
	"testing"

	"github.com/frozeniceee/Reconpipeline/internal/updater"
	"github.com/frozeniceee/Reconpipeline/internal/version"
)

func TestVersion_NotEmpty(t *testing.T) {
	if version.Version == "" {
		t.Error("version.Version must not be empty")
	}
}

func TestVersion_HasVPrefix(t *testing.T) {
	v := version.Version
	if len(v) == 0 || v[0] != 'v' {
		t.Errorf("version %q must start with 'v'", v)
	}
}

func TestIsNewer_NewerMajor(t *testing.T) {
	if !updater.IsNewer("v3.0.0", "v2.5.0") {
		t.Error("v3.0.0 should be newer than v2.5.0")
	}
}

func TestIsNewer_NewerMinor(t *testing.T) {
	if !updater.IsNewer("v2.6.0", "v2.5.0") {
		t.Error("v2.6.0 should be newer than v2.5.0")
	}
}

func TestIsNewer_NewerPatch(t *testing.T) {
	if !updater.IsNewer("v2.5.1", "v2.5.0") {
		t.Error("v2.5.1 should be newer than v2.5.0")
	}
}

func TestIsNewer_Equal(t *testing.T) {
	if updater.IsNewer("v2.5.0", "v2.5.0") {
		t.Error("equal versions should not be 'newer'")
	}
}

func TestIsNewer_OlderMajor(t *testing.T) {
	if updater.IsNewer("v1.9.9", "v2.5.0") {
		t.Error("v1.9.9 should not be newer than v2.5.0")
	}
}

func TestParseVersion(t *testing.T) {
	v := updater.ParseVersion("v2.5.3")
	if v[0] != 2 || v[1] != 5 || v[2] != 3 {
		t.Errorf("ParseVersion(\"v2.5.3\") = %v, want [2 5 3]", v)
	}
}
