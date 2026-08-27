// Package version defines the application version.
// The Version variable is injected at build time via ldflags:
//
//	go build -ldflags "-X github.com/frozeniceee/Reconpipeline/internal/version.Version=v2.5.0"
package version

// Version is the authoritative application version.
// It is set via ldflags at build time. Do not hardcode this elsewhere.
var Version = "v2.5.0"
