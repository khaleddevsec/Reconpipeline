// Package version defines the application version.
// The Version variable is injected at build time via ldflags:
//
//	go build -ldflags "-X github.com/khaleddevsec/Reconpipeline/internal/version.Version=v2.6.0"
package version

// Version is the current semantic version of Reconpipeline.
// Injected at build time via -ldflags "-X ...".
var Version = "v2.6.0"
