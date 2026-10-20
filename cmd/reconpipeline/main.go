// Reconpipeline - Automated Reconnaissance Pipeline
// Made by khaleddevsec
// https://github.com/khaleddevsec/Reconpipeline
package main

import (
	"fmt"
	"os"

	"github.com/khaleddevsec/Reconpipeline/internal/cli"
)

func main() {
	// Normalize common single-dash flags so users running flags like -version, -help, or -url do not hit shorthand errors
	knownFlags := map[string]string{
		"-version":  "--version",
		"-help":     "--help",
		"-doctor":   "--doctor",
		"-update":   "--update",
		"-resume":   "--resume",
		"-quiet":    "--quiet",
		"-verbose":  "--verbose",
		"-dry-run":  "--dry-run",
		"-no-cache": "--no-cache",
		"-no-color": "--no-color",
		"-profile":  "--profile",
		"-mode":     "--mode",
		"-output":   "--output",
		"-timeout":  "--timeout",
		"-threads":  "--threads",
		"-workers":  "--workers",
		"-url":      "--url",
		"-target":   "--target",
		"-list":     "--list",
	}
	for i := 1; i < len(os.Args); i++ {
		if mapped, ok := knownFlags[os.Args[i]]; ok {
			os.Args[i] = mapped
		}
	}

	root := cli.New()
	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
