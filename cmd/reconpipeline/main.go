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
	// Normalize common single-dash flags so users running -version or -help do not hit shorthand errors
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-version":
			os.Args[i] = "--version"
		case "-help":
			os.Args[i] = "--help"
		}
	}

	root := cli.New()
	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
