// Reconpipeline - Automated Reconnaissance Pipeline
// Made by frozeniceee
// https://github.com/frozeniceee/Reconpipeline
package main

import (
	"fmt"
	"os"

	"github.com/frozeniceee/Reconpipeline/internal/cli"
)

func main() {
	root := cli.New()
	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
