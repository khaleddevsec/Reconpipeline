package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags "-X github.com/khaleddevsec/Reconpipeline/pkg/cli.Version=x.y.z".
var Version = "v1.0.0"

// SetVersion allows main packages to override the build-time version string.
func SetVersion(v string) {
	if v != "" {
		Version = v
	}
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print ThreatLens version",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Printf("ThreatLens %s\n", Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
