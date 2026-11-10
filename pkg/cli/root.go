// Package cli implements the command-line interface for ThreatLens / Reconpipeline.
package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	logger    *zap.Logger
	cfgFile   string
	outputDir string
	verbosity string
	silent    bool
)

var rootCmd = &cobra.Command{
	Use:   "threatlens",
	Short: "ThreatLens (Reconpipeline) — cybersecurity intelligence engine",
	Long: `ThreatLens collects HTTP/TLS metadata and correlates findings with
MITRE ATT&CK, CAPEC, CWE, OWASP, and security best practices
to explain attack paths, risks, and mitigations.`,
	SilenceUsage: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return initLogger(verbosity, silent)
	},
}

// Execute is the CLI entry point called from main.
func Execute() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default: threatlens.yaml)")
	rootCmd.PersistentFlags().StringVarP(&outputDir, "output", "o", "./reports", "output directory for reports")
	rootCmd.PersistentFlags().StringVarP(&verbosity, "verbosity", "v", "info", "log level: debug | info | warn | error")
	rootCmd.PersistentFlags().BoolVarP(&silent, "silent", "s", false, "suppress log output")
}

func initLogger(level string, quiet bool) error {
	if quiet {
		logger = zap.NewNop()
		return nil
	}

	var cfg zap.Config
	if level == "debug" {
		cfg = zap.NewDevelopmentConfig()
	} else {
		cfg = zap.NewProductionConfig()
		switch level {
		case "warn":
			cfg.Level = zap.NewAtomicLevelAt(zapcore.WarnLevel)
		case "error":
			cfg.Level = zap.NewAtomicLevelAt(zapcore.ErrorLevel)
		default:
			cfg.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
		}
	}

	var err error
	logger, err = cfg.Build()
	if err != nil {
		return fmt.Errorf("logger: init: %w", err)
	}
	return nil
}

