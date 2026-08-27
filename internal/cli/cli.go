// Package cli implements the Reconpipeline command-line interface.
package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/frozeniceee/Reconpipeline/internal/config"
	"github.com/frozeniceee/Reconpipeline/internal/dependencies"
	"github.com/frozeniceee/Reconpipeline/internal/logging"
	"github.com/frozeniceee/Reconpipeline/internal/pipeline"
	"github.com/frozeniceee/Reconpipeline/internal/reporting"
	"github.com/frozeniceee/Reconpipeline/internal/scope"
	"github.com/frozeniceee/Reconpipeline/internal/updater"
	"github.com/frozeniceee/Reconpipeline/internal/version"
	"github.com/frozeniceee/Reconpipeline/internal/workspace"
)

// logo is the ASCII art banner.
const logo = `
  ____                       ____  _             __
 |  _ \ ___  ___ ___  _ __  |  _ \(_)_ __   ___
 | |_) / _ \/ __/ _ \| '_ \ | |_) | | '_ \ / _ \
 |  _ <  __/ (_| (_) | | | ||  __/| | |_) |  __/
 |_| \_\___|\___\___/|_| |_||_|   |_| .__/ \___|
                                    |_|
`

// flags holds all CLI flag values.
var flags struct {
	output  string
	mode    string
	timeout string
	threads int
	resume  bool
	dryRun  bool
	quiet   bool
	verbose bool
}

// New builds and returns the root cobra command.
func New() *cobra.Command {
	root := &cobra.Command{
		Use:   "reconpipeline [target]",
		Short: "Reconpipeline - Automated Reconnaissance Pipeline",
		Long: `Reconpipeline - Automated Reconnaissance Pipeline

Usage:

    reconpipeline <target>

Commands:

    version       Show version
    update        Update Reconpipeline
    doctor        Check system and dependencies

Options:

    -h, --help
    -v, --version

    --resume
    --output <dir>
    --mode <mode>
    --dry-run

    --timeout <duration>
    --threads <number>

    --quiet
    --verbose`,
		Version:           version.Version,
		SilenceUsage:      true,
		SilenceErrors:     true,
		Args:              cobra.MaximumNArgs(1),
		RunE:              runMain,
		PersistentPreRunE: persistentPreRun,
	}

	// Flags.
	root.Flags().StringVarP(&flags.output, "output", "o", "", "Output directory for results")
	root.Flags().StringVar(&flags.mode, "mode", "full", "Scan mode: full, active, passive")
	root.Flags().StringVar(&flags.timeout, "timeout", "30m", "Scan timeout (e.g. 30m, 1h)")
	root.Flags().IntVar(&flags.threads, "threads", 10, "Concurrency level")
	root.Flags().BoolVar(&flags.resume, "resume", false, "Resume a previous scan")
	root.Flags().BoolVar(&flags.dryRun, "dry-run", false, "Show pipeline plan without executing")
	root.Flags().BoolVarP(&flags.quiet, "quiet", "q", false, "Minimal output")
	root.Flags().BoolVar(&flags.verbose, "verbose", false, "Detailed output")
	root.Flags().BoolP("update", "u", false, "Update Reconpipeline")
	root.Flags().BoolP("doctor", "", false, "Check system and dependencies")

	// Handle --update and --doctor as flags that invoke their commands.
	root.Flags().Lookup("update").Hidden = false
	root.Flags().Lookup("doctor").Hidden = false

	// Subcommands.
	root.AddCommand(versionCmd())
	root.AddCommand(updateCmd())
	root.AddCommand(doctorCmd())

	// Override version template.
	root.SetVersionTemplate(versionString() + "\n")

	return root
}

// persistentPreRun initialises logging for all commands.
func persistentPreRun(cmd *cobra.Command, args []string) error {
	cfg := config.NewConfig()
	level := logging.LevelNormal
	if flags.quiet {
		level = logging.LevelQuiet
	} else if flags.verbose {
		level = logging.LevelVerbose
	}
	_ = logging.Init(level, cfg.LogsDir)
	return nil
}

// runMain is the main entry point for reconpipeline <target>.
func runMain(cmd *cobra.Command, args []string) error {
	// Check --update / --doctor flags.
	if update, _ := cmd.Flags().GetBool("update"); update {
		return runUpdate(cmd, args)
	}
	if doctor, _ := cmd.Flags().GetBool("doctor"); doctor {
		return runDoctor(cmd, args)
	}

	if len(args) == 0 {
		return cmd.Help()
	}

	cfg := config.NewConfig()
	ws := workspace.NewManager(cfg)

	if !flags.quiet {
		printBanner()
	}

	target, err := scope.Normalise(args[0])
	if err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}

	// Resolve timeout.
	timeout, err := time.ParseDuration(flags.timeout)
	if err != nil {
		return fmt.Errorf("invalid timeout %q: %w", flags.timeout, err)
	}

	mode := strings.ToLower(flags.mode)
	if mode != "full" && mode != "active" && mode != "passive" {
		return fmt.Errorf("invalid mode %q: must be full, active, or passive", flags.mode)
	}

	if flags.quiet {
		fmt.Printf("Reconpipeline %s\nTarget: %s\n", version.Version, target.Domain)
	} else {
		fmt.Printf("Target : %s\n", target.Domain)
		fmt.Printf("Mode   : %s\n", modeLabel(mode))
		fmt.Println()
		fmt.Println("────────────────────────────────────────")
	}

	// Dry run — show plan only.
	if flags.dryRun {
		return showDryRun(target, mode, flags.output, ws)
	}

	// Initialise workspace.
	if err := ws.Init(); err != nil {
		return fmt.Errorf("workspace initialisation failed: %w", err)
	}

	// First run / dependency check.
	logging.Info("[01] Preparing dependencies")
	depMgr := dependencies.NewManager(cfg, ws)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Handle SIGINT.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println()
		fmt.Println("Scan interrupted.")
		fmt.Println()
		fmt.Println("Completed results have been preserved.")
		fmt.Println()
		fmt.Printf("Resume with:\n\n    reconpipeline %s --resume\n\n", target.Domain)
		cancel()
	}()

	if err := depMgr.EnsureAll(ctx); err != nil {
		return fmt.Errorf("dependency check failed: %w", err)
	}

	// Run pipeline.
	pipelineOpts := pipeline.Options{
		OutputRoot: flags.output,
		Mode:       mode,
		Threads:    flags.threads,
		Resume:     flags.resume,
		DryRun:     flags.dryRun,
	}

	p := pipeline.New(target, pipelineOpts, ws)
	start := time.Now()

	stages := []struct {
		name  string
		label string
	}{
		{"subdomain-discovery", "[01] Subdomain Discovery"},
		{"live-host-detection", "[02] Live Host Detection"},
		{"active-crawling", "[03] Active Crawling"},
		{"historical-url-discovery", "[04] Historical URL Discovery"},
		{"url-processing", "[05] URL Processing"},
		{"pattern-analysis", "[06] Pattern Analysis"},
	}

	// Print stage lines dynamically.
	if !flags.quiet {
		// Use a channel to capture stage updates.
		runErr := runPipelineWithProgress(ctx, p, stages)

		elapsed := time.Since(start)
		state := p.State()

		fmt.Println()
		fmt.Println("────────────────────────────────────────")
		fmt.Println()
		fmt.Printf("Subdomains : %s\n", formatCount(state.Counters.Subdomains))
		fmt.Printf("Live Hosts : %s\n", formatCount(state.Counters.LiveHosts))
		fmt.Printf("Unique URLs: %s\n", formatCount(state.Counters.UniqueURLs))
		fmt.Println()

		domain, _ := scope.SafeFilename(target.Domain)
		outRoot := flags.output
		if outRoot == "" {
			outRoot = cfg.ResultsDir
		}
		targetDir := ws.TargetDir(outRoot, domain)
		fmt.Printf("Results:\n%s\n\n", targetDir)
		fmt.Printf("Completed in %s\n", formatDuration(elapsed))

		// Generate reports.
		if state != nil {
			_ = reporting.Generate(state, targetDir)
		}

		if runErr != nil && ctx.Err() == nil {
			fmt.Println()
			fmt.Println("Completed with warnings.")
			if len(state.Warnings) > 0 {
				for _, w := range state.Warnings {
					fmt.Printf("  %s\n", w)
				}
			}
		}
	} else {
		if err := p.Run(ctx); err != nil && ctx.Err() == nil {
			logging.Error("Pipeline error: %v", err)
		}
		state := p.State()
		domain, _ := scope.SafeFilename(target.Domain)
		outRoot := flags.output
		if outRoot == "" {
			outRoot = cfg.ResultsDir
		}
		targetDir := ws.TargetDir(outRoot, domain)
		if state != nil {
			_ = reporting.Generate(state, targetDir)
		}
		fmt.Printf("Completed.\nResults: %s\n", targetDir)
	}

	return nil
}

// runPipelineWithProgress runs the pipeline and prints live stage status lines.
func runPipelineWithProgress(ctx context.Context, p *pipeline.Pipeline, stages []struct {
	name  string
	label string
}) error {
	// We run stages one at a time inside the pipeline; here we just
	// print them after the pipeline completes each stage.
	// For a cleaner UX we run the pipeline and then print stage results.
	err := p.Run(ctx)

	state := p.State()
	for _, s := range stages {
		status := statusSymbol(state, s.name)
		fmt.Printf("%-40s %s\n", s.label, status)
	}
	return err
}

// statusSymbol returns the display symbol for a stage outcome.
func statusSymbol(state *pipeline.RunState, name string) string {
	if state == nil {
		return "?"
	}
	for _, s := range state.Stages {
		if s.Name == name {
			switch s.Status {
			case pipeline.StatusCompleted:
				return "v"
			case pipeline.StatusFailed:
				return "!"
			case pipeline.StatusSkipped:
				return "skipped"
			case pipeline.StatusInterrupted:
				return "interrupted"
			default:
				return "-"
			}
		}
	}
	return "-"
}

func printBanner() {
	fmt.Print(logo)
	fmt.Println()
	fmt.Println("Reconpipeline")
	fmt.Println("Made by frozeniceee")
	fmt.Printf("Version: %s\n", version.Version)
	fmt.Println()
}

func versionString() string {
	return fmt.Sprintf("Reconpipeline %s\nMade by frozeniceee", version.Version)
}

func modeLabel(mode string) string {
	switch mode {
	case "full":
		return "Full Recon"
	case "active":
		return "Active Recon"
	case "passive":
		return "Passive Recon"
	default:
		return mode
	}
}

func showDryRun(target *scope.Target, mode, output string, ws *workspace.Manager) error {
	fmt.Printf("Reconpipeline\nVersion: %s\n\n", version.Version)
	fmt.Printf("Target : %s\n", target.Domain)
	fmt.Printf("Mode   : %s\n\n", modeLabel(mode))

	fmt.Println("Pipeline:")
	fmt.Println()
	fmt.Println("[01] Subdomain Discovery")
	fmt.Println("[02] Live Host Detection")
	fmt.Println("[03] Active Crawling")
	fmt.Println("[04] Historical URL Discovery")
	fmt.Println("[05] URL Processing")
	fmt.Println("[06] Pattern Analysis")
	fmt.Println()

	fmt.Println("Dependencies:")
	fmt.Println()
	cfg := config.NewConfig()
	depMgr := dependencies.NewManager(cfg, ws)
	status := depMgr.Status()
	for _, tool := range config.ToolOrder {
		fmt.Printf("%-12s %s\n", capitalize(tool), status[tool])
	}
	fmt.Println()

	outRoot := output
	if outRoot == "" {
		outRoot = "results"
	}
	fmt.Printf("Output:\n\n%s/%s/\n\n", outRoot, target.Domain)
	fmt.Println("Dry run complete.")
	fmt.Println("No reconnaissance was performed.")
	return nil
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func formatCount(n int) string {
	s := fmt.Sprintf("%d", n)
	if n < 1000 {
		return s
	}
	out := ""
	for i, ch := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out += ","
		}
		out += string(ch)
	}
	return out
}

func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%02dh %02dm %02ds", h, m, s)
	}
	return fmt.Sprintf("%02dm %02ds", m, s)
}

// ─── Subcommands ─────────────────────────────────────────────────────────────

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(versionString())
		},
	}
}

func updateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update Reconpipeline",
		RunE:  runUpdate,
	}
}

func doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check system and dependencies",
		RunE:  runDoctor,
	}
}

func runUpdate(cmd *cobra.Command, args []string) error {
	fmt.Println("Checking for updates...")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := updater.Check(ctx)
	if err != nil {
		return fmt.Errorf("update check failed: %w\n\nEnsure https://github.com/frozeniceee/Reconpipeline has releases.", err)
	}

	fmt.Printf("Current version : %s\n", result.CurrentVersion)
	fmt.Printf("Latest version  : %s\n", result.LatestVersion)

	if !result.UpdateAvailable {
		fmt.Println()
		fmt.Println("Reconpipeline is already up to date.")
		return nil
	}

	if result.AssetURL == "" {
		return fmt.Errorf("no release asset available for this platform")
	}

	fmt.Println()
	fmt.Printf("Downloading %s...\n", result.LatestVersion)

	if err := updater.Apply(ctx, result); err != nil {
		return fmt.Errorf("update failed: %w\n\nYour existing installation has been preserved.", err)
	}

	fmt.Printf("\nReconpipeline updated to %s.\n", result.LatestVersion)
	return nil
}

func runDoctor(cmd *cobra.Command, args []string) error {
	cfg := config.NewConfig()
	ws := workspace.NewManager(cfg)
	depMgr := dependencies.NewManager(cfg, ws)

	fmt.Println("Reconpipeline Doctor")
	fmt.Println("────────────────────────────────")
	fmt.Println()

	fmt.Println("Application")
	fmt.Printf("  Version       : %s\n", version.Version)
	fmt.Printf("  Installation  : OK\n")
	fmt.Println()

	fmt.Println("System")
	fmt.Printf("  OS            : %s\n", cfg.OS)
	fmt.Printf("  Architecture  : %s\n", cfg.Arch)
	fmt.Println()

	fmt.Println("Workspace")
	checkDir(cfg.ConfigDir, "Config")
	checkDir(cfg.CacheDir, "Cache")
	checkDir(cfg.LogsDir, "Logs")
	fmt.Println()

	fmt.Println("Managed Tools")
	status := depMgr.Status()
	for _, tool := range config.ToolOrder {
		label := capitalize(tool)
		if tool == "httpx" {
			label = "HTTPX"
		}
		fmt.Printf("  %-14s: %s\n", label, status[tool])
	}
	fmt.Println()

	allOK := true
	for _, s := range status {
		if s != "OK" {
			allOK = false
			break
		}
	}

	if allOK {
		fmt.Println("Status: READY")
	} else {
		fmt.Println("Status: INCOMPLETE")
		fmt.Println()
		fmt.Println("Run: reconpipeline <target> to install missing dependencies.")
	}
	return nil
}

func checkDir(path, label string) {
	if workspace.Exists(path) {
		fmt.Printf("  %-14s: OK\n", label)
	} else {
		fmt.Printf("  %-14s: MISSING\n", label)
	}
}

// DisplayStageUpdate prints a stage result line.
func DisplayStageUpdate(label string, st pipeline.StageStatus) {
	sym := "?"
	switch st {
	case pipeline.StatusCompleted:
		sym = "v"
	case pipeline.StatusFailed:
		sym = "!"
	case pipeline.StatusSkipped:
		sym = "skipped"
	case pipeline.StatusRunning:
		sym = "running"
	}
	fmt.Printf("%-40s %s\n", label, sym)
}

// ResultDir returns the results path for a domain.
func ResultDir(cfg *config.Config, ws *workspace.Manager, output, domain string) string {
	outRoot := output
	if outRoot == "" {
		outRoot = cfg.ResultsDir
	}
	return filepath.Join(outRoot, domain)
}
