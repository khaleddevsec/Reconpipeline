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

	"github.com/frozeniceee/Reconpipeline/internal/comparison"
	"github.com/frozeniceee/Reconpipeline/internal/config"
	"github.com/frozeniceee/Reconpipeline/internal/dependencies"
	"github.com/frozeniceee/Reconpipeline/internal/history"
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
	output   string
	mode     string
	timeout  string
	threads  int
	resume   bool
	dryRun   bool
	quiet    bool
	verbose  bool
	details  bool
	fromScan string
	toScan   string
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

    history <target>   View historical scans for target
    compare <target>   Compare recent scans for changes
    report <target>    Display latest scan report
    doctor             Check system and dependencies
    update             Update Reconpipeline
    version            Show version

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
	root.AddCommand(historyCmd())
	root.AddCommand(compareCmd())
	root.AddCommand(reportCmd())

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
		printBanner()
		printUsage()
		return nil
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

	domain, _ := scope.SafeFilename(target.Domain)
	outRoot := flags.output
	if outRoot == "" {
		outRoot = cfg.ResultsDir
	}
	targetDir := ws.TargetDir(outRoot, domain)

	// Fetch previous scan before current run
	prevMeta, prevDir, _ := history.GetLatestScan(targetDir)

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

	var compResult *comparison.Result

	// Print stage lines dynamically.
	if !flags.quiet {
		runErr := runPipelineWithProgress(ctx, p, stages)

		elapsed := time.Since(start)
		state := p.State()

		// Run comparison
		if state != nil {
			currMeta := &history.ScanMeta{
				ScanID:           state.ScanID,
				Target:           target.Domain,
				NormalisedTarget: target.Domain,
				Version:          state.Version,
				StartTime:        state.StartTime,
			}
			compEngine := comparison.NewEngine()
			compResult, _ = compEngine.CompareScans(prevDir, targetDir, targetDir, prevMeta, currMeta)
		}

		// Generate reports in target directory
		if state != nil {
			_ = reporting.Generate(state, targetDir, compResult)
		}

		// Save scan into history
		if state != nil {
			_, scanDir, _ := history.SaveScan(targetDir, state)
			if scanDir != "" {
				_ = reporting.Generate(state, scanDir, compResult)
			}
		}

		fmt.Println()
		fmt.Println("────────────────────────────────────────")
		fmt.Println()
		fmt.Printf("Subdomains : %s\n", formatCount(state.Counters.Subdomains))
		fmt.Printf("Live Hosts : %s\n", formatCount(state.Counters.LiveHosts))
		fmt.Printf("Unique URLs: %s\n", formatCount(state.Counters.UniqueURLs))
		fmt.Println()

		if compResult != nil && compResult.HasPrevious {
			fmt.Println("Changes Since Previous Scan:")
			fmt.Printf("  Subdomains : +%d, -%d\n", len(compResult.NewSubdomains), len(compResult.RemovedSubdomains))
			fmt.Printf("  Live Hosts : +%d, -%d\n", len(compResult.NewHosts), len(compResult.RemovedHosts))
			fmt.Printf("  Unique URLs: +%d, -%d\n", len(compResult.NewURLs), len(compResult.RemovedURLs))
			fmt.Println()
		}

		fmt.Printf("Results:\n%s\n\n", targetDir)
		fmt.Printf("Completed in %s\n", formatDuration(elapsed))

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
		if state != nil {
			currMeta := &history.ScanMeta{
				ScanID:           state.ScanID,
				Target:           target.Domain,
				NormalisedTarget: target.Domain,
				Version:          state.Version,
				StartTime:        state.StartTime,
			}
			compEngine := comparison.NewEngine()
			compResult, _ = compEngine.CompareScans(prevDir, targetDir, targetDir, prevMeta, currMeta)
			_ = reporting.Generate(state, targetDir, compResult)
			_, scanDir, _ := history.SaveScan(targetDir, state)
			if scanDir != "" {
				_ = reporting.Generate(state, scanDir, compResult)
			}
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
	vStatus := updater.GetVersionStatus(context.Background())
	fmt.Printf("Version: %s\n", vStatus)
	fmt.Println()
}

func printUsage() {
	fmt.Println(`Reconpipeline - Automated Reconnaissance Pipeline

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
    --verbose`)
}

func versionString() string {
	vStatus := updater.GetVersionStatus(context.Background())
	return fmt.Sprintf("Reconpipeline %s\nMade by frozeniceee", vStatus)
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

func historyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "history <target>",
		Short: "View historical scans for target",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHistory(args[0], flags.details)
		},
	}
	cmd.Flags().BoolVarP(&flags.details, "details", "d", false, "Show detailed metrics for each scan")
	return cmd
}

func compareCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "compare <target>",
		Short: "Compare recent scans for change detection",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCompare(args[0], flags.fromScan, flags.toScan)
		},
	}
	cmd.Flags().StringVar(&flags.fromScan, "from", "", "Base scan ID to compare from")
	cmd.Flags().StringVar(&flags.toScan, "to", "", "Target scan ID to compare to")
	return cmd
}

func reportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report <target>",
		Short: "Display or locate latest scan report",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReport(args[0])
		},
	}
	return cmd
}

func runHistory(targetRaw string, details bool) error {
	cfg := config.NewConfig()
	ws := workspace.NewManager(cfg)

	target, err := scope.Normalise(targetRaw)
	if err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}

	domain, _ := scope.SafeFilename(target.Domain)
	outRoot := flags.output
	if outRoot == "" {
		outRoot = cfg.ResultsDir
	}
	targetDir := ws.TargetDir(outRoot, domain)

	scans, err := history.ListScans(targetDir)
	if err != nil {
		return err
	}

	fmt.Printf("Reconpipeline %s\n\n", version.Version)
	fmt.Printf("Target : %s\n\n", target.Domain)
	fmt.Println("Scan History")
	fmt.Println("────────────────────────────────────────")

	if len(scans) == 0 {
		fmt.Println("No recorded scans found for this target.")
		return nil
	}

	if !details {
		fmt.Printf("%-4s %-20s %-12s %s\n", "#", "Date", "Duration", "Status")
		for i, s := range scans {
			dateStr := s.StartTime.Format("2006-01-02 15:04")
			durStr := s.Duration
			if durStr == "" {
				durStr = "-"
			}
			fmt.Printf("%02d   %-20s %-12s %s\n", i+1, dateStr, durStr, history.Capitalize(s.Status))
		}
	} else {
		for i, s := range scans {
			fmt.Printf("[%02d] Scan ID   : %s\n", i+1, s.ScanID)
			fmt.Printf("     Date      : %s\n", history.FormatTime(s.StartTime))
			fmt.Printf("     Status    : %s\n", history.Capitalize(s.Status))
			fmt.Printf("     Duration  : %s\n", s.Duration)
			fmt.Printf("     Subdomains: %s\n", formatCount(s.Counters.Subdomains))
			fmt.Printf("     Live Hosts: %s\n", formatCount(s.Counters.LiveHosts))
			fmt.Printf("     URLs      : %s\n", formatCount(s.Counters.UniqueURLs))
			fmt.Printf("     APIs      : %s\n", formatCount(s.Counters.APIURLs))
			fmt.Printf("     JavaScript: %s\n", formatCount(s.Counters.JavaScriptURLs))
			fmt.Printf("     Parameters: %s\n", formatCount(s.Counters.ParamURLs))
			fmt.Printf("     GF Matches: %d\n", s.Counters.XSSMatches+s.Counters.SQLiMatches+s.Counters.LFIMatches+s.Counters.SSRFMatches+s.Counters.RedirectMatches)
			fmt.Println()
		}
	}

	return nil
}

func runCompare(targetRaw, fromID, toID string) error {
	cfg := config.NewConfig()
	ws := workspace.NewManager(cfg)

	target, err := scope.Normalise(targetRaw)
	if err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}

	domain, _ := scope.SafeFilename(target.Domain)
	outRoot := flags.output
	if outRoot == "" {
		outRoot = cfg.ResultsDir
	}
	targetDir := ws.TargetDir(outRoot, domain)

	var prevMeta, currMeta *history.ScanMeta
	var prevDir, currDir string

	if fromID != "" && toID != "" {
		var pErr, cErr error
		prevMeta, prevDir, pErr = history.GetScan(targetDir, fromID)
		if pErr != nil {
			return pErr
		}
		currMeta, currDir, cErr = history.GetScan(targetDir, toID)
		if cErr != nil {
			return cErr
		}
	} else {
		latest, lDir, err := history.GetLatestScan(targetDir)
		if err != nil || latest == nil {
			fmt.Printf("Reconpipeline %s\n\nTarget : %s\n\nNo scans found to compare.\n", version.Version, target.Domain)
			return nil
		}
		currMeta = latest
		currDir = lDir

		prev, pDir, pErr := history.GetPreviousScan(targetDir, latest.ScanID)
		if pErr == nil && prev != nil {
			prevMeta = prev
			prevDir = pDir
		}
	}

	compEngine := comparison.NewEngine()
	res, err := compEngine.CompareScans(prevDir, currDir, targetDir, prevMeta, currMeta)
	if err != nil {
		return err
	}

	fmt.Printf("Reconpipeline %s\n\n", version.Version)
	fmt.Printf("Target : %s\n\n", target.Domain)
	fmt.Print(compEngine.FormatTextSummary(res))
	return nil
}

func runReport(targetRaw string) error {
	cfg := config.NewConfig()
	ws := workspace.NewManager(cfg)

	target, err := scope.Normalise(targetRaw)
	if err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}

	domain, _ := scope.SafeFilename(target.Domain)
	outRoot := flags.output
	if outRoot == "" {
		outRoot = cfg.ResultsDir
	}
	targetDir := ws.TargetDir(outRoot, domain)

	reportTxtPath := filepath.Join(targetDir, "report.txt")
	reportHTMLPath := filepath.Join(targetDir, "report.html")
	reportJSONPath := filepath.Join(targetDir, "report.json")

	if !workspace.Exists(reportTxtPath) {
		fmt.Printf("Reconpipeline %s\n\nTarget : %s\n\nNo report found. Run a scan first:\n\n    reconpipeline %s\n", version.Version, target.Domain, target.Domain)
		return nil
	}

	fmt.Printf("Reconpipeline %s\n\n", version.Version)
	fmt.Printf("Target : %s\n\n", target.Domain)
	fmt.Println("Latest Scan Reports:")
	fmt.Println("────────────────────────────────────────")
	fmt.Printf("HTML Dashboard : %s\n", reportHTMLPath)
	fmt.Printf("JSON Report    : %s\n", reportJSONPath)
	fmt.Printf("Text Report    : %s\n\n", reportTxtPath)

	if data, err := os.ReadFile(reportTxtPath); err == nil {
		fmt.Println(string(data))
	}

	return nil
}
