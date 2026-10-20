// Package cli implements the Reconpipeline command-line interface.
package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/khaleddevsec/Reconpipeline/internal/comparison"
	"github.com/khaleddevsec/Reconpipeline/internal/config"
	"github.com/khaleddevsec/Reconpipeline/internal/dependencies"
	"github.com/khaleddevsec/Reconpipeline/internal/history"
	"github.com/khaleddevsec/Reconpipeline/internal/logging"
	"github.com/khaleddevsec/Reconpipeline/internal/pipeline"
	"github.com/khaleddevsec/Reconpipeline/internal/reporting"
	"github.com/khaleddevsec/Reconpipeline/internal/scope"
	"github.com/khaleddevsec/Reconpipeline/internal/updater"
	"github.com/khaleddevsec/Reconpipeline/internal/version"
	"github.com/khaleddevsec/Reconpipeline/internal/workspace"
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
	target   string
	list     string
	output   string
	mode     string
	profile  string
	timeout  string
	threads  int
	workers  int
	exclude  string
	resume   bool
	dryRun   bool
	noCache  bool
	noColor  bool
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
    reconpipeline -u <target>
    reconpipeline -l <targets.txt>

Commands:

    history <target>   View historical scans for target
    compare <target>   Compare recent scans for changes
    report <target>    Display latest scan report
    doctor             Check system and dependencies
    update             Update Reconpipeline
    version            Show version

Options:

    -u, --url <target>     Target domain or URL
    -l, --list <file>      File containing list of targets
    -o, --output <dir>     Output directory for results
    --profile <name>       Profile: full, fast, passive (default: full)
    --mode <mode>          Scan mode: full, active, passive (default: full)
    --resume               Resume an interrupted scan
    --dry-run              Show pipeline plan without executing
    --no-cache             Bypass stage caching

    --timeout <dur>        Scan timeout (e.g. 30m, 1h) (default: 30m)
    --threads <num>        Concurrency level (default: 10)
    --workers <num>        Worker concurrency alias

    --no-color             Disable coloured output
    -q, --quiet            Minimal output
    --verbose              Detailed output
    -h, --help             Show help
    -v, --version          Show version`,
		Version:           version.Version,
		SilenceUsage:      true,
		SilenceErrors:     true,
		Args:              cobra.ArbitraryArgs,
		RunE:              runMain,
		PersistentPreRunE: persistentPreRun,
	}

	// Flags.
	root.Flags().StringVarP(&flags.target, "url", "u", "", "Target domain or URL (e.g. example.com)")
	root.Flags().StringVarP(&flags.target, "target", "t", "", "Target domain or URL alias")
	root.Flags().StringVarP(&flags.list, "list", "l", "", "Path to file containing list of targets")
	root.Flags().StringVarP(&flags.output, "output", "o", "", "Output directory for results")
	root.Flags().StringVar(&flags.mode, "mode", "full", "Scan mode: full, active, passive")
	root.Flags().StringVar(&flags.profile, "profile", "full", "Execution profile: full, fast, passive")
	root.Flags().StringVar(&flags.timeout, "timeout", "30m", "Scan timeout (e.g. 30m, 1h)")
	root.Flags().IntVar(&flags.threads, "threads", 10, "Concurrency level")
	root.Flags().IntVar(&flags.workers, "workers", 0, "Worker concurrency alias")
	root.Flags().StringVarP(&flags.exclude, "exclude", "e", "", "Excluded subdomains or CIDR ranges (comma-separated)")
	root.Flags().BoolVar(&flags.resume, "resume", false, "Resume a previous scan")
	root.Flags().BoolVar(&flags.dryRun, "dry-run", false, "Show pipeline plan without executing")
	root.Flags().BoolVar(&flags.noCache, "no-cache", false, "Bypass stage caching")
	root.Flags().BoolVar(&flags.noColor, "no-color", false, "Disable terminal colours")
	root.Flags().BoolVarP(&flags.quiet, "quiet", "q", false, "Minimal output")
	root.Flags().BoolVar(&flags.verbose, "verbose", false, "Detailed output")
	root.Flags().Bool("update", false, "Update Reconpipeline")
	root.Flags().Bool("doctor", false, "Check system and dependencies")

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
	if flags.noColor {
		logging.SetNoColor(true)
	}
	level := logging.LevelNormal
	if flags.quiet {
		level = logging.LevelQuiet
	} else if flags.verbose {
		level = logging.LevelVerbose
	}
	_ = logging.Init(level, cfg.LogsDir)
	return nil
}

// runMain is the main entry point for reconpipeline.
func runMain(cmd *cobra.Command, args []string) error {
	// Check --update / --doctor flags.
	if update, _ := cmd.Flags().GetBool("update"); update {
		return runUpdate(cmd, args)
	}
	if doctor, _ := cmd.Flags().GetBool("doctor"); doctor {
		return runDoctor(cmd, args)
	}

	var targets []string
	if flags.target == "-" || (len(args) > 0 && args[0] == "-") {
		stdinTargets, err := readTargetLines("-")
		if err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}
		targets = append(targets, stdinTargets...)
	} else {
		if flags.target != "" {
			targets = append(targets, flags.target)
		}
		if len(args) > 0 {
			targets = append(targets, args...)
		}
	}

	if flags.list != "" {
		fileTargets, err := readTargetLines(flags.list)
		if err != nil {
			return fmt.Errorf("failed to read targets file %q: %w", flags.list, err)
		}
		targets = append(targets, fileTargets...)
	}

	// Check if piped from stdin without blocking
	if len(targets) == 0 {
		if stat, err := os.Stdin.Stat(); err == nil && (stat.Mode()&os.ModeCharDevice) == 0 {
			targets = append(targets, readPipedStdin(250*time.Millisecond)...)
		}
	}

	if len(targets) == 0 {
		printBanner()
		printUsage()
		return nil
	}

	for _, t := range targets {
		if err := runSingleTarget(cmd, t); err != nil {
			if len(targets) > 1 {
				logging.Error("Target %s failed: %v", t, err)
				continue
			}
			return err
		}
	}
	return nil
}

func readPipedStdin(timeout time.Duration) []string {
	ch := make(chan string)

	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			ch <- scanner.Text()
		}
		close(ch)
	}()

	select {
	case line, ok := <-ch:
		if !ok {
			return nil
		}
		var lines []string
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
		for l := range ch {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "#") {
				lines = append(lines, l)
			}
		}
		return lines
	case <-time.After(timeout):
		return nil
	}
}

func readTargetLines(path string) ([]string, error) {
	if path == "-" {
		var lines []string
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				lines = append(lines, line)
			}
		}
		return lines, scanner.Err()
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// runSingleTarget runs the reconnaissance pipeline for a single target string.
func runSingleTarget(cmd *cobra.Command, targetRaw string) error {
	cfg := config.NewConfig()
	ws := workspace.NewManager(cfg)

	target, err := scope.Normalise(targetRaw)
	if err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}

	threads := flags.threads
	if flags.workers > 0 {
		threads = flags.workers
	}

	mode := strings.ToLower(flags.mode)
	profile := strings.ToLower(flags.profile)

	if err := config.ValidateOptions(threads, flags.timeout, mode, profile); err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	if profile != "" && profile != "full" && cmd.Flags().Changed("profile") && !cmd.Flags().Changed("mode") {
		prof := config.GetProfile(profile)
		mode = prof.Mode
		if !cmd.Flags().Changed("threads") && flags.workers == 0 {
			threads = prof.Threads
		}
	}

	if flags.quiet {
		fmt.Printf("Reconpipeline %s\nTarget: %s\n", version.Version, target.Domain)
	} else {
		printBanner()
		fmt.Printf("Target  : %s\n", target.Domain)
		if profile != "" && profile != "full" {
			fmt.Printf("Profile : %s\n", capitalize(profile))
		}
		fmt.Printf("Mode    : %s\n", modeLabel(mode))
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

	// Resolve timeout.
	timeout, _ := time.ParseDuration(flags.timeout)

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

	var exclusions []string
	if flags.exclude != "" {
		for _, e := range strings.Split(flags.exclude, ",") {
			e = strings.TrimSpace(e)
			if e != "" {
				exclusions = append(exclusions, e)
			}
		}
	}

	// Run pipeline.
	pipelineOpts := pipeline.Options{
		OutputRoot: flags.output,
		Mode:       mode,
		Profile:    profile,
		Threads:    threads,
		Resume:     flags.resume,
		DryRun:     flags.dryRun,
		NoCache:    flags.noCache,
		Timeout:    timeout,
		Exclusions: exclusions,
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
		{"url-verification", "[06] URL Verification"},
		{"pattern-analysis", "[07] Pattern Analysis"},
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
		fmt.Printf("Subdomains   : %s\n", formatCount(state.Counters.Subdomains))
		fmt.Printf("Live Hosts   : %s\n", formatCount(state.Counters.LiveHosts))
		fmt.Printf("Unique URLs  : %s\n", formatCount(state.Counters.UniqueURLs))
		if state.Counters.VerifiedURLs > 0 || state.StageCompleted("url-verification") {
			fmt.Printf("Verified URLs: %s\n", formatCount(state.Counters.VerifiedURLs))
		}
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
	fmt.Fprint(os.Stderr, logo)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Reconpipeline")
	fmt.Fprintln(os.Stderr, "Made by khaleddevsec")
	fmt.Fprintf(os.Stderr, "Version: %s\n\n", version.Version)
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Reconpipeline - Automated Reconnaissance Pipeline

Usage:

    reconpipeline <target>
    reconpipeline -u <target>
    reconpipeline -l <targets.txt>

Commands:

    history <target>   View historical scans for target
    compare <target>   Compare recent scans for changes
    report <target>    Display latest scan report
    doctor             Check system and dependencies
    update             Update Reconpipeline
    version            Show version

Options:

    -u, --url <target>     Target domain or URL
    -l, --list <file>      File containing list of targets
    -o, --output <dir>     Output directory for results
    --profile <name>       Profile: full, fast, passive (default: full)
    --mode <mode>          Scan mode: full, active, passive (default: full)

    --resume               Resume an interrupted scan
    --dry-run              Show pipeline plan without executing
    --no-cache             Bypass stage caching

    --timeout <duration>   Scan timeout (e.g. 30m, 1h) (default: 30m)
    --threads <number>     Concurrency level (default: 10)
    --workers <number>     Worker concurrency alias

    -q, --quiet            Minimal output
    --verbose              Detailed output
    --no-color             Disable terminal colours
    -h, --help             Show help
    -v, --version          Show version`)
}

func versionString() string {
	return fmt.Sprintf("Reconpipeline %s\nMade by khaleddevsec", version.Version)
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
	fmt.Printf("Target Domain : %s\n", target.Domain)
	fmt.Printf("Scan Mode     : %s\n", modeLabel(mode))

	if flags.exclude != "" {
		fmt.Printf("Exclusions    : %s\n", flags.exclude)
	} else {
		fmt.Printf("Exclusions    : none configured\n")
	}

	fmt.Println("Scope Policy  : Centralized authorization boundary strictly enforced.")
	fmt.Println("                Private ranges (RFC 1918, 127.0.0.0/8, 169.254.169.254) and off-origin hosts BLOCKED.")
	fmt.Println()

	fmt.Println("Planned Pipeline Stages & Operations:")
	fmt.Println()
	fmt.Println("[01] Subdomain Discovery      : Passive enumeration & DNS resolution (Subfinder)")
	fmt.Println("[02] Live Host Detection       : Active HTTP probe & metadata profiling (HTTPX #1)")
	fmt.Println("[03] Active Crawling           : Scope-constrained spidering (Katana)")
	fmt.Println("[04] Historical URL Discovery  : Passive archive discovery (GAU)")
	fmt.Println("[05] URL Processing            : Normalization, clustering, API & param classification (urlengine)")
	fmt.Println("[06] URL Verification          : Active verification of selected endpoints (HTTPX #2)")
	fmt.Println("[07] Pattern Analysis          : Security intelligence & takeover candidate analysis (GF)")
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
		outRoot = cfg.ResultsDir
	}
	fmt.Printf("Output Destination:\n\n%s/%s/\n\n", outRoot, target.Domain)
	fmt.Println("Dry run complete.")
	fmt.Println("No reconnaissance or active network requests were performed.")
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
	var check bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show version",
		Run: func(cmd *cobra.Command, args []string) {
			if check {
				fmt.Println("Checking for updates...")
				vStatus := updater.GetVersionStatus(context.Background())
				fmt.Printf("Reconpipeline %s\nMade by khaleddevsec\n", vStatus)
			} else {
				fmt.Println(versionString())
			}
		},
	}
	cmd.Flags().BoolVarP(&check, "check", "c", false, "Check for newer version online")
	return cmd
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
		return fmt.Errorf("update check failed: %w\n\nEnsure https://github.com/khaleddevsec/Reconpipeline has releases.", err)
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
	goBin := dependencies.FindGo()
	if goBin != "" {
		fmt.Printf("  Go Compiler   : %s (OK)\n", goBin)
	} else {
		fmt.Printf("  Go Compiler   : NOT FOUND\n")
	}
	fmt.Println()

	fmt.Println("Managed Tools")
	status := depMgr.Status()
	versions := depMgr.ToolVersions()
	for _, tool := range config.ToolOrder {
		label := capitalize(tool)
		if tool == "httpx" {
			label = "HTTPX"
		}
		vStr := versions[tool]
		if vStr == "" {
			vStr = status[tool]
		}
		fmt.Printf("  %-14s: %-10s (%s)\n", label, status[tool], vStr)
	}
	fmt.Println()

	fmt.Println("Workspace")
	checkDir(cfg.ConfigDir, "Config")
	checkDir(cfg.CacheDir, "Cache")
	checkDir(cfg.LogsDir, "Logs")
	checkDir(cfg.ToolsDir, "Tools")
	checkDir(cfg.VersionsDir, "Versions")
	fmt.Println()

	fmt.Println("Configuration")
	fmt.Printf("  Profile       : %s\n", cfg.UserSettings.DefaultProfile)
	fmt.Printf("  Threads       : %d\n", cfg.UserSettings.DefaultThreads)
	fmt.Printf("  Timeout       : %s\n", cfg.UserSettings.DefaultTimeout)
	fmt.Printf("  Cache Enabled : %t\n", cfg.UserSettings.CacheEnabled)
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
			if s.Counters.VerifiedURLs > 0 {
				fmt.Printf("     Verified  : %s\n", formatCount(s.Counters.VerifiedURLs))
			}
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
