package cli

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/khaleddevsec/Reconpipeline/v2/internal/collector"
	"github.com/khaleddevsec/Reconpipeline/v2/internal/config"
	"github.com/khaleddevsec/Reconpipeline/v2/internal/correlation"
	"github.com/khaleddevsec/Reconpipeline/v2/internal/database"
	"github.com/khaleddevsec/Reconpipeline/v2/internal/fingerprint"
	"github.com/khaleddevsec/Reconpipeline/v2/internal/knowledge"
	"github.com/khaleddevsec/Reconpipeline/v2/internal/parser"
	"github.com/khaleddevsec/Reconpipeline/v2/internal/report"
	"github.com/khaleddevsec/Reconpipeline/v2/internal/risk"
	"github.com/khaleddevsec/Reconpipeline/v2/models"
	"github.com/khaleddevsec/Reconpipeline/v2/pkg/utils"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	scanFormat       string
	scanName         string
	scanListFile     string
	scanInsecure     bool
	scanProxy        string
	scanBlockPrivate bool
	scanFailOn       string
	scanHeaders      []string
)

var scanCmd = &cobra.Command{
	Use:   "scan [url...]",
	Short: "Scan one or more URLs and produce a security intelligence report",
	Args:  cobra.ArbitraryArgs,
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&scanFormat, "format", "f", "json",
		"report format: json|markdown|html|csv|sarif")
	scanCmd.Flags().StringVarP(&scanName, "name", "n", "",
		"output filename (without extension); defaults to \"report\"")
	scanCmd.Flags().StringVarP(&scanListFile, "list", "l", "",
		"path to file containing target URLs (one per line)")
	scanCmd.Flags().BoolVarP(&scanInsecure, "insecure", "k", false,
		"skip TLS certificate verification")
	scanCmd.Flags().StringVar(&scanProxy, "proxy", "",
		"HTTP/HTTPS/SOCKS5 proxy URL")
	scanCmd.Flags().BoolVar(&scanBlockPrivate, "block-private", false,
		"block private/internal/loopback IPs (SSRF protection)")
	scanCmd.Flags().StringVar(&scanFailOn, "fail-on", "",
		"exit with code 1 if findings at or above severity exist (low|medium|high|critical)")
	scanCmd.Flags().StringArrayVarP(&scanHeaders, "header", "H", nil,
		"custom HTTP request header (e.g. -H 'Authorization: Bearer token')")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	cfg := loadConfig(cmd)

	fmtLower := strings.ToLower(strings.TrimSpace(scanFormat))
	if fmtLower == "md" {
		fmtLower = "markdown"
	}
	if !models.IsValidFormat(models.ReportFormat(fmtLower)) {
		return fmt.Errorf("unsupported report format %q (supported: json, markdown, html, csv, sarif)", scanFormat)
	}
	scanFormat = fmtLower

	targets, err := collectTargets(args, scanListFile, cfg.Targets)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("no targets specified (pass URLs as arguments, via -l <file>, stdin, or in config file)")
	}

	store := openStore(cfg)
	if store != nil {
		defer func() {
			if err := store.Close(); err != nil {
				logger.Warn("database close error", zap.Error(err))
			}
		}()
	}

	kdb := knowledge.NewYAMLDatabase(logger)
	if cfg.KnowledgeDB == "" || kdb.Load(cfg.KnowledgeDB) != nil {
		if embErr := kdb.LoadEmbedded(); embErr != nil {
			logger.Warn("knowledge DB unavailable; correlation produces no findings", zap.Error(embErr))
		}
	}

	col, err := collector.NewHTTPCollector(cfg, logger)
	if err != nil {
		return fmt.Errorf("collector init: %w", err)
	}

	results, failedCount := runConcurrentScans(ctx, cfg, kdb, store, col, targets)

	if len(results) == 0 {
		return fmt.Errorf("all %d target scan(s) failed", len(targets))
	}

	rep := buildReport(results, failedCount)
	if err := writeReport(cfg, rep); err != nil {
		return err
	}

	if scanFailOn != "" {
		if exceeded, err := checkFailThreshold(rep, scanFailOn); err != nil {
			return err
		} else if exceeded {
			return fmt.Errorf("findings exceeded severity threshold %q", strings.ToUpper(scanFailOn))
		}
	}

	return nil
}

// collectTargets merges URLs from CLI args, -l list file, stdin, and config file.
func collectTargets(args []string, listFile string, cfgTargets []string) ([]string, error) {
	seen := make(map[string]bool)
	var out []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" || strings.HasPrefix(u, "#") {
			return
		}
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}

	readFromStdin := false
	for _, a := range args {
		if a == "-" {
			readFromStdin = true
			continue
		}
		add(a)
	}

	if listFile != "" {
		lines, err := readTargetLines(listFile)
		if err != nil {
			return nil, fmt.Errorf("read target list %q: %w", listFile, err)
		}
		for _, l := range lines {
			add(l)
		}
	}

	for _, t := range cfgTargets {
		add(t)
	}

	if readFromStdin || (len(out) == 0 && hasPipedStdin()) {
		lines, err := readTargetLines("-")
		if err == nil {
			for _, l := range lines {
				add(l)
			}
		}
	}

	return out, nil
}

func readTargetLines(path string) ([]string, error) {
	var scanner *bufio.Scanner
	if path == "-" {
		scanner = bufio.NewScanner(os.Stdin)
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		scanner = bufio.NewScanner(f)
	}
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func hasPipedStdin() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) == 0
}

// runConcurrentScans fans out scans across cfg.Concurrency goroutines.
func runConcurrentScans(
	ctx context.Context,
	cfg *config.Config,
	kdb knowledge.DB,
	store database.Store,
	col collector.Collector,
	rawURLs []string,
) ([]*models.ScanResult, int) {
	concurrency := cfg.Concurrency
	if concurrency < 1 {
		concurrency = 5
	}
	sem := make(chan struct{}, concurrency)
	var (
		mu          sync.Mutex
		wg          sync.WaitGroup
		results     []*models.ScanResult
		failedCount int32
	)

	for _, rawURL := range rawURLs {
		target, err := utils.NormalizeURL(rawURL)
		if err != nil {
			logger.Error("invalid URL", zap.String("url", rawURL), zap.Error(err))
			atomic.AddInt32(&failedCount, 1)
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(t models.Target) {
			defer wg.Done()
			defer func() { <-sem }()

			result, err := scanTarget(ctx, cfg, kdb, col, t)
			if err != nil {
				logger.Error("scan failed", zap.String("url", t.URL), zap.Error(err))
				atomic.AddInt32(&failedCount, 1)
				return
			}
			if store != nil {
				if err := store.SaveResult(ctx, result); err != nil {
					logger.Warn("database save failed", zap.Error(err))
				}
			}
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(target)
	}

	wg.Wait()
	return results, int(atomic.LoadInt32(&failedCount))
}

func scanTarget(
	ctx context.Context,
	_ *config.Config,
	kdb knowledge.DB,
	col collector.Collector,
	target models.Target,
) (*models.ScanResult, error) {
	logger.Info("scanning", zap.String("url", target.URL))

	data, err := col.Collect(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("collect: %w", err)
	}

	data, err = parser.NewHTTPParser(logger).Parse(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	fps, err := fingerprint.NewHeaderEngine(logger).Identify(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: %w", err)
	}

	result := &models.ScanResult{
		ID:            utils.NewID(),
		Target:        target,
		CollectedData: *data,
		Fingerprints:  fps,
		CollectedAt:   data.CollectedAt,
	}

	findings, err := correlation.NewHeaderCorrelator(kdb, logger).Correlate(ctx, result)
	if err != nil {
		return nil, fmt.Errorf("correlate: %w", err)
	}
	result.Findings = findings

	score, err := risk.NewDefaultEngine(logger).Score(ctx, result)
	if err != nil {
		return nil, fmt.Errorf("risk score: %w", err)
	}
	result.RiskScore = score
	result.AnalysedAt = time.Now()

	logger.Info("scan complete",
		zap.String("url", target.URL),
		zap.Int("findings", len(findings)),
		zap.Float64("risk_score", score))
	return result, nil
}

func buildReport(results []*models.ScanResult, failedCount int) *models.Report {
	rep := &models.Report{
		Title:       "ThreatLens Security Intelligence Report",
		Version:     Version,
		GeneratedAt: time.Now(),
		Summary: models.ReportSummary{
			FailedTargets: failedCount,
			BySeverity:    make(map[models.Severity]int),
		},
	}
	totalRisk := 0.0
	for _, r := range results {
		rep.Results = append(rep.Results, *r)
		rep.Summary.TotalFindings += len(r.Findings)
		totalRisk += r.RiskScore
		for _, f := range r.Findings {
			rep.Summary.BySeverity[f.Severity]++
		}
	}
	rep.Summary.TotalTargets = len(results)
	if len(results) > 0 {
		rep.Summary.RiskScore = totalRisk / float64(len(results))
	}
	return rep
}

func loadConfig(cmd *cobra.Command) *config.Config {
	cfg := config.Default()
	if cfgFile != "" {
		loaded, err := config.Load(cfgFile)
		if err != nil {
			logger.Warn("config not found, using defaults", zap.Error(err))
		} else {
			cfg = loaded
		}
	}

	// Apply CLI flag overrides
	if cmd != nil && cmd.Flags().Changed("output") {
		cfg.OutputDir = outputDir
	} else if cfg.OutputDir == "" {
		cfg.OutputDir = outputDir
	}
	if cmd != nil && cmd.Flags().Changed("verbosity") {
		cfg.Verbosity = verbosity
	}
	if scanInsecure {
		cfg.Insecure = true
	}
	if scanProxy != "" {
		cfg.Proxy = scanProxy
	}
	if scanBlockPrivate {
		cfg.BlockPrivateIPs = true
	}
	if cfg.Headers == nil {
		cfg.Headers = make(map[string]string)
	}
	for _, h := range scanHeaders {
		if idx := strings.Index(h, ":"); idx > 0 {
			k := strings.TrimSpace(h[:idx])
			v := strings.TrimSpace(h[idx+1:])
			cfg.Headers[k] = v
		}
	}

	return cfg
}

func openStore(cfg *config.Config) database.Store {
	store := database.NewSQLiteStore(logger)
	if err := store.Open(filepath.Join(cfg.OutputDir, "threatlens.db")); err != nil {
		logger.Warn("database unavailable, skipping persistence", zap.Error(err))
		return nil
	}
	return store
}

func writeReport(cfg *config.Config, rep *models.Report) error {
	name := strings.TrimSpace(scanName)
	if name == "" {
		name = "report"
	}

	if err := os.MkdirAll(cfg.OutputDir, 0750); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	outPath := filepath.Join(cfg.OutputDir, name+"."+scanFormat)
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open report file: %w", err)
	}
	defer f.Close()

	gen := report.GeneratorFor(models.ReportFormat(scanFormat), logger)
	var buf bytes.Buffer
	if err := gen.Generate(context.Background(), rep, &buf); err != nil {
		return err
	}
	if _, err = f.Write(buf.Bytes()); err != nil {
		return err
	}
	logger.Info("report saved", zap.String("path", outPath))
	return nil
}

func checkFailThreshold(rep *models.Report, threshold string) (bool, error) {
	rank := func(s models.Severity) int {
		switch s {
		case models.SeverityCritical:
			return 4
		case models.SeverityHigh:
			return 3
		case models.SeverityMedium:
			return 2
		case models.SeverityLow:
			return 1
		default:
			return 0
		}
	}
	minRank := rank(models.Severity(strings.ToUpper(strings.TrimSpace(threshold))))
	if minRank == 0 {
		return false, fmt.Errorf("invalid --fail-on severity %q (expected low, medium, high, or critical)", threshold)
	}
	for sev, count := range rep.Summary.BySeverity {
		if count > 0 && rank(sev) >= minRank {
			return true, nil
		}
	}
	return false, nil
}

