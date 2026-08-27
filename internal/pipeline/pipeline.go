// Package pipeline orchestrates the Reconpipeline scan stages with modularity,
// caching, dependency validation, and concurrency control.
package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/frozeniceee/Reconpipeline/internal/cache"
	"github.com/frozeniceee/Reconpipeline/internal/config"
	"github.com/frozeniceee/Reconpipeline/internal/intelligence/asset"
	"github.com/frozeniceee/Reconpipeline/internal/intelligence/dns"
	"github.com/frozeniceee/Reconpipeline/internal/intelligence/status"
	"github.com/frozeniceee/Reconpipeline/internal/intelligence/tech"
	"github.com/frozeniceee/Reconpipeline/internal/logging"
	"github.com/frozeniceee/Reconpipeline/internal/scope"
	"github.com/frozeniceee/Reconpipeline/internal/tools/gau"
	"github.com/frozeniceee/Reconpipeline/internal/tools/gf"
	"github.com/frozeniceee/Reconpipeline/internal/tools/httpx"
	"github.com/frozeniceee/Reconpipeline/internal/tools/katana"
	"github.com/frozeniceee/Reconpipeline/internal/tools/subfinder"
	"github.com/frozeniceee/Reconpipeline/internal/urlprocessor"
	"github.com/frozeniceee/Reconpipeline/internal/workspace"
)

// Options configures a pipeline run.
type Options struct {
	// OutputRoot is the directory where target results are stored.
	OutputRoot string
	// Mode is the scan mode: "full", "active", "passive".
	Mode string
	// Profile is the execution profile: "full", "fast", "passive".
	Profile string
	// Threads is the concurrency level passed to tools.
	Threads int
	// Resume indicates whether to resume an interrupted scan.
	Resume bool
	// DryRun indicates whether to simulate without running tools.
	DryRun bool
	// NoCache indicates whether to bypass stage caching.
	NoCache bool
	// Timeout is the scan timeout limit.
	Timeout time.Duration
}

// Pipeline orchestrates tool execution across all 6 stages.
type Pipeline struct {
	target    *scope.Target
	opts      Options
	ws        *workspace.Manager
	cache     *cache.Manager
	state     *RunState
	runFile   string
	subfinder *subfinder.Tool
	httpx     *httpx.Tool
	katana    *katana.Tool
	gau       *gau.Tool
	gf        *gf.Tool
}

// New creates a Pipeline.
func New(target *scope.Target, opts Options, ws *workspace.Manager) *Pipeline {
	cacheMgr := cache.NewManager(filepath.Join(ws.LogsDir(), "..", "cache"), !opts.NoCache)

	// Apply profile defaults if specified
	if opts.Profile != "" {
		prof := config.GetProfile(opts.Profile)
		if opts.Mode == "" || opts.Mode == "full" {
			opts.Mode = prof.Mode
		}
		if opts.Threads <= 0 {
			opts.Threads = prof.Threads
		}
	}
	if opts.Threads <= 0 {
		opts.Threads = config.DefaultThreads
	}
	if opts.Mode == "" {
		opts.Mode = config.DefaultMode
	}

	return &Pipeline{
		target:    target,
		opts:      opts,
		ws:        ws,
		cache:     cacheMgr,
		subfinder: subfinder.New(ws),
		httpx:     httpx.New(ws),
		katana:    katana.New(ws),
		gau:       gau.New(ws),
		gf:        gf.New(ws),
	}
}

// Run executes the full pipeline for the target.
func (p *Pipeline) Run(ctx context.Context) error {
	domain, _ := scope.SafeFilename(p.target.Domain)
	targetDir := p.ws.TargetDir(p.opts.OutputRoot, domain)

	// Initialise or load run state.
	p.runFile = workspace.RunFilePath(targetDir)
	if p.opts.Resume && workspace.Exists(p.runFile) {
		existing, err := Load(p.runFile)
		if err == nil {
			p.state = existing
		}
	}
	if p.state == nil {
		p.state = NewRunState(p.target.Raw, p.target.Domain, p.opts.Mode)
		p.state.Profile = p.opts.Profile
	}

	// Create target directory structure.
	if err := p.ws.InitTargetDirs(targetDir); err != nil {
		return fmt.Errorf("failed to create result directories: %w", err)
	}

	p.saveState()

	// Stage directory helpers.
	stageDir := func(n int, name string) string {
		return p.ws.StageDir(targetDir, n, name)
	}

	warnings := []string{}
	var err error

	// ─── Stage 01: Subdomain Discovery ───────────────────────────────────────
	stage1Dir := stageDir(1, "subdomain-discovery")
	subdomainsFile := filepath.Join(stage1Dir, "subdomains.txt")
	if !p.shouldSkip("subdomain-discovery", subdomainsFile) {
		err = p.runStage(ctx, "subdomain-discovery", stage1Dir, func() error {
			if subErr := p.subfinder.Run(ctx, p.target.Domain, subdomainsFile, p.opts.Threads); subErr != nil {
				return subErr
			}
			// Intelligent Asset Classification
			classifier := asset.NewClassifier()
			classResults, _ := classifier.ProcessSubdomains(subdomainsFile, stage1Dir)
			if classResults != nil {
				p.state.Counters.AssetsClassified = len(classResults)
			}

			// DNS Intelligence Gathering
			dnsResolver := dns.NewEngine(p.opts.Threads)
			dnsResults, _ := dnsResolver.ProcessSubdomains(ctx, subdomainsFile, stage1Dir)
			if dnsResults != nil {
				p.state.Counters.DNSResolved = len(dnsResults)
			}

			return nil
		})
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Subdomain Discovery encountered an error: %v", err))
		}
	}
	p.state.Counters.Subdomains = urlprocessor.CountLines(subdomainsFile)

	// ─── Stage 02: Live Host Detection (HTTPX) ───────────────────────────────
	stage2Dir := stageDir(2, "live-host-detection")
	liveHostsFile := filepath.Join(stage2Dir, "live-hosts.txt")
	metaFile := filepath.Join(stage2Dir, "metadata.json")
	if !p.shouldSkip("live-host-detection", liveHostsFile) {
		err = p.runStage(ctx, "live-host-detection", stage2Dir, func() error {
			if hErr := p.httpx.Run(ctx, subdomainsFile, liveHostsFile, p.opts.Threads); hErr != nil {
				return hErr
			}

			// Technology Intelligence Gathering
			techEngine := tech.NewEngine()
			techDir := filepath.Join(stage2Dir, "technologies")
			techResults, _ := techEngine.ProcessMetadata(metaFile, techDir)
			if techResults != nil {
				p.state.Counters.TechnologiesDetected = len(techResults)
			}

			// HTTP Status Intelligence Categorization
			statusEngine := status.NewEngine()
			statusDir := filepath.Join(stage2Dir, "status")
			_, _ = statusEngine.ProcessMetadata(metaFile, statusDir)

			return nil
		})
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Live Host Detection encountered an error: %v", err))
		}
	}
	p.state.Counters.LiveHosts = urlprocessor.CountLines(liveHostsFile)

	// ─── Stage 03 & 04: Crawling & Historical (Parallel Execution) ───────────
	katanaFile := filepath.Join(stageDir(3, "active-crawling"), "katana-urls.txt")
	gauFile := filepath.Join(stageDir(4, "historical-url-discovery"), "gau-urls.txt")

	katanaSkip := p.shouldSkip("active-crawling", katanaFile)
	gauSkip := p.shouldSkip("historical-url-discovery", gauFile)

	var wg sync.WaitGroup
	var katanaErr, gauErr error

	if p.opts.Mode == "passive" || p.opts.Profile == "passive" {
		p.state.SetStageStatus("active-crawling", StatusSkipped)
		p.saveState()
		katanaSkip = true
	}

	// Active Crawling (Katana)
	if !katanaSkip {
		wg.Add(1)
		go func() {
			defer wg.Done()
			katanaErr = p.runStage(ctx, "active-crawling", stageDir(3, "active-crawling"), func() error {
				kErr := p.katana.Run(ctx, liveHostsFile, p.target.Domain, katanaFile, p.opts.Threads)
				katanaSub := filepath.Join(stageDir(3, "active-crawling"), "katana", "urls.txt")
				if data, readErr := os.ReadFile(katanaFile); readErr == nil {
					_ = os.WriteFile(katanaSub, data, 0640)
				}
				return kErr
			})
		}()
	}

	// Historical URL Discovery (GAU)
	if !gauSkip && p.opts.Mode != "active" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			gauErr = p.runStage(ctx, "historical-url-discovery", stageDir(4, "historical-url-discovery"), func() error {
				gErr := p.gau.Run(ctx, liveHostsFile, p.target.Domain, gauFile, p.opts.Threads)
				gauSub := filepath.Join(stageDir(4, "historical-url-discovery"), "gau", "urls.txt")
				if data, readErr := os.ReadFile(gauFile); readErr == nil {
					_ = os.WriteFile(gauSub, data, 0640)
				}
				return gErr
			})
		}()
	} else if p.opts.Mode == "active" {
		p.state.SetStageStatus("historical-url-discovery", StatusSkipped)
		p.saveState()
	}

	wg.Wait()

	if katanaErr != nil {
		warnings = append(warnings, fmt.Sprintf("Active Crawling encountered an error: %v", katanaErr))
	}
	if gauErr != nil {
		warnings = append(warnings, fmt.Sprintf("Historical URL Discovery encountered an error: %v", gauErr))
	}

	p.state.Counters.KatanaURLs = urlprocessor.CountLines(katanaFile)
	p.state.Counters.GAUURLs = urlprocessor.CountLines(gauFile)

	// ─── Stage 05: URL Processing (Smart URL Engine) ──────────────────────────
	urlProcDir := stageDir(5, "url-processing")
	uniqueURLsFile := filepath.Join(urlProcDir, "unique-urls.txt")
	var urlResults *urlprocessor.Results

	if !p.shouldSkip("url-processing", uniqueURLsFile) {
		err = p.runStage(ctx, "url-processing", urlProcDir, func() error {
			var procErr error
			urlResults, procErr = urlprocessor.Process(katanaFile, gauFile, urlProcDir)
			return procErr
		})
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("URL Processing encountered an error: %v", err))
		}
	}
	if urlResults != nil {
		p.state.Counters.TotalURLs = urlResults.TotalMerged
		p.state.Counters.UniqueURLs = urlResults.Unique
		p.state.Counters.APIURLs = urlResults.API
		p.state.Counters.JavaScriptURLs = urlResults.JavaScript
		p.state.Counters.ParamURLs = urlResults.Parameterised
		p.state.Counters.InterestingURLs = urlResults.Interesting
		p.state.Counters.URLClusters = urlResults.TotalClusters
		p.state.Counters.HighPriorityURLs = urlResults.HighPriority
		p.state.Counters.MediumPriorityURLs = urlResults.MediumPriority
		p.state.Counters.LowPriorityURLs = urlResults.LowPriority
	}

	// ─── Stage 06: Pattern Analysis (GF) ─────────────────────────────────────
	patternDir := stageDir(6, "pattern-analysis")
	summaryPatternFile := filepath.Join(patternDir, "patterns", "pattern-summary.json")

	if !p.shouldSkip("pattern-analysis", summaryPatternFile) {
		err = p.runStage(ctx, "pattern-analysis", patternDir, func() error {
			counts, runErr := p.gf.RunAll(ctx, uniqueURLsFile, patternDir)
			if counts != nil {
				p.state.Counters.XSSMatches = counts["xss"]
				p.state.Counters.SQLiMatches = counts["sqli"]
				p.state.Counters.LFIMatches = counts["lfi"]
				p.state.Counters.SSRFMatches = counts["ssrf"]
				p.state.Counters.RedirectMatches = counts["redirect"]

				summaryData, _ := json.MarshalIndent(counts, "", "  ")
				_ = os.WriteFile(summaryPatternFile, summaryData, 0640)

				for pName := range counts {
					src := filepath.Join(patternDir, pName+".txt")
					dst := filepath.Join(patternDir, "gf", pName+".txt")
					if d, rErr := os.ReadFile(src); rErr == nil {
						_ = os.WriteFile(dst, d, 0640)
					}
				}
			}
			return runErr
		})
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Pattern Analysis encountered an error: %v", err))
		}
	}

	// ─── Generate Summary Folder ──────────────────────────────────────────────
	summaryDir := filepath.Join(targetDir, "summary")
	_ = os.MkdirAll(summaryDir, 0750)
	statsJSON, _ := json.MarshalIndent(p.state.Counters, "", "  ")
	_ = os.WriteFile(filepath.Join(summaryDir, "statistics.json"), statsJSON, 0640)

	summaryTxt := fmt.Sprintf("Target: %s\nMode: %s\nProfile: %s\nSubdomains: %d\nLive Hosts: %d\nUnique URLs: %d\nAPI URLs: %d\nJS URLs: %d\nParameters: %d\nClusters: %d\nHigh Priority: %d\n",
		p.target.Domain, p.opts.Mode, p.opts.Profile, p.state.Counters.Subdomains, p.state.Counters.LiveHosts, p.state.Counters.UniqueURLs, p.state.Counters.APIURLs, p.state.Counters.JavaScriptURLs, p.state.Counters.ParamURLs, p.state.Counters.URLClusters, p.state.Counters.HighPriorityURLs)
	_ = os.WriteFile(filepath.Join(summaryDir, "summary.txt"), []byte(summaryTxt), 0640)

	// Finalise state.
	for _, w := range warnings {
		p.state.AddWarning(w)
	}
	p.state.Finish()
	p.saveState()

	return nil
}

// runStage executes a stage function, tracking state and caching.
func (p *Pipeline) runStage(ctx context.Context, name, outDir string, fn func() error) error {
	select {
	case <-ctx.Done():
		p.state.MarkInterrupted()
		p.saveState()
		return ctx.Err()
	default:
	}

	p.state.SetStageStatus(name, StatusRunning)
	p.saveState()

	err := fn()

	if err != nil {
		if ctx.Err() != nil {
			p.state.SetStageStatus(name, StatusInterrupted)
			p.state.MarkInterrupted()
			p.saveState()
			return ctx.Err()
		}
		p.state.SetStageError(name, err)
		p.state.AddError(fmt.Sprintf("%s: %v", name, err))
		p.saveState()
		return err
	}

	p.state.SetStageCompleted(name, outDir, false)
	p.saveState()
	return nil
}

// shouldSkip returns true if resume mode is on, the stage is completed, and required output exists.
func (p *Pipeline) shouldSkip(name, requiredFile string) bool {
	if !p.opts.Resume {
		return false
	}
	if !p.state.StageCompleted(name) {
		return false
	}
	if requiredFile != "" && !workspace.Exists(requiredFile) {
		return false
	}
	return true
}

// saveState persists the current run state silently.
func (p *Pipeline) saveState() {
	if p.runFile == "" {
		return
	}
	if err := p.state.Save(p.runFile); err != nil {
		logging.Verbose("Failed to save run state: %v", err)
	}
}

// State returns the current run state (for reporting).
func (p *Pipeline) State() *RunState {
	return p.state
}
