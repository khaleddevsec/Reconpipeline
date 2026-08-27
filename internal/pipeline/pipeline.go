// Package pipeline orchestrates the Reconpipeline scan stages.
package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

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
	// Threads is the concurrency level passed to tools.
	Threads int
	// Resume skips completed stages.
	Resume bool
	// DryRun shows the plan without executing.
	DryRun bool
}

// StageResult is the result of executing one pipeline stage.
type StageResult struct {
	Name    string
	Success bool
	Warning string
	Error   error
}

// Pipeline is the main orchestration engine.
type Pipeline struct {
	target  *scope.Target
	opts    Options
	ws      *workspace.Manager
	state   *RunState
	runFile string

	// Tool adapters.
	subfinder *subfinder.Tool
	httpx     *httpx.Tool
	katana    *katana.Tool
	gau       *gau.Tool
	gf        *gf.Tool
}

// New creates a Pipeline.
func New(target *scope.Target, opts Options, ws *workspace.Manager) *Pipeline {
	return &Pipeline{
		target:    target,
		opts:      opts,
		ws:        ws,
		subfinder: subfinder.New(ws),
		httpx:     httpx.New(ws),
		katana:    katana.New(ws),
		gau:       gau.New(ws),
		gf:        gf.New(ws),
	}
}

// Run executes the full pipeline for the target.
// It handles resume, stage errors, and updates run.json throughout.
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
	if !p.shouldSkip("subdomain-discovery") {
		err = p.runStage(ctx, "subdomain-discovery", func() error {
			if subErr := p.subfinder.Run(ctx, p.target.Domain, subdomainsFile, p.opts.Threads); subErr != nil {
				return subErr
			}
			// Intelligent Asset Classification
			classifier := asset.NewClassifier()
			assets, _ := classifier.ProcessSubdomains(subdomainsFile, stage1Dir)
			p.state.Counters.AssetsClassified = len(assets)

			// DNS Intelligence Gathering
			dnsEngine := dns.NewEngine(p.opts.Threads)
			dnsRecs, _ := dnsEngine.ProcessSubdomains(ctx, subdomainsFile, filepath.Join(stage1Dir, "dns"))
			p.state.Counters.DNSResolved = len(dnsRecs)
			return nil
		})
		if err != nil {
			return err
		}
	}
	p.state.Counters.Subdomains = urlprocessor.CountLines(subdomainsFile)

	// ─── Stage 02: Live Host Detection ───────────────────────────────────────
	liveHostDir := stageDir(2, "live-host-detection")
	liveHostsFile := filepath.Join(liveHostDir, "live-hosts.txt")
	metaFile := filepath.Join(liveHostDir, "metadata.json")
	if !p.shouldSkip("live-host-detection") {
		err = p.runStage(ctx, "live-host-detection", func() error {
			if hErr := p.httpx.Run(ctx, subdomainsFile, liveHostDir, p.opts.Threads); hErr != nil {
				return hErr
			}
			// Technology Intelligence Grouping
			techEngine := tech.NewEngine()
			groups, _ := techEngine.ProcessMetadata(metaFile, filepath.Join(liveHostDir, "technologies"))
			p.state.Counters.TechnologiesDetected = len(groups)

			// HTTP Status Intelligence Organization
			statusEngine := status.NewEngine()
			_, _ = statusEngine.ProcessMetadata(metaFile, filepath.Join(liveHostDir, "status"))
			return nil
		})
		if err != nil {
			return err
		}
	}
	liveHostsCount := urlprocessor.CountLines(liveHostsFile)
	if liveHostsCount == 0 {
		// Fallback: if no live hosts found, seed target host URL so active crawl proceeds
		targetURL := "https://" + p.target.Domain
		if p.target.Scheme != "" {
			targetURL = p.target.Scheme + "://" + p.target.Domain
		}
		_ = os.WriteFile(liveHostsFile, []byte(targetURL+"\n"), 0640)
		liveHostsCount = urlprocessor.CountLines(liveHostsFile)
	}
	p.state.Counters.LiveHosts = liveHostsCount

	// ─── Stages 03 + 04: Katana & GAU (concurrent) ───────────────────────────
	katanaFile := filepath.Join(stageDir(3, "active-crawling"), "katana-urls.txt")
	gauFile := filepath.Join(stageDir(4, "historical-url-discovery"), "gau-urls.txt")

	katanaSkip := p.shouldSkip("active-crawling")
	gauSkip := p.shouldSkip("historical-url-discovery")

	if !katanaSkip || !gauSkip {
		var wg sync.WaitGroup
		var katanaErr, gauErr error

		if p.opts.Mode == "passive" {
			// Passive mode: skip active crawling.
			katanaSkip = true
			p.state.SetStageStatus("active-crawling", StatusSkipped)
			p.saveState()
		}

		if !katanaSkip {
			wg.Add(1)
			go func() {
				defer wg.Done()
				katanaErr = p.runStage(ctx, "active-crawling", func() error {
					kErr := p.katana.Run(ctx, liveHostsFile, scope.RootDomain(p.target.Domain), katanaFile, p.opts.Threads)
					// Mirror into katana/ subfolder for organized view
					katanaSub := filepath.Join(stageDir(3, "active-crawling"), "katana", "urls.txt")
					if data, readErr := os.ReadFile(katanaFile); readErr == nil {
						_ = os.WriteFile(katanaSub, data, 0640)
					}
					return kErr
				})
			}()
		}

		if !gauSkip && p.opts.Mode != "active" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				gauErr = p.runStage(ctx, "historical-url-discovery", func() error {
					gErr := p.gau.Run(ctx, liveHostsFile, p.target.Domain, gauFile, p.opts.Threads)
					// Mirror into gau/ subfolder for organized view
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
	}

	p.state.Counters.KatanaURLs = urlprocessor.CountLines(katanaFile)
	p.state.Counters.GAUURLs = urlprocessor.CountLines(gauFile)

	// ─── Stage 05: URL Processing (Smart URL Engine) ──────────────────────────
	urlProcDir := stageDir(5, "url-processing")
	var urlResults *urlprocessor.Results
	if !p.shouldSkip("url-processing") {
		err = p.runStage(ctx, "url-processing", func() error {
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
	uniqueURLsFile := filepath.Join(urlProcDir, "unique-urls.txt")
	if !p.shouldSkip("pattern-analysis") {
		err = p.runStage(ctx, "pattern-analysis", func() error {
			counts, runErr := p.gf.RunAll(ctx, uniqueURLsFile, patternDir)
			if counts != nil {
				p.state.Counters.XSSMatches = counts["xss"]
				p.state.Counters.SQLiMatches = counts["sqli"]
				p.state.Counters.LFIMatches = counts["lfi"]
				p.state.Counters.SSRFMatches = counts["ssrf"]
				p.state.Counters.RedirectMatches = counts["redirect"]

				// Write pattern summary JSON
				summaryData, _ := json.MarshalIndent(counts, "", "  ")
				_ = os.WriteFile(filepath.Join(patternDir, "patterns", "pattern-summary.json"), summaryData, 0640)

				// Mirror patterns into gf/ directory
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

	summaryTxt := fmt.Sprintf("Target: %s\nMode: %s\nSubdomains: %d\nLive Hosts: %d\nUnique URLs: %d\nAPI URLs: %d\nJS URLs: %d\nParameters: %d\nClusters: %d\nHigh Priority: %d\n",
		p.target.Domain, p.opts.Mode, p.state.Counters.Subdomains, p.state.Counters.LiveHosts, p.state.Counters.UniqueURLs, p.state.Counters.APIURLs, p.state.Counters.JavaScriptURLs, p.state.Counters.ParamURLs, p.state.Counters.URLClusters, p.state.Counters.HighPriorityURLs)
	_ = os.WriteFile(filepath.Join(summaryDir, "summary.txt"), []byte(summaryTxt), 0640)

	// Finalise.
	for _, w := range warnings {
		p.state.AddWarning(w)
	}
	p.state.Finish()
	p.saveState()

	return nil
}

// runStage executes a stage function, updating run state before and after.
func (p *Pipeline) runStage(ctx context.Context, name string, fn func() error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	p.state.SetStageStatus(name, StatusRunning)
	p.saveState()

	start := time.Now()
	err := fn()
	dur := time.Since(start)
	_ = dur

	if err != nil {
		if ctx.Err() != nil {
			p.state.SetStageStatus(name, StatusInterrupted)
			p.saveState()
			return ctx.Err()
		}
		p.state.SetStageStatus(name, StatusFailed)
		p.state.AddError(fmt.Sprintf("%s: %v", name, err))
		p.saveState()
		return err
	}

	p.state.SetStageStatus(name, StatusCompleted)
	p.saveState()
	return nil
}

// shouldSkip returns true if resume mode is on and the stage is completed.
func (p *Pipeline) shouldSkip(name string) bool {
	if !p.opts.Resume {
		return false
	}
	return p.state.StageCompleted(name)
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
