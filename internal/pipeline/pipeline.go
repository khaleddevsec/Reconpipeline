// Package pipeline orchestrates the Reconpipeline scan stages with modularity,
// caching, dependency validation, and concurrency control.
package pipeline

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/khaleddevsec/Reconpipeline/internal/cache"
	"github.com/khaleddevsec/Reconpipeline/internal/config"
	"github.com/khaleddevsec/Reconpipeline/internal/intelligence/asset"
	"github.com/khaleddevsec/Reconpipeline/internal/intelligence/dns"
	"github.com/khaleddevsec/Reconpipeline/internal/intelligence/status"
	"github.com/khaleddevsec/Reconpipeline/internal/intelligence/tech"
	"github.com/khaleddevsec/Reconpipeline/internal/logging"
	"github.com/khaleddevsec/Reconpipeline/internal/scope"
	"github.com/khaleddevsec/Reconpipeline/internal/tools/gau"
	"github.com/khaleddevsec/Reconpipeline/internal/tools/gf"
	"github.com/khaleddevsec/Reconpipeline/internal/tools/httpx"
	"github.com/khaleddevsec/Reconpipeline/internal/tools/katana"
	"github.com/khaleddevsec/Reconpipeline/internal/tools/subfinder"
	"github.com/khaleddevsec/Reconpipeline/internal/urlprocessor"
	"github.com/khaleddevsec/Reconpipeline/internal/workspace"
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
	// Exclusions is a list of domains, subdomains, or CIDRs to exclude from scope.
	Exclusions []string
}

// Pipeline orchestrates tool execution across all 6 stages.
type Pipeline struct {
	target    *scope.Target
	policy    *scope.Policy
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
		policy:    scope.NewPolicy(target, opts.Exclusions...),
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

			// Enforce centralized scope policy on discovered subdomains
			if rawSubs := readLines(subdomainsFile); len(rawSubs) > 0 {
				var inScopeSubs []string
				for _, sub := range rawSubs {
					if p.policy.IsHostInScope(sub) {
						inScopeSubs = append(inScopeSubs, sub)
					}
				}
				_ = writeLines(subdomainsFile, inScopeSubs)
			}
			// Intelligent Asset Classification
			classifier := asset.NewClassifier()
			classResults, _ := classifier.ProcessSubdomains(subdomainsFile, stage1Dir)
			if classResults != nil {
				p.state.Counters.AssetsClassified = len(classResults)
			}

			// DNS Intelligence Gathering
			dnsResolver := dns.NewEngine(p.opts.Threads)
			dnsResults, _ := dnsResolver.ProcessSubdomains(ctx, subdomainsFile, stage1Dir, p.target.Domain)
			if dnsResults != nil {
				p.state.Counters.DNSResolved = len(dnsResults)
			}
			if wcData, err := os.ReadFile(filepath.Join(stage1Dir, "wildcard.txt")); err == nil && len(wcData) > 0 {
				warnings = append(warnings, fmt.Sprintf("Wildcard DNS detected for %s", p.target.Domain))
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
			if hErr := p.httpx.Run(ctx, subdomainsFile, stage2Dir, p.opts.Threads); hErr != nil {
				return hErr
			}

			// If no live hosts detected from subdomains, seed target as fallback
			if urlprocessor.CountLines(liveHostsFile) == 0 {
				seedHosts := fmt.Sprintf("https://%s\nhttp://%s\n", p.target.Domain, p.target.Domain)
				_ = os.WriteFile(liveHostsFile, []byte(seedHosts), 0640)
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
				crawlDepth := 3
				if prof := config.GetProfile(p.opts.Profile); prof.CrawlDepth > 0 {
					crawlDepth = prof.CrawlDepth
				}
				kErr := p.katana.Run(ctx, liveHostsFile, p.target.Domain, katanaFile, p.opts.Threads, crawlDepth)
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

	// ─── Stage 06: URL Verification (HTTPX #2) ──────────────────────────────
	stage6Dir := stageDir(6, "url-verification")
	inputURLsFile := filepath.Join(stage6Dir, "input-urls.txt")
	verifiedURLsFile := filepath.Join(stage6Dir, "verified-urls.txt")

	verifySkip := p.shouldSkip("url-verification", verifiedURLsFile)

	if p.opts.Mode == "passive" || p.opts.Profile == "passive" {
		p.state.SetStageStatus("url-verification", StatusSkipped)
		p.saveState()
		verifySkip = true
	}

	if !verifySkip {
		err = p.runStage(ctx, "url-verification", stage6Dir, func() error {
			// Read unique URLs from Stage 5
			uniqueURLs := readLines(uniqueURLsFile)

			// Determine max verification URLs
			maxVerify := 5000
			if p.opts.Profile != "" {
				prof := config.GetProfile(p.opts.Profile)
				if prof.MaxVerifyURLs > 0 {
					maxVerify = prof.MaxVerifyURLs
				}
			}

			// Smart URL Selection: conservative filtering & prioritization with centralized policy
			selected := urlprocessor.SelectForVerificationWithPolicy(uniqueURLs, p.policy, maxVerify)

			// Write input-urls.txt
			if err := writeLines(inputURLsFile, selected); err != nil {
				return fmt.Errorf("failed to write input-urls.txt: %w", err)
			}

			// Execute HTTPX #2
			if len(selected) > 0 {
				if vErr := p.httpx.VerifyURLs(ctx, inputURLsFile, stage6Dir, p.opts.Threads); vErr != nil {
					return vErr
				}
			} else {
				_ = os.WriteFile(verifiedURLsFile, []byte{}, 0640)
				_ = os.WriteFile(filepath.Join(stage6Dir, "httpx.jsonl"), []byte{}, 0640)
				_ = os.WriteFile(filepath.Join(stage6Dir, "metadata.json"), []byte("[]"), 0640)
			}
			return nil
		})
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("URL Verification encountered an error: %v", err))
		}
	}
	p.state.Counters.SelectedURLs = urlprocessor.CountLines(inputURLsFile)
	p.state.Counters.VerifiedURLs = urlprocessor.CountLines(verifiedURLsFile)

	// ─── Stage 07: Pattern Analysis (GF) ─────────────────────────────────────
	stage7Dir := stageDir(7, "pattern-analysis")
	legacyStage6Dir := filepath.Join(targetDir, "06-pattern-analysis")
	summaryPatternFile := filepath.Join(stage7Dir, "patterns", "pattern-summary.json")

	// Determine GF input file: use verified URLs if available, fallback to unique URLs
	gfInputFile := verifiedURLsFile
	if urlprocessor.CountLines(verifiedURLsFile) == 0 {
		gfInputFile = uniqueURLsFile
	}

	if !p.shouldSkip("pattern-analysis", summaryPatternFile) {
		err = p.runStage(ctx, "pattern-analysis", stage7Dir, func() error {
			actx := &gf.AnalysisContext{
				TargetDomain:     p.target.Domain,
				VerifiedURLsFile: gfInputFile,
				HTTPX2MetaFile:   filepath.Join(stageDir(6, "url-verification"), "metadata.json"),
				HTTPX1MetaFile:   filepath.Join(stageDir(2, "live-host-detection"), "metadata.json"),
				DNSRecordsFile:   filepath.Join(stageDir(1, "subdomain-discovery"), "dns", "dns-records.json"),
				SubdomainsFile:   subdomainsFile,
				LiveHostsFile:    liveHostsFile,
			}

			summary, counts, runErr := p.gf.RunIntelligence(ctx, actx, gfInputFile, stage7Dir)
			if counts != nil {
				p.state.Counters.XSSMatches = counts["xss"]
				p.state.Counters.SQLiMatches = counts["sqli"]
				p.state.Counters.LFIMatches = counts["lfi"]
				p.state.Counters.SSRFMatches = counts["ssrf"]
				p.state.Counters.RedirectMatches = counts["redirect"]

				if summary != nil {
					p.state.Counters.TotalCandidates = summary.TotalMatches
					p.state.Counters.HighConfidenceCandidates = summary.ConfidenceCounts[gf.ConfidenceHigh]
					p.state.Counters.TakeoverCandidates = summary.TakeoverCount
					if apiCat, ok := summary.Categories[string(gf.CategoryAPI)]; ok {
						p.state.Counters.APICandidates = apiCat.TotalMatches
					}
					if authCat, ok := summary.Categories[string(gf.CategoryAuth)]; ok {
						p.state.Counters.AuthCandidates = authCat.TotalMatches
					}
					if admCat, ok := summary.Categories[string(gf.CategoryAdmin)]; ok {
						p.state.Counters.AdminCandidates = admCat.TotalMatches
					}
					if sensCat, ok := summary.Categories[string(gf.CategorySensitiveFile)]; ok {
						p.state.Counters.SensitiveFileCandidates = sensCat.TotalMatches
					}
				}

				// Backward compatibility copy to legacy 06-pattern-analysis
				_ = os.MkdirAll(filepath.Join(legacyStage6Dir, "patterns"), 0750)
				_ = os.MkdirAll(filepath.Join(legacyStage6Dir, "gf"), 0750)
				if summaryData, rErr := os.ReadFile(summaryPatternFile); rErr == nil {
					_ = os.WriteFile(filepath.Join(legacyStage6Dir, "patterns", "pattern-summary.json"), summaryData, 0640)
				}
				if resData, rErr := os.ReadFile(filepath.Join(stage7Dir, "patterns", "pattern-results.json")); rErr == nil {
					_ = os.WriteFile(filepath.Join(legacyStage6Dir, "patterns", "pattern-results.json"), resData, 0640)
				}
				if takeData, rErr := os.ReadFile(filepath.Join(stage7Dir, "patterns", "takeover-candidates.json")); rErr == nil {
					_ = os.WriteFile(filepath.Join(legacyStage6Dir, "patterns", "takeover-candidates.json"), takeData, 0640)
				}

				for pName := range counts {
					src := filepath.Join(stage7Dir, pName+".txt")
					dst := filepath.Join(stage7Dir, "gf", pName+".txt")
					if d, rErr := os.ReadFile(src); rErr == nil {
						_ = os.WriteFile(dst, d, 0640)
						_ = os.WriteFile(filepath.Join(legacyStage6Dir, pName+".txt"), d, 0640)
						_ = os.WriteFile(filepath.Join(legacyStage6Dir, "gf", pName+".txt"), d, 0640)
					}
				}
				// Copy takeover-candidates.txt and other-patterns.txt to legacy stage
				for _, extra := range []string{"takeover-candidates.txt", "other-patterns.txt"} {
					src := filepath.Join(stage7Dir, extra)
					if d, rErr := os.ReadFile(src); rErr == nil {
						_ = os.WriteFile(filepath.Join(legacyStage6Dir, extra), d, 0640)
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

	summaryTxt := fmt.Sprintf("Target: %s\nMode: %s\nProfile: %s\nSubdomains: %d\nLive Hosts: %d\nUnique URLs: %d\nSelected URLs: %d\nVerified URLs: %d\nAPI URLs: %d\nJS URLs: %d\nParameters: %d\nClusters: %d\nHigh Priority: %d\n",
		p.target.Domain, p.opts.Mode, p.opts.Profile, p.state.Counters.Subdomains, p.state.Counters.LiveHosts, p.state.Counters.UniqueURLs, p.state.Counters.SelectedURLs, p.state.Counters.VerifiedURLs, p.state.Counters.APIURLs, p.state.Counters.JavaScriptURLs, p.state.Counters.ParamURLs, p.state.Counters.URLClusters, p.state.Counters.HighPriorityURLs)
	_ = os.WriteFile(filepath.Join(summaryDir, "summary.txt"), []byte(summaryTxt), 0640)

	// Finalise state.
	for _, w := range warnings {
		p.state.AddWarning(w)
	}
	p.state.Finish()
	p.saveState()

	return nil
}

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 512*1024), 512*1024)
	for scanner.Scan() {
		t := strings.TrimSpace(scanner.Text())
		if t != "" {
			lines = append(lines, t)
		}
	}
	return lines
}

func writeLines(path string, lines []string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	return w.Flush()
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

	domain, _ := scope.SafeFilename(p.target.Domain)
	inputHash := cache.ComputeHash(p.target.Domain + ":" + p.opts.Mode + ":" + p.opts.Profile)

	// Check stage cache if enabled
	if p.cache != nil && p.cache.IsEnabled() && !p.opts.NoCache {
		if entry, entryDir, hit := p.cache.Get(domain, name, inputHash); hit && entry != nil {
			if err := p.cache.RestoreArtifacts(entryDir, outDir); err == nil {
				logging.Verbose("Cache hit for stage %s (target: %s)", name, domain)
				p.state.SetStageCompleted(name, outDir, true)
				p.saveState()
				return nil
			}
		}
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

	// Cache successful stage outputs
	if p.cache != nil && p.cache.IsEnabled() && !p.opts.NoCache {
		if files, cErr := cache.CollectStageFiles(outDir); cErr == nil && len(files) > 0 {
			_ = p.cache.Put(domain, name, inputHash, files, nil)
		}
	}

	p.state.SetStageCompleted(name, outDir, false)
	p.saveState()
	return nil
}

// shouldSkip returns true if resume mode is on, the stage is completed, and required output exists and is non-empty.
func (p *Pipeline) shouldSkip(name, requiredFile string) bool {
	if !p.opts.Resume {
		return false
	}
	if !p.state.StageCompleted(name) {
		return false
	}
	if requiredFile != "" {
		fi, err := os.Stat(requiredFile)
		if err != nil || fi.Size() == 0 {
			return false
		}
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
