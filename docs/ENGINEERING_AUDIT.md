# ReconPipeline — Comprehensive Engineering Audit

**Audit Date**: October 2026  
**Auditor**: Senior Go / Security Tool Engineer  
**Branch**: `develop`  
**Repository**: `github.com/khaleddevsec/Reconpipeline`

---

## 1. Executive Summary

This engineering audit assesses the architectural integrity, security boundaries, correctness, and operational reliability of ReconPipeline v2.6.0. The audit verified actual source code, test suites, and runtime behaviors.

While the pipeline features a modular multi-stage structure (subdomains, live hosts, crawling, historical URLs, smart URL engine, verification, pattern intelligence), multiple critical and high-severity defects were confirmed:
1. **Unchecked SSRF / Private IP Probing**: Subdomains resolving to loopback (`127.0.0.1`), cloud metadata (`169.254.169.254`), or private RFC 1918 subnets are passed directly to HTTPX without scope policy validation.
2. **Missing Crawl Scope Enforcement in Katana**: Katana is executed with `_ = rootDomain`, ignoring the scoped root domain and lacking domain regex filters, allowing crawler link extraction to traverse out-of-scope third-party origins.
3. **Destructive URL Normalization & Loss of Provenance**: `urlengine.NormalizeURL` forcibly strips trailing slashes (`/path/` -> `/path`), sorts and re-encodes query parameters with `url.QueryEscape` (altering `%20` and query sequence), and mutates raw URLs without retaining source provenance (Katana vs. GAU), discovery timestamps, or referrers.
4. **Disconnected Stage Caching**: `cache.Manager` is initialized in `pipeline.New()`, but `p.cache.Get` and `p.cache.Put` are never invoked in `runStage()`, rendering inter-scan stage caching completely inactive.
5. **Stored Cross-Site Scripting (XSS) in HTML Dashboard**: HTTP response page titles (`ca.OldTitle`, `ca.NewTitle`) in delta comparisons are rendered into `report.html` without HTML escaping, enabling arbitrary script execution when an analyst inspects targets with hostile `<script>` titles.
6. **Binary Corruption on `reconpipeline update`**: `updater.Apply` streams raw HTTP response bytes directly into the target binary path without extracting the `.tar.gz` archive produced by the release pipeline.
7. **Inflated "Confirmed" Finding Confidences**: Pattern heuristics and HTTP status 200 responses are reported as "confirmed live sensitive file exposure" without secondary validation.

---

## 2. Findings Matrix

| ID | Category | Severity | File | Function / Component | Status |
|---|---|---|---|---|---|
| SEC-01 | Scope Enforcement | Critical | `internal/scope/scope.go`, `internal/pipeline/pipeline.go` | `InScope`, Stage 1 & 2 orchestration | Confirmed |
| SEC-02 | Scope / Crawling | High | `internal/tools/katana/katana.go` | `Run` | Confirmed |
| SEC-03 | Reporting / XSS | High | `internal/reporting/html.go` | `GenerateHTML` | Confirmed |
| ARCH-01 | URL Processing | High | `internal/intelligence/urlengine/engine.go` | `NormalizeURL`, `Process` | Confirmed |
| ARCH-02 | Caching | High | `internal/pipeline/pipeline.go` | `runStage`, `shouldSkip` | Confirmed |
| REL-01 | Lifecycle / Update | High | `internal/updater/updater.go` | `Apply` | Confirmed |
| SEC-04 | Pattern Intelligence | Medium | `internal/tools/gf/engine.go` | `EvaluateConfidence` | Confirmed |
| REL-02 | Subprocess Execution | Medium | `internal/executor/executor.go` | `RunToFile` | Confirmed |
| ARCH-03 | Delta Comparison | Medium | `internal/comparison/comparison.go` | `CompareScans` | Confirmed |
| REL-03 | Platform Compatibility | Low | `internal/dependencies/manager.go` | `installGf` | Confirmed |

---

## 3. Detailed Audit Findings

### SEC-01: Inadequate Scope Boundaries & Lack of SSRF/Private IP Range Filtering
- **File**: `internal/scope/scope.go:93`, `internal/pipeline/pipeline.go:165`
- **Severity**: **Critical**
- **Impact**: When scanning targets whose subdomains resolve to internal/private IPs (`127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`) or AWS/GCP/Azure instance metadata endpoints (`169.254.169.254`), HTTPX and Katana initiate active requests to those internal resources. Furthermore, `InScope` relies solely on `strings.HasSuffix(host, "."+rootDomain)` and lacks support for explicit CIDR/IP exclusions, out-of-scope host exclusions (e.g. `exclude.domain.com`), or port filtering.
- **Correction**: Introduce a centralized `scope.Policy` that verifies hostnames, parses exclusion lists, validates resolved IP addresses against public routing boundaries (blocking RFC 1918, RFC 3927 link-local, loopback, and broadcast ranges unless explicitly authorized), and re-validates URLs discovered dynamically.

---

### SEC-02: Missing Katana Crawl Scope Enforcement
- **File**: `internal/tools/katana/katana.go:35-69`
- **Severity**: **High**
- **Impact**: In `katana.Run(ctx, liveHostsFile, rootDomain, outFile, threads, optionalDepth...)`, `rootDomain` is suppressed with `_ = rootDomain`. Katana flags lack `-cs` (crawl scope regex) and `-cos` (crawl out of scope disabled). If a crawled page contains external links or off-origin JavaScript resources, Katana can crawl out-of-scope assets.
- **Correction**: Pass strict crawl scope regex (`-cs`) and field scope (`-fs fqdn`) matching the authorized root domain. Validate every URL emitted by Katana against `scope.Policy` before ingestion into Stage 05.

---

### SEC-03: Stored Cross-Site Scripting in HTML Dashboard
- **File**: `internal/reporting/html.go:261-267`
- **Severity**: **High**
- **Impact**: In `html.go`:
  ```go
  details = append(details, fmt.Sprintf("title: %q &rarr; %q", ca.OldTitle, ca.NewTitle))
  ```
  `ca.OldTitle` and `ca.NewTitle` contain HTML page titles retrieved from external endpoints. Because they are interpolated into `report.html` without `html.EscapeString()`, an adversary deploying a payload like `<title><script>alert(document.domain)</script></title>` can achieve stored code execution in the context of an analyst opening the local HTML report.
- **Correction**: Wrap all dynamically extracted text, page titles, URLs, and server headers in `html.EscapeString()`. Add test cases asserting that hostile payloads (`<script>`, `"><img onerror=...>`, etc.) are neutralized.

---

### ARCH-01: Destructive URL Normalization & Missing Identity Model
- **File**: `internal/intelligence/urlengine/engine.go:213-272`
- **Severity**: **High**
- **Impact**:
  1. `NormalizeURL` forcibly strips trailing slashes on all paths (`path = strings.TrimSuffix(path, "/")`). In HTTP servers, `/path` and `/path/` can point to distinct route handlers or trigger redirects.
  2. Query parameters are unescaped into a `url.Values` map, sorting keys but destroying the original parameter order, re-escaping with `url.QueryEscape` (converting spaces to `+` and altering pre-encoded tokens).
  3. Raw URLs are discarded; downstream stages receive mutated strings without knowledge of the original URL, collection source (Katana vs. GAU), parent referrers, or discovery timestamps.
- **Correction**: Create a structured `URLRecord` containing `OriginalURL`, `CanonicalKey`, `ParsedURL`, `Source`, `Timestamp`, and `ExtractionMethod`. Maintain `OriginalURL` for active verification while using `CanonicalKey` strictly for semantic deduplication. Preserve trailing slashes and raw query integrity.

---

### ARCH-02: Disconnected Stage Caching & Incomplete Resume Validation
- **File**: `internal/pipeline/pipeline.go:70, 492-536`, `internal/cache/cache.go`
- **Severity**: **High**
- **Impact**: `Pipeline.cache` is instantiated but neither checked nor populated within `runStage`. Only `p.opts.Resume` with `workspace.Exists(requiredFile)` skips stages. No hash verification occurs on resume, meaning corrupt or empty files from interrupted scans are treated as completed stages. Furthermore, cache keys do not incorporate scan profile, crawl depth, mode, or exclusion settings.
- **Correction**: Connect `cache.Manager` into `runStage`. Generate cache keys incorporating `target + stage + inputHash + profile + mode + toolVersion`. Before skipping an existing output on resume, verify file integrity and non-zero byte size.

---

### REL-01: Archive Extraction Failure During Self-Update
- **File**: `internal/updater/updater.go:180-202`
- **Severity**: **High**
- **Impact**: `updater.Apply` writes `resp.Body` directly to `exePath + ".update.tmp"` and swaps it into place. However, `.github/workflows/release.yml` packages release binaries inside `.tar.gz` archives. Applying an update replaces the executable with a tar archive, permanently corrupting the binary.
- **Correction**: Detect the downloaded asset extension (`.tar.gz`, `.zip`, raw binary). Extract the target executable into a temporary file and verify its execution header before performing atomic replacement.

---

### SEC-04: Misleading Confidence Levels in Pattern Intelligence
- **File**: `internal/tools/gf/engine.go:145-147`
- **Severity**: **Medium**
- **Impact**: The GF engine reports HTTP 200 responses matching sensitive file patterns as `"Sensitive file exposure confirmed live (HTTP 200)"`. A standard single-page app (SPA) returning a 200 OK index page for all routes (`/config.json`, `/.env`) causes false positives to be labelled as "confirmed".
- **Correction**: Differentiate finding states into `candidate`, `corroborated`, `confirmed`, `rejected`, and `unverified`. Label heuristic pattern matches strictly as `candidate` or `corroborated`, reserving `confirmed` exclusively for findings with content-level corroboration.

---

### REL-02: Unchecked File Writes in `executor.RunToFile`
- **File**: `internal/executor/executor.go:158-162`
- **Severity**: **Medium**
- **Impact**: `RunToFile` checks `if res.ExitCode == 0 || workspace.Exists(tmpName)`. Because `tmpName` is created before process launch, `workspace.Exists(tmpName)` is always true, causing failed process outputs to overwrite previous valid outputs.
- **Correction**: Only write to destination when `res.ExitCode == 0` and `res.Error == nil`.

---

### ARCH-03: Premature "Removed Asset" Classification in Delta Comparison
- **File**: `internal/comparison/comparison.go:81-95`
- **Severity**: **Medium**
- **Impact**: If a scan is executed in `passive` or `fast` mode, or is interrupted, any assets discovered in a previous `full` scan are listed as `RemovedSubdomains` or `RemovedHosts`.
- **Correction**: Inspect the previous and current scan metadata (`Mode`, `Status`, `Profile`). If current scan status is not `completed` or modes differ, flag comparisons with appropriate caveats rather than reporting definitive removals.

---

### REL-03: Non-Portable GF Placeholder
- **File**: `internal/dependencies/manager.go:91-94`
- **Severity**: **Low**
- **Impact**: If `go install` fails, `manager.go` creates `#!/bin/sh` on all platforms including Windows (`gf.exe`), which cannot be executed natively.
- **Correction**: On Windows, create a compatible placeholder (`.cmd` / `.bat`) or manage built-in GF pure-Go engine execution without relying on shell scripts.

---

## 4. Implementation Plan

1. **Phase 2**: Centralize Scope Policy in `internal/scope/` (IP/CIDR boundary check, out-of-scope regex/host exclusion, port filter, Katana `-cs` integration).
2. **Phase 3**: Refactor URL model in `internal/intelligence/urlengine/` to preserve `OriginalURL`, query order, and trailing slashes while computing canonical comparison keys.
3. **Phase 4 & 5**: Update Smart URL Engine with explicit provenance, deterministic clustering, and explainable priority signals.
4. **Phase 6**: Revise GF and Takeover confidence states (`candidate`, `corroborated`, `confirmed`, `unverified`).
5. **Phase 7**: Connect stage caching in `internal/pipeline/` and harden resume integrity checking and delta comparison.
6. **Phase 8 & 9**: Harden `executor.go`, `updater.go` (archive extraction), and `dependencies/manager.go`.
7. **Phase 10**: Remediate HTML escaping in `internal/reporting/html.go` and add hostile XSS unit tests.
8. **Phase 11-14**: Full test validation (`go test ./...`, `go vet ./...`), documentation update (`docs/ARCHITECTURE.md`, `README.md`).
