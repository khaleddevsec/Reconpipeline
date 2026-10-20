# ReconPipeline — Architecture and Engineering Specification

## 1. System Overview

ReconPipeline is a high-performance, modular reconnaissance orchestration framework designed for bug bounty hunters, application security engineers, and red teams. It coordinates passive and active asset discovery, DNS intelligence, content crawling, URL normalization, endpoint prioritization, HTTP verification, pattern analysis, and reporting under a strict, centralized authorization boundary.

```
                              ┌────────────────────────┐
                              │  CLI & Scope Policy    │
                              │ (internal/scope, cli)  │
                              └──────────┬─────────────┘
                                         │
                    ┌────────────────────┴────────────────────┐
                    ▼                                         ▼
         [01] Subdomain Discovery                  [02] Live Host Detection
              (Subfinder + DNS)                         (HTTPX #1 + Tech)
                    │                                         │
                    └────────────────────┬────────────────────┘
                                         │
                    ┌────────────────────┴────────────────────┐
                    ▼                                         ▼
         [03] Active Crawling                     [04] Historical Archive
              (Katana - In-Scope)                      (GAU - Archive)
                    │                                         │
                    └────────────────────┬────────────────────┘
                                         │
                                         ▼
                              [05] URL Processing
                           (Smart URL Engine & Model)
                                         │
                                         ▼
                              [06] URL Verification
                                (HTTPX #2 - Smart)
                                         │
                                         ▼
                              [07] Pattern Analysis
                          (GF & Takeover Intelligence)
                                         │
                    ┌────────────────────┴────────────────────┐
                    ▼                                         ▼
              JSON Reports                              HTML Dashboard
        (run-state, deltas, diffs)                 (Context-Escaped, Clean)
```

---

## 2. Pipeline Stages & Execution Flow

The pipeline executes 7 discrete stages, with Stages 03 and 04 executing concurrently:

| Stage | Name | Tool / Module | Execution | Purpose |
|---|---|---|---|---|
| **01** | Subdomain Discovery | `subfinder`, `dns`, `asset` | Active/Passive | Discovers subdomains, maps DNS records (A, AAAA, CNAME), detects wildcards, classifies assets. Discovered hosts are immediately filtered against the centralized scope policy. |
| **02** | Live Host Detection | `httpx` (Pass 1), `tech`, `status` | Active | Identifies responding HTTP/HTTPS endpoints on ports 80/443, extracts server headers, technologies, titles, and response status codes. |
| **03** | Active Crawling | `katana` | Active (Concurrent with 04) | Explores live hosts with scope regex (`-cs`) and post-crawl filtering to discover reachable links, endpoints, forms, and JavaScript files without drifting off-target. |
| **04** | Historical URL Discovery | `gau` | Passive (Concurrent with 03) | Queries Wayback Machine, Common Crawl, and AlienVault for historical URLs and parameters without sending direct traffic to the target. |
| **05** | URL Processing | `urlengine` (Smart Engine) | Local Go Computation | Normalizes URLs conservatively (preserving trailing slashes, parameter order, and repeated keys), generates canonical deduplication keys, clusters endpoints, identifies API/JS/param traits, and exports structured `URLRecord` JSON. |
| **06** | URL Verification | `httpx` (Pass 2) | Active | Selects high- and medium-interest URLs (bounded by profile `MaxVerifyURLs`) under strict scope policy and actively verifies live reachability, capturing final status codes and redirects. |
| **07** | Pattern Analysis | `gf`, `takeover` | Security Intelligence | Scans verified URLs against security patterns (XSS, SQLi, SSRF, LFI, Redirect, API, Auth, Admin, Sensitive Files). Performs subdomain takeover candidate analysis with confidence categorization. |

---

## 3. Centralized Scope Boundary (`internal/scope`)

Authorization scope is a non-negotiable security boundary:

1. **Host Verification (`Policy.IsHostInScope`)**:
   - Matches target domain and exact subdomains (`*.example.com`).
   - Prevents lookalike suffix attacks (e.g. `example.com.attacker.test` or `attackerexample.com` are strictly rejected).
   - Rejects bare IP targets and restricted IP ranges (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, loopback `127.0.0.0/8`, cloud metadata `169.254.169.254`).
   - Enforces user-configured domain and CIDR exclusions (`--exclude` / `-e`).
2. **URL Verification (`Policy.IsURLInScope`)**:
   - Validates that scheme is strictly `http` or `https`.
   - Validates hostname and configured port restrictions.
3. **DNS SSRF / Rebinding Guard (`Policy.ValidateHostResolution`)**:
   - Resolves target hostnames before active network interaction and verifies resolved IP addresses are public and authorized.
4. **Multi-Stage Enforcement**:
   - **Stage 01**: Subdomains discovered by Subfinder are filtered before being stored or resolved.
   - **Stage 02**: HTTPX only receives in-scope, non-excluded subdomains.
   - **Stage 03**: Katana executes with `-cs` (crawl scope regex) and post-crawl URL filtering.
   - **Stage 06**: HTTPX #2 only receives URLs validated by `SelectForVerificationWithPolicy`.

---

## 4. URL Model and Normalization (`internal/intelligence/urlengine`)

### Structured URL Identity (`URLRecord`)
Every URL processed through the pipeline is represented as a structured `URLRecord` preserving complete provenance:
- `OriginalURL`: The exact raw URL as discovered.
- `NormalizedURL`: Conservative normalization (scheme lowercase, host lowercase, default port stripped, dot segments resolved).
- `CanonicalKey`: Deterministic comparison key with sorted query parameters, used exclusively for semantic deduplication.
- `Sources`: List of discovery sources (`katana` / `crawl`, `gau` / `archive`).
- `Parameters`: Query parameter names and repeated values.
- `ClusterPattern`: Normalized path skeleton used for parameter family clustering.
- `PriorityScore` & `Reasons`: Explainable ranking score and textual reason strings.
- `VerificationState`: Explicit state (`candidate`, `corroborated`, `confirmed`, `unverified`).

### Conservative Normalization Rules
1. **Trailing Slashes Preserved**: `/api/v1/users` and `/api/v1/users/` are treated as distinct paths because server routing frameworks frequently handle them differently.
2. **Parameter Order Preserved**: Query parameter sequence in `NormalizedURL` matches the original URL.
3. **Repeated Parameters Preserved**: Repeated keys (e.g. `?id=1&id=2`) are kept intact.
4. **Percent Encoding Maintained**: Valid percent-encoded octets are preserved without destructive decoding.
5. **Path Traversal Resolved**: Normalized dot segments (`/a/b/../c` -> `/a/c`) to prevent duplicate path representations.

---

## 5. Finding Confidence and Evidence Model (`internal/tools/gf`)

Reconnaissance findings must never conflate heuristic matches with confirmed vulnerabilities:

| State | Definition | Example in ReconPipeline |
|---|---|---|
| `candidate` | Syntactic or regex pattern match on parameter or path name. | GF pattern match for `redirect=` or `id=`. Requires active verification and payload testing. |
| `corroborated` | Pattern match backed by observed HTTP or DNS behavior. | HTTP 200 response on sensitive backup file path, or CNAME pointing to an unclaimed third-party service provider. Requires out-of-band validation. |
| `confirmed` | Definitive proof of exploitability or vulnerability. | *ReconPipeline never marks findings as confirmed without explicit active validation.* |
| `rejected` | False positive or out-of-scope asset. | Excluded domain or known static placeholder. |
| `unverified` | Extracted endpoint that has not yet been probed. | Passive URL from GAU before HTTPX #2 verification. |

### Takeover Candidate Analysis
- Fingerprints CNAME records against known vulnerable cloud and SaaS providers.
- Marks potential dangling records as `corroborated` candidates.
- **Strict Rule**: ReconPipeline **never** attempts to claim or hijack third-party resources.

---

## 6. Stage Caching and Resume

### Stage Caching (`internal/cache`)
- Computes SHA-256 cache keys derived from target domain, tool versions, scan profile/mode, concurrency, and upstream stage artifacts.
- Automatically caches stage output directories (up to 15MB total).
- Cache hits restore stage outputs without invoking external subprocesses.
- Bypassed cleanly when `--no-cache` or `--resume` is specified.

### Scan Resumption (`internal/pipeline/run.go`)
- Checkpoints stage execution state in atomic `run-state.json`.
- When `--resume` is supplied, checks for stage status `completed` and verifies that required stage output files exist and are non-empty (`fi.Size() > 0`).
- Prevents resumed scans from repeating finished stages.

### Historical Comparisons (`internal/comparison`)
- Preserves timestamped scan snapshots under `~/.reconpipeline/history/<target>/`.
- Distinguishes new assets, persistent assets, and removed assets.
- If a scan is interrupted or incomplete, flags `IsIncompleteScan: true` and issues a warning rather than misreporting missing endpoints as permanently decommissioned.

---

## 7. Process Management and External Tools

- **Subprocess Execution (`internal/executor`)**:
  - Context-bound process management with graceful cancellation propagation (`SIGINT` / `SIGTERM`).
  - Strict atomic file writes (`RunToFile`): temporary files are created with mode `0600` and renamed only on exit code 0. Partial/failed executions never corrupt existing output files.
- **Secure Self-Update (`internal/updater`)**:
  - Automatically identifies `.tar.gz` and `.zip` release archives using magic bytes.
  - Extracts the binary into a temporary file, sets executable permissions `0755`, and atomically swaps it over the running binary.
  - Maintains automatic `.bak` fallback rollback if the updated executable fails health validation.

---

## 8. Reporting and Security (`internal/reporting`)

- **HTML Dashboard**:
  - Generates a single-file, self-contained interactive HTML dashboard (`report.html`).
  - Context-aware HTML escaping (`html.EscapeString`) applied across all dynamic asset titles, server headers, URL values, and stage outputs to completely eliminate Stored XSS.
  - Secure styling with no external script dependencies or unsafe inline event handlers.
- **JSON Structured Data**:
  - `run-state.json`: Complete execution record with per-stage timing, durations, counters, and warnings.
  - `url-records.json`: Structured URL dataset with provenance, clustering, and priority assessments.
  - `statistics.json`: Machine-readable summary for automation and CI/CD pipelines.
