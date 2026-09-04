# Changelog

All notable changes to this project are documented in this file.

This project follows [Semantic Versioning](https://semver.org/).

## v2.6.0 — Smart URL Verification

Release Date: 2026-09-05  
Branch: develop

### Features & URL Verification Enhancements

- **Second HTTPX Stage (`06-url-verification`)**: Integrated an intelligent endpoint verification and enrichment stage between Go URL Processing and GF Pattern Analysis.
- **Smart URL Selection & Prioritization**: Conservative, deterministic candidate selection prioritizing high-security endpoints (APIs, parameterized routes, GraphQL, Swagger/OpenAPI, JSON, auth/admin) and medium-priority application endpoints while filtering out static resource noise (images, fonts, CSS, media).
- **Scope-Constrained Endpoint Probing**: Strict target domain scope validation preventing out-of-scope probes.
- **URL Metadata & Response Enrichment**: Captures HTTP status codes, titles, servers, content types, content lengths, locations, and technologies into structured `metadata.json`, `verified-urls.txt`, and `httpx.jsonl`.
- **GF Integration Pipeline Optimization**: GF pattern analysis consumes clean, verified, responsive URLs (`verified-urls.txt`) with automatic graceful fallback to unique URLs if verification is skipped.
- **Configurable Concurrency & Thresholds**: Supports `verify_urls` and `max_verify_urls` configuration in user settings and execution profiles (`full`, `fast`, `passive`).
- **Resumption & Graceful Interruption**: Full state preservation (`run.json`), atomic writing, and interruption safety for Stage 06.
- **Reporting & Dashboard Extensions**: Displays verified URLs in CLI outputs, terminal summary metrics, text reports (`report.txt`), JSON reports (`report.json`), and the standalone HTML dashboard (`report.html`).

---

## v2.5.3 — V2.2 Optimization, Reliability & Extensibility

Release Date: 2026-08-27  
Branch: develop

### Optimizations & Architectural Enhancements

- **Pipeline Lifecycle & Dependency Orchestrator**: Explicit stage lifecycle states (`pending`, `running`, `completed`, `failed`, `skipped`, `interrupted`) with stage input validation and accurate per-stage duration tracking.
- **Smart Stage Caching & Invalidation**: Isolated caching (`internal/cache`) with SHA-256 content hashing, version keying, and `--no-cache` support.
- **Configuration & Execution Profiles**: Optional YAML/JSON user configuration loading with support for execution profiles (`full`, `fast`, `passive`) and validation of all runtime options.
- **Data Integrity & Atomic File Operations**: `workspace.WriteFileAtomic` ensures atomic metadata and result persistence via temporary files, fsync, and atomic rename to prevent corrupted files during interruptions.
- **Controlled Concurrency & Parallel Execution**: Active crawling (Katana) and Historical URL discovery (GAU) execute concurrently under bounded worker pools with clean context cancellation and error propagation.
- **Process Resilience & Exponential Retry**: Subprocess executor wrapped with transient error retries and timeout propagation.
- **Diagnostic Doctor & Health Checks**: Enhanced `reconpipeline doctor` with Go compiler verification (supporting PATH and `/usr/local/go/bin/go`), tool versions, workspace health, and configuration inspection.
- **Enhanced Logging & ANSI Stripping**: Per-scan log files (`logs/scan-<id>.log`), `--no-color` mode, and ANSI escape code sanitization.
- **Extended Test Suite**: 61 automated unit and integration tests passing (`61/61 PASS`).

---

## v2.5.2 — V2.1 History & Smart Reporting

Release Date: 2026-08-27  
Branch: develop

### Features & Reporting Enhancements

- **Scan Identification & Metadata**: Deterministic scan IDs (`scan-YYYYMMDD-HHMMSS`) with structured `scan.json` and `summary.json`.
- **Scan History Engine**: Persistent scan history under `results/<target>/history/<scan_id>/` with target isolation and snapshot preservation.
- **Delta Change Detection & Comparison Engine**: Automated comparison between scans detecting new, removed, and changed subdomains, live hosts, URLs, APIs, JS endpoints, and asset metadata (HTTP status codes, titles, servers).
- **Comparison Output Files**: Output tracking in `results/<target>/comparison/` (`new-subdomains.txt`, `removed-subdomains.txt`, `new-hosts.txt`, `removed-hosts.txt`, `new-urls.txt`, `removed-urls.txt`, `changed-assets.json`, `comparison.json`, `comparison.txt`).
- **Standalone HTML Dashboard (`report.html`)**: Self-contained, responsive, clean HTML reconnaissance dashboard with KPI cards, stage indicators, security pattern tables, and changes since previous scan.
- **Structured JSON & Text Reports**: Enhanced `report.json` and `report.txt` with scan metadata, intelligence counts, and delta comparison summaries.
- **New CLI Commands**:
  - `reconpipeline history <target>` (`--details` / `-d` supported).
  - `reconpipeline compare <target>` (`--from <id> --to <id>` supported).
  - `reconpipeline report <target>` (Locates and displays latest reports).
- **Extended Test Suite**: 53 automated unit and integration tests covering history, delta detection, HTML report generation, and CLI subcommands.

---

## v2.5.1 — V2.0 Intelligent Recon Core

Release Date: 2026-08-27  
Branch: develop

### Features & Intelligence Enhancements

- **Asset Classification**: Automated heuristic classification of hostnames into `production`, `development`, `staging`, `api`, `admin`, `auth`, `cdn`, `mail`, `static`, and `unknown` with confidence scores and reasoning.
- **DNS Intelligence**: Automated gathering of A records, AAAA records, CNAME chains, and resolved IP lists with bounded concurrency.
- **Technology Intelligence**: Live host grouping by technology fingerprints including Nginx, Apache, WordPress, Node.js, PHP, CDN, and Cloud infrastructure.
- **HTTP Status Intelligence**: Response status code organization into `2xx`, `3xx`, `4xx`, `5xx`, and `interesting-status` categories.
- **Smart URL Engine**:
  - Deep semantic-preserving URL normalization (casing, default port removal, fragment stripping, deterministic query parameter sorting).
  - Exact and structural duplicate filtering with raw data preservation.
  - Endpoint family clustering (`/api/user/{id}`, `/item/{uuid}`, `/download/{hash}`).
  - API endpoint detection and pattern indexing (`/api/`, `/graphql`, `/swagger`, `/openapi`).
  - JavaScript intelligence with asset separation and route/endpoint extraction.
  - Parameter intelligence categorizing query keys into identifiers, URLs, file paths, redirects, search terms, pagination, and auth tokens.
  - Interesting endpoint grouping into high, medium, and low interest tiers.
  - Deterministic, explainable priority scoring (`high`, `medium`, `low`) for every unique URL.
- **Enhanced Directory Structure**: Structured subfolders (`dns/`, `classified/`, `status/`, `technologies/`, `raw/`, `normalized/`, `deduplicated/`, `clusters/`, `api/`, `javascript/`, `parameters/`, `interesting/`, `priority/`, `summary/`) while preserving 100% backward compatibility.
- **Extended Test Suite**: 46 automated unit and integration tests covering all intelligence modules.

---

## v2.5.0

Initial production release of Reconpipeline.

### Features

- Single-command automated reconnaissance pipeline: `reconpipeline <target>`
- Automatic management of Subfinder, HTTPX, Katana, GAU, and GF
- Six-stage pipeline: subdomain discovery, live host detection, active crawling,
  historical URL discovery, URL processing, and pattern analysis
- Concurrent Katana and GAU execution
- Pure Go URL processing: merge, normalise, deduplicate, classify
- Pattern analysis: XSS, SQLi, LFI, SSRF, open redirect
- Scan modes: full, active, passive
- Resume support via run.json
- Graceful SIGINT handling
- Self-update system
- Doctor command for dependency and environment inspection
- Dry-run mode
- TXT and JSON report generation
- Strict target scope enforcement
- Safe subprocess execution (no sh -c with user input)
- Linux amd64 and arm64 support
- GitHub Actions CI and release workflows

---

Future releases will follow Semantic Versioning:

- PATCH releases (v2.5.x): bug fixes and minor improvements
- MINOR releases (v2.x.0): new features, backwards compatible
- MAJOR releases (vX.0.0): breaking changes
