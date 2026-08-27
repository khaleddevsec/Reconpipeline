# Reconpipeline

```
  ____                       ____  _             __
 |  _ \ ___  ___ ___  _ __  |  _ \(_)_ __   ___
 | |_) / _ \/ __/ _ \| '_ \ | |_) | | '_ \ / _ \
 |  _ <  __/ (_| (_) | | | ||  __/| | |_) |  __/
 |_| \_\___|\___\___/|_| |_||_|   |_| .__/ \___|
                                    |_|
```

Reconpipeline  
Made by frozeniceee  
Version: v2.5.3  
Release: V2.2 — Optimization, Reliability & Extensibility

---

## Overview

Reconpipeline is a single-command automated reconnaissance orchestration pipeline
built for Linux. It coordinates Subfinder, HTTPX, Katana, GAU, and GF to perform
subdomain discovery, DNS intelligence gathering, live host detection, technology
fingerprinting, HTTP status categorization, active crawling, historical URL discovery,
smart URL normalization, deduplication, URL clustering, parameter intelligence,
endpoint prioritization, pattern analysis, scan history persistence, delta change
detection, and standalone HTML/JSON reporting.

The user interacts with one command:

```
reconpipeline example.com
```

All internal tools are managed automatically in `~/.reconpipeline/`. No manual tool
installation, PATH configuration, or per-tool knowledge is required.

---

## Features

- Single command execution: `reconpipeline <target>`
- Automatic internal tool management (Subfinder, HTTPX, Katana, GAU, GF)
- Six-stage reconnaissance pipeline with modular lifecycle states
- Profiles: `full` (default), `fast` (reduced crawl depth/timeout), `passive` (passive-only)
- Smart Stage Caching & Invalidation (separate from history)
- Atomic File Operations (`.tmp` write + sync + rename) to protect data integrity
- Controlled Parallelism (bounded concurrent execution of active crawling and historical discovery)
- Resource and process timeout handling with retry backoff
- Graceful Signal Handling (`Ctrl+C` / SIGINT / SIGTERM) with partial state preservation
- Asset Classification (production, development, staging, api, admin, auth, cdn, mail, static, unknown)
- DNS Intelligence (A records, AAAA records, CNAME resolution, IP aggregation)
- Technology Intelligence (Nginx, Apache, WordPress, Node.js, PHP, CDN, Cloud)
- HTTP Status Intelligence (2xx, 3xx, 4xx, 5xx, interesting status codes)
- Smart URL Normalization (fragment stripping, query sorting, trailing slash handling)
- URL Clustering (endpoint family grouping: `/api/user/{id}`, `/item/{uuid}`, `/download/{hash}`)
- API Endpoint Detection (`/api/`, `/v1/`, `/graphql`, `/rest/`, `/swagger`, `/openapi`)
- JavaScript Intelligence (JS file isolation and route/endpoint extraction)
- Parameter Intelligence (categorization: identifier, url, file_path, redirect, search, pagination, auth_token)
- Interesting Endpoint Detection (high, medium, low interest heuristics)
- Smart Prioritization (deterministic, explainable priority scoring)
- GF Pattern Analysis (XSS, SQLi, LFI, SSRF, Open Redirect)
- Scan History Persistence (`results/<target>/history/<scan_id>/`)
- Delta Change Detection (comparing current scan against previous scans)
- Standalone, responsive HTML Dashboard (`report.html`) with zero external dependencies
- Machine-readable structured JSON reports (`report.json`)
- Comprehensive CLI commands (`history`, `compare`, `report`, `doctor`, `update`, `version`)
- Per-scan logging (`logs/scan-<id>.log`) and `--no-color` mode
- Linux amd64 and arm64 support

---

## Architecture

```
                         TARGET
                            |
                            v
                  SUBDOMAIN DISCOVERY
                            |
                            v
                     DNS INTELLIGENCE
                            |
                            v
                   ASSET CLASSIFICATION
                            |
                            v
                   LIVE HOST DETECTION (HTTPX)
                            |
                 +----------+----------+
                 |                     |
                 v                     v
          TECHNOLOGIES              STATUS
                 |                     |
                 +----------+----------+
                            |
                 +----------+----------+
                 |                     |
                 v                     v
              KATANA                  GAU
         (active crawl)         (historical URLs)
                 |                     |
                 +----------+----------+
                            |
                            v
                    SMART URL ENGINE
                            |
             +--------------+--------------+
             |              |              |
             v              v              v
            API             JS        PARAMETERS
             |              |              |
             +--------------+--------------+
                            |
                            v
                      NORMALIZATION
                            |
                            v
                      DEDUPLICATION
                            |
                            v
                     URL CLUSTERING
                            |
                            v
                   INTEREST DETECTION
                            |
                            v
                     PRIORITIZATION
                            |
                            v
                     PATTERN ANALYSIS (GF)
                            |
                            v
                     HISTORY & DELTAS
                            |
             +--------------+--------------+
             |              |              |
             v              v              v
         HTML DASHBOARD  JSON REPORT   TEXT REPORT
```

---

## Pipeline Stages

| Stage | Name                       | Engine / Tool  | Primary Outputs |
|-------|----------------------------|----------------|-----------------|
| 01    | Subdomain Discovery        | Subfinder, DNS | `subdomains.txt`, `dns/`, `classified/`, `metadata.json` |
| 02    | Live Host Detection        | HTTPX, Tech    | `live-hosts.txt`, `status/`, `technologies/`, `metadata.json` |
| 03    | Active Crawling            | Katana         | `katana-urls.txt`, `katana/urls.txt` |
| 04    | Historical URL Discovery   | GAU            | `gau-urls.txt`, `gau/urls.txt` |
| 05    | URL Processing             | Smart URL Core | `raw/`, `normalized/`, `deduplicated/`, `api/`, `javascript/`, `parameters/`, `clusters/`, `interesting/`, `priority/` |
| 06    | Pattern Analysis           | GF             | `xss.txt`, `sqli.txt`, `lfi.txt`, `ssrf.txt`, `redirect.txt`, `patterns/` |

---

## Installation

### Standard Installation

```bash
cd /root
mkdir Reconpipeline
cd Reconpipeline
git clone https://github.com/frozeniceee/Reconpipeline.git .
chmod +x install.sh
./install.sh
```

### One-Line Command

```bash
cd /root && mkdir -p Reconpipeline && cd Reconpipeline && git clone https://github.com/frozeniceee/Reconpipeline.git . && chmod +x install.sh && ./install.sh
```

---

## Usage

```bash
# Basic scan
reconpipeline example.com

# Target with protocol
reconpipeline https://example.com/

# Execution profiles
reconpipeline example.com --profile full
reconpipeline example.com --profile fast
reconpipeline example.com --profile passive

# Resume interrupted scan
reconpipeline example.com --resume

# Bypass stage caching
reconpipeline example.com --no-cache

# Custom output directory
reconpipeline example.com --output ./my-results

# Concurrency and timeout
reconpipeline example.com --threads 20 --timeout 1h

# View scan history
reconpipeline history example.com
reconpipeline history example.com --details

# Compare scans for change detection
reconpipeline compare example.com
reconpipeline compare example.com --from scan-20260827-100000 --to scan-20260828-110000

# View latest scan reports
reconpipeline report example.com

# Diagnostic commands
reconpipeline doctor
reconpipeline version
reconpipeline update
```

---

## CLI Options & Commands

```
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

    -h, --help              Show help information
    -v, --version           Show current version and update status
        --update            Update Reconpipeline to the latest release
        --doctor            Inspect system and dependency health

Profiles & Modes:
        --profile <name>    Profile: full, fast, passive (default: full)
        --mode <mode>       Scan mode: full, active, passive (default: full)
        --no-cache          Bypass stage caching

Scan:
        --resume            Resume an interrupted scan from saved state
    -o, --output <dir>      Custom output directory for results
        --dry-run           Display execution plan without running tools

Runtime:
        --timeout <dur>     Scan timeout duration (e.g. 30m, 1h) (default: 30m)
        --threads <num>     Concurrency level (default: 10)
        --workers <num>     Worker concurrency alias

Display:
        --no-color          Disable coloured terminal output
    -q, --quiet             Minimal output
        --verbose           Detailed execution logs
```

---

## Configuration & Profiles

Reconpipeline works out of the box with zero configuration. Optional user configuration
can be defined in `~/.config/reconpipeline/config.yaml` or `~/.reconpipeline/config/config.yaml`:

```yaml
default_profile: full
default_threads: 10
default_timeout: 30m
default_output: results
cache_enabled: true
log_level: info
```

### Profiles Overview

- **full**: Comprehensive reconnaissance with maximum discovery depth (default).
- **fast**: Streamlined reconnaissance with reduced crawl depth and shorter timeouts.
- **passive**: Non-intrusive reconnaissance skipping active crawling (Katana).

---

## Output Structure

```
results/
└── example.com/
    ├── 01-subdomain-discovery/
    │   ├── subdomains.txt
    │   ├── metadata.json
    │   ├── classified/
    │   └── dns/
    │
    ├── 02-live-host-detection/
    │   ├── live-hosts.txt
    │   ├── metadata.json
    │   ├── status/
    │   └── technologies/
    │
    ├── 03-active-crawling/
    │   ├── katana-urls.txt
    │   └── katana/urls.txt
    │
    ├── 04-historical-url-discovery/
    │   ├── gau-urls.txt
    │   └── gau/urls.txt
    │
    ├── 05-url-processing/
    │   ├── all-urls.txt
    │   ├── normalized-urls.txt
    │   ├── unique-urls.txt
    │   ├── api-urls.txt
    │   ├── javascript-urls.txt
    │   ├── parameterized-urls.txt
    │   ├── interesting-urls.txt
    │   ├── raw/
    │   ├── normalized/
    │   ├── deduplicated/
    │   ├── clusters/
    │   ├── api/
    │   ├── javascript/
    │   ├── parameters/
    │   ├── interesting/
    │   └── priority/
    │
    ├── 06-pattern-analysis/
    │   ├── xss.txt
    │   ├── sqli.txt
    │   ├── lfi.txt
    │   ├── ssrf.txt
    │   ├── redirect.txt
    │   ├── gf/
    │   └── patterns/
    │
    ├── history/
    │   └── scan-20260827-183042/
    │       ├── scan.json
    │       ├── summary.json
    │       ├── summary.txt
    │       ├── report.json
    │       ├── report.html
    │       ├── subdomains.txt
    │       ├── live-hosts.txt
    │       ├── unique-urls.txt
    │       └── statistics.json
    │
    ├── comparison/
    │   ├── new-subdomains.txt
    │   ├── removed-subdomains.txt
    │   ├── new-hosts.txt
    │   ├── removed-hosts.txt
    │   ├── new-urls.txt
    │   ├── removed-urls.txt
    │   ├── changed-assets.json
    │   ├── comparison.json
    │   └── comparison.txt
    │
    ├── summary/
    │   ├── statistics.json
    │   └── summary.txt
    │
    ├── report.html
    ├── report.txt
    ├── report.json
    └── run.json
```

---

## Testing

Run the full unit and integration test suite:

```bash
go test -v ./...
```

---

## Branching Model

- `main`: Stable production branch. Tagged releases (e.g. `v2.5.0`, `v2.5.1`, `v2.5.2`, `v2.5.3`).
- `develop`: Active development branch for new capabilities and optimizations.

---

## Legal & Authorized Use Notice

Reconpipeline is designed exclusively for authorized security assessments, bug bounty
reconnaissance, defensive security testing, and asset discovery.

Users are strictly responsible for obtaining proper authorization prior to testing targets.
Unauthorized scanning or testing of target systems is prohibited.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
