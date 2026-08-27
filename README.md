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
Version: v2.5.2  
Release: V2.1 — History & Smart Reporting

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
- Six-stage reconnaissance pipeline
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
- Observation of new, removed, and changed assets (status codes, titles, servers)
- Standalone, responsive HTML Dashboard (`report.html`) with zero external dependencies
- Machine-readable structured JSON reports (`report.json`)
- Comprehensive CLI commands (`history`, `compare`, `report`, `doctor`, `update`, `version`)
- Scan modes: full, active, passive
- Resume support via `run.json`
- Graceful SIGINT handling (results preserved on interrupt)
- Raw data preservation across all stages
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

## Requirements

- Linux (amd64 or arm64)
- Go 1.21 or later (required for building the binary from source)
- Internet connection (for first-run tool downloads)

The compiled Reconpipeline binary runs as a standalone tool and does not require Go
at runtime once dependencies are initialized.

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

The installer verifies the Linux environment, architecture, Go compiler (preferring
`/usr/local/go/bin/go`, falling back to PATH), builds the binary with version injection,
installs to `/usr/local/bin/reconpipeline`, and sets up the workspace at `~/.reconpipeline/`.

---

## Usage

```bash
# Basic scan
reconpipeline example.com

# Target with protocol
reconpipeline https://example.com/

# Scan modes
reconpipeline example.com --mode full
reconpipeline example.com --mode active
reconpipeline example.com --mode passive

# Resume interrupted scan
reconpipeline example.com --resume

# Dry-run execution plan
reconpipeline example.com --dry-run

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

Scan:
        --resume            Resume an interrupted scan from saved state
    -o, --output <dir>      Custom output directory for results
        --mode <mode>       Scan mode: full, active, passive (default: full)
        --dry-run           Display execution plan without running tools

Runtime:
        --timeout <dur>     Scan timeout duration (e.g. 30m, 1h) (default: 30m)
        --threads <num>     Concurrency level (default: 10)

Display:
    -q, --quiet             Minimal output
        --verbose           Detailed execution logs
```

---

## Output Structure

Results are organized deterministically per target domain:

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

Raw data is preserved across every stage. Processed datasets and historical records
exist alongside raw files to prevent data loss.

---

## History & Comparison Workflow

When scanning a target, Reconpipeline automatically:

1. Loads the latest prior scan for the specific target.
2. Executes the reconnaissance pipeline.
3. Computes the delta differences across subdomains, live hosts, URLs, and asset metadata.
4. Generates a standalone `report.html` dashboard, `report.json`, and `report.txt`.
5. Persists the current scan snapshots into `history/<scan_id>/`.
6. Saves detailed comparison records into `comparison/`.

---

## Dependency Management

Internal tools are managed inside `~/.reconpipeline/`:

```
~/.reconpipeline/
├── tools/
│   ├── subfinder/
│   ├── httpx/
│   ├── katana/
│   ├── gau/
│   └── gf/
├── versions/
│   └── manifest.json
├── cache/
├── config/
└── logs/
```

Before each execution, Reconpipeline validates managed binaries. Missing tools are
downloaded and installed automatically.

---

## Testing

Run the full unit and integration test suite:

```bash
go test -v ./...
```

Test coverage includes:
- Scan ID generation and scan metadata serialization
- Scan history persistence, listing, and target isolation
- Delta comparison engine (new, removed, and changed assets)
- Standalone HTML report dashboard generation
- Target normalisation and ccTLD root domain parsing
- Asset classification rules and confidence scoring
- DNS record resolution and IP gathering
- Technology and HTTP status categorization
- Smart URL normalization and deterministic deduplication
- URL clustering and endpoint pattern extraction
- API endpoint detection and JavaScript endpoint analysis
- Parameter intelligence classification
- URL priority scoring and interest level segregation
- Run state persistence, stage skipping, and resume

---

## Versioning

Reconpipeline follows Semantic Versioning:

- `MAJOR.MINOR.PATCH`
- PATCH releases: bug fixes, heuristic improvements, compatibility updates.
- MINOR releases: new pipeline intelligence and reporting stages, backwards compatible.
- MAJOR releases: architectural overhauls, breaking changes.

---

## Branching Model

- `main`: Stable production branch. Tagged releases (e.g. `v2.5.0`, `v2.5.1`, `v2.5.2`).
- `develop`: Active development branch for new capabilities and features.

---

## Troubleshooting

1. **Permission Denied on install.sh**:
   Run `chmod +x install.sh` before running `./install.sh`.
2. **Missing Dependencies**:
   Run `reconpipeline doctor` to inspect the status of managed dependencies.
3. **Interrupted Scans**:
   Resume an interrupted scan by appending `--resume` to the original command:
   `reconpipeline example.com --resume`.

---

## Legal & Authorized Use Notice

Reconpipeline is designed exclusively for authorized security assessments, bug bounty
reconnaissance, defensive security testing, and asset discovery.

Users are strictly responsible for obtaining proper authorization prior to testing targets.
Unauthorized scanning or testing of target systems is prohibited.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
