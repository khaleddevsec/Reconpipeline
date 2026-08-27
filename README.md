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
Version: v2.5.0

---

## Overview

Reconpipeline is a single-command automated reconnaissance pipeline for Linux.

It internally orchestrates Subfinder, HTTPX, Katana, GAU, and GF to perform
subdomain discovery, live host detection, active crawling, historical URL
discovery, URL classification, and pattern analysis.

The user interacts with one tool:

```
reconpipeline example.com
```

No manual installation of internal tools is required. No PATH configuration.
No per-tool knowledge needed.

---

## Features

- Single command: `reconpipeline example.com`
- Automatic management of all internal tools
- Six-stage reconnaissance pipeline
- Concurrent active crawling and historical URL discovery
- Pure Go URL processing: merge, normalise, deduplicate, classify
- Pattern analysis for XSS, SQLi, LFI, SSRF, open redirect
- Scan modes: full, active, passive
- Resume support
- Graceful interruption handling
- Self-update system
- Doctor command for environment inspection
- Dry-run mode
- TXT and JSON reports
- Strict target scope enforcement
- Linux amd64 and arm64 support

---

## Architecture

```
Target
  |
  v
Subfinder (subdomain discovery)
  |
  v
HTTPX (live host detection)
  |
  +-------------------+
  |                   |
  v                   v
Katana              GAU
(active crawling)   (historical URLs)
  |                   |
  +---------+---------+
            |
            v
    URL Processing (Go)
    - merge
    - normalise
    - deduplicate
    - classify
            |
            v
    Pattern Analysis (GF)
    - XSS
    - SQLi
    - LFI
    - SSRF
    - Open Redirect
            |
            v
        Report
```

Katana and GAU run concurrently after HTTPX completes.

---

## Pipeline

| Stage | Tool     | Output                              |
|-------|----------|-------------------------------------|
| 01    | Subfinder | subdomains.txt                     |
| 02    | HTTPX     | live-hosts.txt, metadata.json      |
| 03    | Katana    | katana-urls.txt                    |
| 04    | GAU       | gau-urls.txt                       |
| 05    | Go        | all-urls.txt, unique-urls.txt, ... |
| 06    | GF        | xss.txt, sqli.txt, lfi.txt, ...    |

---

## Requirements

- Linux (amd64 or arm64)
- Go 1.21 or later (for building only)
- Internet connection (for tool downloads on first run)

The compiled Reconpipeline binary does not require Go at runtime.

---

## Installation

### Step-by-step

```bash
cd /root
mkdir Reconpipeline
cd Reconpipeline
git clone https://github.com/frozeniceee/Reconpipeline.git .
chmod +x install.sh
./install.sh
```

### One-line

```bash
cd /root && mkdir -p Reconpipeline && cd Reconpipeline && git clone https://github.com/frozeniceee/Reconpipeline.git . && chmod +x install.sh && ./install.sh
```

The installer:

1. Detects Linux
2. Detects CPU architecture
3. Detects Go (prefers `/usr/local/go/bin/go`, falls back to PATH)
4. Builds Reconpipeline with version v2.5.0 injected at build time
5. Installs the binary to `/usr/local/bin/reconpipeline`
6. Creates the `~/.reconpipeline/` workspace
7. Verifies the installation

---

## Quick Start

```bash
reconpipeline example.com
```

On first run, Reconpipeline automatically downloads and installs all required
internal tools before beginning the scan.

---

## Usage

```bash
reconpipeline example.com

reconpipeline example.com --mode full

reconpipeline example.com --mode active

reconpipeline example.com --mode passive

reconpipeline example.com --resume

reconpipeline example.com --dry-run

reconpipeline example.com --output ./results

reconpipeline example.com --timeout 30m

reconpipeline example.com --threads 10

reconpipeline --doctor

reconpipeline doctor

reconpipeline --update

reconpipeline update

reconpipeline --version

reconpipeline version
```

---

## CLI Options

```
Global:

    -h, --help              Show help
    -v, --version           Show version
        --update            Update Reconpipeline
        --doctor            Check system and dependencies

Scan:

        --resume            Resume a previous scan
    -o, --output <dir>      Output directory for results
        --mode <mode>       Scan mode: full, active, passive
        --dry-run           Show pipeline plan without executing

Runtime:

        --timeout <d>       Scan timeout (e.g. 30m, 1h)
        --threads <n>       Concurrency level (default: 10)

Display:

    -q, --quiet             Minimal output
        --verbose           Detailed output
```

---

## Modes

| Mode    | Description                                      |
|---------|--------------------------------------------------|
| full    | All stages: subdomain, live, crawl, historical   |
| active  | Subfinder, HTTPX, Katana. No historical (GAU).   |
| passive | Subfinder, HTTPX, GAU. No active crawl (Katana). |

---

## Dependency Management

Reconpipeline automatically manages all internal tools in:

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

Before each scan, Reconpipeline verifies that all tools are present and
functional. Missing or broken tools are installed or repaired automatically.

The user does not need to install, configure, or update these tools manually.

---

## Output Structure

```
results/
└── example.com/
    ├── 01-subdomain-discovery/
    │   └── subdomains.txt
    ├── 02-live-host-detection/
    │   ├── live-hosts.txt
    │   └── metadata.json
    ├── 03-active-crawling/
    │   └── katana-urls.txt
    ├── 04-historical-url-discovery/
    │   └── gau-urls.txt
    ├── 05-url-processing/
    │   ├── all-urls.txt
    │   ├── normalized-urls.txt
    │   ├── unique-urls.txt
    │   ├── api-urls.txt
    │   ├── javascript-urls.txt
    │   ├── parameterized-urls.txt
    │   └── interesting-urls.txt
    ├── 06-pattern-analysis/
    │   ├── xss.txt
    │   ├── sqli.txt
    │   ├── lfi.txt
    │   ├── ssrf.txt
    │   ├── redirect.txt
    │   └── other-patterns.txt
    ├── report.txt
    ├── report.json
    └── run.json
```

Custom output directory:

```bash
reconpipeline example.com --output ./my-results
```

Results are written to `./my-results/example.com/`.

---

## Resume

Start a scan and interrupt it:

```
Ctrl+C
```

Reconpipeline saves scan progress to `run.json`. Resume from where it stopped:

```bash
reconpipeline example.com --resume
```

Completed stages are skipped. The scan continues from the first incomplete stage.

---

## Reports

Two report files are generated after each scan:

`report.txt` — human-readable summary  
`report.json` — machine-readable structured data

Pattern matches are labelled as "Potential Pattern Matches" and are not
confirmed vulnerabilities.

---

## Doctor

```bash
reconpipeline doctor
```

Displays:

- Application version and installation status
- Operating system and architecture
- Workspace directory status
- Status of all managed tools

---

## Update

```bash
reconpipeline update
```

Reconpipeline checks for the latest release on GitHub, downloads the correct
binary for your platform, and replaces itself atomically.

Scan results, configuration, cache, and managed dependencies are preserved.

---

## Development

Requirements:

- Go 1.21+
- Linux (for building release binaries)

```bash
# Clone
git clone https://github.com/frozeniceee/Reconpipeline.git
cd Reconpipeline

# Build
make build

# Test
make test

# Vet
make vet

# Format
make fmt

# Build release binaries
make release
```

---

## Testing

```bash
go test ./...
```

Test coverage:

- Target normalisation
- Scope validation
- URL processing (merge, normalise, deduplicate, classify)
- Version comparison
- Workspace creation
- Report generation
- Run state save and load

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Responsible Use

Reconpipeline is intended for authorised security testing, security research,
asset discovery, and reconnaissance.

Users are responsible for ensuring they have permission to test their targets.

Do not use Reconpipeline against systems you do not have authorisation to test.

---

## License

MIT License. See [LICENSE](LICENSE).

Third-party tools (Subfinder, HTTPX, Katana, GAU, GF) are subject to their
own licenses. See [LICENSE](LICENSE) for details.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md).
