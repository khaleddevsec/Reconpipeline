# Reconpipeline (ThreatLens)

[![Go Reference](https://pkg.go.dev/badge/github.com/khaleddevsec/Reconpipeline.svg)](https://pkg.go.dev/github.com/khaleddevsec/Reconpipeline)
[![CI](https://github.com/khaleddevsec/Reconpipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/khaleddevsec/Reconpipeline/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A Go-based cybersecurity **intelligence engine** — not just a scanner.

Reconpipeline (ThreatLens) collects HTTP and TLS metadata from websites and correlates findings with **MITRE ATT&CK**, **CAPEC**, **CWE**, and **OWASP Top 10** to explain *why* each finding matters, how an attacker could abuse it, and what should be done to remediate it.

---

## Features

- Collects HTTP headers, TLS/X.509 certificate details, cookies, redirect chains, and server banners
- Detects server, framework, language, CMS, and CDN via header fingerprinting
- Built-in embedded knowledge database (`go:embed`) — works standalone from any directory with zero internet required
- Correlates missing & misconfigured security headers (HSTS, CSP, CORS, XFO, XCTO, Referrer-Policy, Permissions-Policy), insecure cookies (`Secure`, `HttpOnly`, `SameSite`), and TLS/certificate weaknesses (weak protocol, weak cipher, expired or self-signed certificates)
- Non-diluting risk scoring (`0–10`) anchored to critical severity with incremental risk accumulation
- Five output formats: **JSON**, **Markdown**, **HTML**, **CSV** (formula-injection safe), and **SARIF 2.1.0**
- Concurrent scanning with worker pool, retry backoff, proxy support, SSRF protection (`--block-private`), and CI/CD severity threshold gates (`--fail-on`)
- SQLite persistence with `history` CLI command to inspect past scans
- Docker (`scratch` with root CA certificates) and GitHub Actions CI/Release included

---

## Requirements

| Tool | Version |
|---|---|
| Go | 1.23+ |
| Git | any |
| Docker | optional |

---

## Installation

### With `go install` (Recommended)

```sh
go install github.com/khaleddevsec/Reconpipeline@latest
# or install as threatlens binary:
go install github.com/khaleddevsec/Reconpipeline/cmd/threatlens@latest
```

### From source

```sh
git clone https://github.com/khaleddevsec/Reconpipeline.git
cd Reconpipeline
go build -o threatlens ./cmd/threatlens
```

Move the binary to your PATH:

```sh
# Linux/macOS
sudo mv threatlens /usr/local/bin/

# Windows (PowerShell)
Move-Item threatlens.exe C:\Windows\System32\
```

### Docker

```sh
docker build -t threatlens .
docker run --rm threatlens scan https://example.com
```

---

## Quick Start

### 1 — Zero-config scan (uses embedded knowledge base)

```sh
threatlens scan https://example.com
# Output: ./reports/report.json
```

### 2 — HTML report you can open in a browser

```sh
threatlens scan -f html -o ./reports https://example.com
# Output: ./reports/report.html
```

### 3 — Custom report name

```sh
threatlens scan -f html -n tesla-audit -o ./reports https://www.tesla.com
# Output: ./reports/tesla-audit.html
```

### 4 — Scan targets from a file or STDIN pipe

```sh
threatlens scan -l targets.txt -f html -n batch-audit
# Or via pipe:
cat targets.txt | threatlens scan -f json -n piped-scan
```

### 5 — CI/CD Pipeline Gate (`--fail-on`)

```sh
threatlens scan --fail-on high -f sarif -n results -o ./reports https://example.com
# Output: ./reports/results.sarif (exits with code 1 if HIGH or CRITICAL findings exist)
```

### 6 — View Scan History from SQLite Database

```sh
threatlens history
threatlens history <scan-id>
```

---

## CLI Reference

```
threatlens scan [url...] [flags]

Flags:
  -f, --format string        report format: json|markdown|html|csv|sarif (default "json")
  -n, --name string          output filename without extension (default "report")
  -o, --output string        output directory for reports (default "./reports")
  -l, --list string          path to file containing target URLs (one per line)
  -c, --config string        config file (optional; embedded knowledge DB used by default)
  -k, --insecure             skip TLS certificate verification
      --proxy string         HTTP/HTTPS/SOCKS5 proxy URL
      --block-private        block private/internal/loopback IPs (SSRF protection)
      --fail-on string       exit with code 1 if findings >= severity exist (low|medium|high|critical)
  -H, --header stringArray   custom HTTP request header (e.g. -H 'Authorization: Bearer token')
  -v, --verbosity string     log level: debug | info | warn | error (default "info")
  -s, --silent               suppress log output
```

---

## Running Tests

```sh
# All tests
go test ./...

# With coverage
go test -cover ./...

# Race detector
go test -race ./...
```

---

## Project Structure

```
main.go               Root CLI entry point (for go install & pkg.go.dev)
cmd/threatlens/       Named binary CLI entry point
pkg/
  cli/                Cobra CLI commands (scan, history, version)
  utils/              URL normalization and ID generation utilities
internal/
  collector/          HTTP/TLS metadata collection, redirect tracking, retries
  parser/             Normalize raw data & detect header/cookie/TLS issues
  fingerprint/        Detect server, framework, CDN, CMS, language
  knowledge/          Embedded + local YAML knowledge database
  correlation/        Map findings to MITRE ATT&CK, CAPEC, CWE, OWASP
  risk/               Non-diluting risk scoring engine
  report/             JSON / Markdown / HTML / CSV / SARIF reporters
  database/           SQLite persistence
  plugins/            Plugin registry
models/               Shared domain types
knowledge/            Embedded YAML security knowledge rules
tests/                End-to-end integration tests
```

---

## License

MIT — see [LICENSE](LICENSE) for details.
