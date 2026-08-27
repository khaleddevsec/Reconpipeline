# Changelog

All notable changes to this project are documented in this file.

This project follows [Semantic Versioning](https://semver.org/).

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
