# Changelog

All notable changes to this project are documented in this file.

This project follows [Semantic Versioning](https://semver.org/).

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
