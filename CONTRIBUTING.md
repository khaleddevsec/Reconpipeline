# Contributing to Reconpipeline

Thank you for your interest in contributing to Reconpipeline.

---

## Go Environment

Reconpipeline is written in Go 1.21 or later.

Reconpipeline respects the following Go binary detection order:

1. `/usr/local/go/bin/go` — preferred
2. `go` from `$PATH`

When building locally:

```bash
# Verify Go is available
/usr/local/go/bin/go version

# Or via PATH
go version
```

Download Go from: https://go.dev/dl/

---

## Project Structure

```
Reconpipeline/
├── cmd/
│   └── reconpipeline/
│       └── main.go           Entry point
│
├── internal/
│   ├── cli/                  CLI commands and flags
│   ├── config/               Internal configuration
│   ├── dependencies/         Tool download and manifest
│   ├── executor/             Safe subprocess execution
│   ├── logging/              Structured logger
│   ├── pipeline/             Pipeline orchestration and run state
│   ├── reporting/            Report generation
│   ├── scope/                Target normalisation and validation
│   ├── tools/
│   │   ├── subfinder/        Subfinder adapter
│   │   ├── httpx/            HTTPX adapter
│   │   ├── katana/           Katana adapter
│   │   ├── gau/              GAU adapter
│   │   └── gf/               GF adapter
│   ├── updater/              Self-update logic
│   ├── urlprocessor/         URL merge, normalise, classify
│   ├── version/              Version source
│   └── workspace/            Workspace directory management
│
├── configs/                  Tool source configuration
├── tests/                    Test files
├── .github/workflows/        CI and release workflows
│
├── go.mod
├── install.sh
├── Makefile
└── README.md
```

---

## Coding Style

- Format all code with `go fmt ./...` before committing.
- Pass `go vet ./...` with no errors.
- All tests must pass with `go test ./...`.
- Use `exec.CommandContext` for subprocess execution — never `sh -c` with user input.
- Managed tool binaries must be resolved from `~/.reconpipeline/tools/` — never from PATH.
- Do not hardcode version numbers. The version is injected via `-ldflags` at build time.
- Do not show raw third-party tool output in the terminal. Only clean stage status.

---

## Testing

Run all tests:

```bash
go test ./...
```

Run with verbose output:

```bash
go test -v ./...
```

Test coverage areas:
- Target normalisation and scope validation
- URL processing (merge, normalise, deduplicate, classify)
- Version comparison
- Workspace directory creation
- Run state save and load
- Report generation

---

## Building

```bash
# Standard build
make build

# Build release binaries for linux/amd64 and linux/arm64
make release

# Run fmt, vet, test, build
make all
```

Or directly:

```bash
go build \
  -ldflags "-s -w -X github.com/frozeniceee/Reconpipeline/internal/version.Version=v2.5.0" \
  -o dist/reconpipeline \
  ./cmd/reconpipeline/
```

---

## Pull Requests

1. Fork the repository.
2. Create a branch: `git checkout -b feature/your-feature`.
3. Make your changes following the coding style above.
4. Run `make all` to verify the build passes.
5. Submit a pull request with a clear description.

---

## Issue Reporting

When reporting a bug, include:

- Reconpipeline version: `reconpipeline --version`
- Doctor output: `reconpipeline doctor`
- Operating system and architecture
- The exact command that failed
- Relevant log output from `~/.reconpipeline/logs/`

---

## Release Process

1. Update `CHANGELOG.md` with the new version details.
2. Create a Git tag: `git tag v2.5.1`
3. Push the tag: `git push origin v2.5.1`
4. GitHub Actions automatically builds and publishes the release.

The version is injected at build time by the release workflow:

```
-X github.com/frozeniceee/Reconpipeline/internal/version.Version=v2.5.1
```

---

## Versioning

Reconpipeline follows Semantic Versioning:

- `MAJOR.MINOR.PATCH`
- PATCH: bug fixes
- MINOR: new features, backwards compatible
- MAJOR: breaking changes

---

## Responsible Use

Reconpipeline is for authorised security testing only.
Contributors must not add features that facilitate unauthorised access to systems.
