# Contributing to Reconpipeline (ThreatLens)

Thank you for your interest in contributing to **Reconpipeline**!

## How to Contribute

1. Fork the repository (`https://github.com/khaleddevsec/Reconpipeline`).
2. Create a feature or bugfix branch (`git checkout -b feat/your-feature`).
3. Ensure all code is formatted with `gofmt` and passes `go vet ./...` and `go test -race ./...`.
4. Submit a Pull Request with a clear summary of changes.

## Adding Knowledge Base Rules

Security intelligence rules live in `knowledge/*.yaml` and are automatically embedded into the binary via `go:embed`. Each rule should include:
- Unique `id`, `title`, `description`, and `severity` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`)
- `confidence` (`0.0`–`1.0`)
- Standard mappings (`cwe_id`, `capec_id`, `mitre_attack`, `owasp`)
- Actionable `remediation`
