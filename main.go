// Reconpipeline (ThreatLens) is a high-performance cybersecurity intelligence engine
// that collects HTTP and TLS metadata from web targets and correlates findings
// with MITRE ATT&CK, CAPEC, CWE, and OWASP Top 10.
//
// Install with:
//
//	go install github.com/khaleddevsec/Reconpipeline@latest
//
// Or:
//
//	go install github.com/khaleddevsec/Reconpipeline/cmd/threatlens@latest
package main

import "github.com/khaleddevsec/Reconpipeline/pkg/cli"

var version = "v1.0.0"

func main() {
	cli.SetVersion(version)
	cli.Execute()
}
