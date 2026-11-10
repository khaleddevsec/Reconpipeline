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
//	go install github.com/khaleddevsec/Reconpipeline/v2/cmd/threatlens@latest
package main

import "github.com/khaleddevsec/Reconpipeline/v2/pkg/cli"

var version = "v2.5.0"

func main() {
	cli.SetVersion(version)
	cli.Execute()
}

