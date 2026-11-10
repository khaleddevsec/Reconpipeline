// Command threatlens is a Go-based cybersecurity intelligence engine that collects
// HTTP/TLS metadata and correlates findings with MITRE ATT&CK, CAPEC, CWE, and OWASP.
package main

import "github.com/khaleddevsec/Reconpipeline/pkg/cli"

var version = "v1.0.0"

func main() {
	cli.SetVersion(version)
	cli.Execute()
}
