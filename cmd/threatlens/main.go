// Command threatlens is a Go-based cybersecurity intelligence engine that collects
// HTTP/TLS metadata and correlates findings with MITRE ATT&CK, CAPEC, CWE, and OWASP.
package main

import "github.com/khaleddevsec/Reconpipeline/v2/pkg/cli"

var version = "v2.5.0"

func main() {
	cli.SetVersion(version)
	cli.Execute()
}
