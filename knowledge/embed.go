// Package knowledgefs embeds the built-in offline security knowledge database.
package knowledgefs

import "embed"

// DefaultFS holds the embedded YAML knowledge base files.
//
//go:embed *.yaml
var DefaultFS embed.FS

