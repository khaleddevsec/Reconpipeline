package report

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/khaleddevsec/Reconpipeline/v2/models"
	"go.uber.org/zap"
)

// SARIFReporter implements Generator for SARIF 2.1.0 output.
type SARIFReporter struct {
	log *zap.Logger
}

// NewSARIFReporter constructs a SARIFReporter.
func NewSARIFReporter(log *zap.Logger) *SARIFReporter {
	return &SARIFReporter{log: log}
}

func (r *SARIFReporter) Format() models.ReportFormat { return models.ReportFormatSARIF }

// Generate writes a SARIF 2.1.0 document to w.
func (r *SARIFReporter) Generate(_ context.Context, rep *models.Report, w io.Writer) error {
	if rep == nil {
		return fmt.Errorf("report: nil report")
	}

	doc := buildSARIF(rep)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("report: marshal sarif: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("report: write sarif: %w", err)
	}
	r.log.Info("SARIF report written", zap.Int("results", len(rep.Results)))
	return nil
}

// ----- SARIF 2.1.0 types -----

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

func buildSARIF(rep *models.Report) sarifDocument {
	// collect unique rules across all results
	rulesMap := make(map[string]sarifRule)
	var sarifResults []sarifResult

	for _, result := range rep.Results {
		for _, f := range result.Findings {
			if _, seen := rulesMap[f.ID]; !seen {
				props := make(map[string]string)
				if f.CWEID != "" {
					props["cwe"] = f.CWEID
				}
				if f.CAPECID != "" {
					props["capec"] = f.CAPECID
				}
				rulesMap[f.ID] = sarifRule{
					ID:               f.ID,
					Name:             f.Title,
					ShortDescription: sarifMessage{Text: f.Description},
					Properties:       props,
				}
			}
			sarifResults = append(sarifResults, sarifResult{
				RuleID:  f.ID,
				Level:   sarifLevel(f.Severity),
				Message: sarifMessage{Text: f.Title + ": " + f.Remediation},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysical{
						ArtifactLocation: sarifArtifact{URI: result.Target.URL},
					},
				}},
			})
		}
	}

	rules := make([]sarifRule, 0, len(rulesMap))
	for _, r := range rulesMap {
		rules = append(rules, r)
	}

	return sarifDocument{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:    "ThreatLens",
				Version: rep.Version,
				Rules:   rules,
			}},
			Results: sarifResults,
		}},
	}
}

func sarifLevel(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
