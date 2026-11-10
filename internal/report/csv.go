package report

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"

	"github.com/khaleddevsec/Reconpipeline/v2/models"
	"go.uber.org/zap"
)

// CSVReporter implements Generator for CSV output.
type CSVReporter struct {
	log *zap.Logger
}

// NewCSVReporter constructs a CSVReporter.
func NewCSVReporter(log *zap.Logger) *CSVReporter {
	return &CSVReporter{log: log}
}

func (r *CSVReporter) Format() models.ReportFormat { return models.ReportFormatCSV }

// Generate writes findings as CSV rows to w.
func (r *CSVReporter) Generate(_ context.Context, rep *models.Report, w io.Writer) error {
	if rep == nil {
		return fmt.Errorf("report: nil report")
	}

	cw := csv.NewWriter(w)
	if err := cw.Write([]string{
		"target", "finding_id", "title", "severity", "confidence",
		"cwe_id", "capec_id", "owasp", "remediation",
	}); err != nil {
		return fmt.Errorf("report: csv header: %w", err)
	}

	for _, result := range rep.Results {
		for _, f := range result.Findings {
			owasp := ""
			if len(f.OWASP) > 0 {
				owasp = f.OWASP[0]
			}
			if err := cw.Write([]string{
				sanitizeCSVCell(result.Target.URL),
				sanitizeCSVCell(f.ID),
				sanitizeCSVCell(f.Title),
				sanitizeCSVCell(string(f.Severity)),
				fmt.Sprintf("%.2f", f.Confidence),
				sanitizeCSVCell(f.CWEID),
				sanitizeCSVCell(f.CAPECID),
				sanitizeCSVCell(owasp),
				sanitizeCSVCell(f.Remediation),
			}); err != nil {
				return fmt.Errorf("report: csv row: %w", err)
			}
		}
	}

	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("report: csv flush: %w", err)
	}
	r.log.Info("CSV report written", zap.Int("results", len(rep.Results)))
	return nil
}

// sanitizeCSVCell guards against CSV formula injection by prefixing leading
// formula characters (=, +, -, @, tab, CR) with a single quote.
func sanitizeCSVCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	default:
		return s
	}
}
