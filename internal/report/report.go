package report

import (
	"context"
	"io"

	"github.com/khaleddevsec/Reconpipeline/v2/models"
	"go.uber.org/zap"
)

// Generator produces a report in a specific output format.
type Generator interface {
	Generate(ctx context.Context, report *models.Report, w io.Writer) error
	Format() models.ReportFormat
}

// GeneratorFor returns the Generator for the requested format, defaulting to JSON.
func GeneratorFor(format models.ReportFormat, log *zap.Logger) Generator {
	switch format {
	case models.ReportFormatMarkdown:
		return NewMarkdownReporter(log)
	case models.ReportFormatHTML:
		return NewHTMLReporter(log)
	case models.ReportFormatCSV:
		return NewCSVReporter(log)
	case models.ReportFormatSARIF:
		return NewSARIFReporter(log)
	default:
		return NewJSONReporter(log)
	}
}
