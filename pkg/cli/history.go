package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/khaleddevsec/Reconpipeline/v2/internal/database"
	"github.com/spf13/cobra"
)

var historyCmd = &cobra.Command{
	Use:   "history [scan-id]",
	Short: "List past scans from the local SQLite database or inspect a specific scan ID",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runHistory,
}

func init() {
	rootCmd.AddCommand(historyCmd)
}

func runHistory(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	cfg := loadConfig(cmd)

	dbPath := filepath.Join(cfg.OutputDir, "threatlens.db")
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("no scan history database found at %s", dbPath)
	}

	store := database.NewSQLiteStore(logger)
	if err := store.Open(dbPath); err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer store.Close()

	if len(args) == 1 {
		res, err := store.GetResult(ctx, args[0])
		if err != nil {
			return fmt.Errorf("scan ID %q not found: %w", args[0], err)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}

	results, err := store.ListResults(ctx)
	if err != nil {
		return fmt.Errorf("list history: %w", err)
	}
	if len(results) == 0 {
		fmt.Println("No scan history recorded yet.")
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tTARGET\tRISK SCORE\tFINDINGS\tCOLLECTED AT")
	for _, r := range results {
		fmt.Fprintf(tw, "%s\t%s\t%.2f/10\t%d\t%s\n",
			r.ID,
			r.Target.URL,
			r.RiskScore,
			len(r.Findings),
			r.CollectedAt.Format("2006-01-02 15:04:05 UTC"),
		)
	}
	return tw.Flush()
}

