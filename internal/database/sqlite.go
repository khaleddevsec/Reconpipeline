package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/khaleddevsec/Reconpipeline/models"
	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

// SQLiteStore implements Store using a local SQLite database.
type SQLiteStore struct {
	db  *sql.DB
	log *zap.Logger
}

// NewSQLiteStore returns an uninitialised SQLiteStore.
func NewSQLiteStore(log *zap.Logger) *SQLiteStore {
	return &SQLiteStore{log: log}
}

// Open opens or creates the SQLite file at path and runs migrations.
func (s *SQLiteStore) Open(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("database: create dir: %w", err)
	}

	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("database: open: %w", err)
	}
	db.SetMaxOpenConns(1)
	s.db = db
	return s.migrate()
}

func (s *SQLiteStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS scan_results (
			id           TEXT PRIMARY KEY,
			target_url   TEXT NOT NULL,
			collected_at TEXT NOT NULL,
			analysed_at  TEXT NOT NULL,
			risk_score   REAL NOT NULL,
			findings     TEXT NOT NULL,
			fingerprints TEXT NOT NULL DEFAULT '[]'
		)`)
	if err != nil {
		return fmt.Errorf("database: migrate: %w", err)
	}
	return nil
}

func (s *SQLiteStore) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteStore) SaveResult(ctx context.Context, result *models.ScanResult) error {
	findings, err := json.Marshal(result.Findings)
	if err != nil {
		return fmt.Errorf("database: marshal findings: %w", err)
	}
	fps, err := json.Marshal(result.Fingerprints)
	if err != nil {
		return fmt.Errorf("database: marshal fingerprints: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO scan_results
		 (id, target_url, collected_at, analysed_at, risk_score, findings, fingerprints)
		 VALUES (?,?,?,?,?,?,?)`,
		result.ID,
		result.Target.URL,
		result.CollectedAt.UTC().Format(time.RFC3339),
		result.AnalysedAt.UTC().Format(time.RFC3339),
		result.RiskScore,
		string(findings),
		string(fps),
	)
	if err != nil {
		return fmt.Errorf("database: save result: %w", err)
	}
	s.log.Debug("result saved", zap.String("id", result.ID))
	return nil
}

func (s *SQLiteStore) GetResult(ctx context.Context, id string) (*models.ScanResult, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, target_url, collected_at, analysed_at, risk_score, findings, fingerprints
		 FROM scan_results WHERE id = ?`, id)
	return scanRow(row)
}

func (s *SQLiteStore) ListResults(ctx context.Context) ([]models.ScanResult, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, target_url, collected_at, analysed_at, risk_score, findings, fingerprints
		 FROM scan_results ORDER BY collected_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("database: list results: %w", err)
	}
	defer rows.Close()

	var results []models.ScanResult
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, *r)
	}
	return results, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanRow(s scanner) (*models.ScanResult, error) {
	var (
		result     models.ScanResult
		collectedS string
		analysedS  string
		findingsJ  string
		fpsJ       string
	)
	if err := s.Scan(
		&result.ID,
		&result.Target.URL,
		&collectedS,
		&analysedS,
		&result.RiskScore,
		&findingsJ,
		&fpsJ,
	); err != nil {
		return nil, fmt.Errorf("database: scan row: %w", err)
	}
	result.CollectedAt, _ = time.Parse(time.RFC3339, collectedS)
	result.AnalysedAt, _ = time.Parse(time.RFC3339, analysedS)
	if err := json.Unmarshal([]byte(findingsJ), &result.Findings); err != nil {
		return nil, fmt.Errorf("database: unmarshal findings: %w", err)
	}
	if fpsJ != "" {
		_ = json.Unmarshal([]byte(fpsJ), &result.Fingerprints)
	}
	return &result, nil
}
