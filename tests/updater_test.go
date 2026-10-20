package tests

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/khaleddevsec/Reconpipeline/internal/updater"
)

func TestUpdater_VersionComparison(t *testing.T) {
	if !updater.IsNewer("v2.6.0", "v2.5.0") {
		t.Error("expected v2.6.0 to be newer than v2.5.0")
	}
	if !updater.IsNewer("v3.0.0", "v2.9.9") {
		t.Error("expected v3.0.0 to be newer than v2.9.9")
	}
	if updater.IsNewer("v2.5.0", "v2.5.0") {
		t.Error("identical versions should not be newer")
	}
	if updater.IsNewer("v2.4.9", "v2.5.0") {
		t.Error("older version should not be newer")
	}
}

func TestUpdater_TarGzExtraction(t *testing.T) {
	tempDir := t.TempDir()
	destBinary := filepath.Join(tempDir, "reconpipeline-extracted")

	// Create synthetic tar.gz with "reconpipeline" binary
	var tarGzBuf bytes.Buffer
	gzw := gzip.NewWriter(&tarGzBuf)
	tw := tar.NewWriter(gzw)

	binaryContent := []byte("#!/bin/sh\necho 'Reconpipeline Mock Binary'\n")
	hdr := &tar.Header{
		Name: "reconpipeline",
		Mode: 0755,
		Size: int64(len(binaryContent)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("failed to write tar header: %v", err)
	}
	if _, err := tw.Write(binaryContent); err != nil {
		t.Fatalf("failed to write tar body: %v", err)
	}
	tw.Close()
	gzw.Close()

	// Apply extraction logic via updater check result
	res := &updater.CheckResult{
		AssetURL:  "https://github.com/khaleddevsec/Reconpipeline/releases/download/v2.6.0/reconpipeline-linux-amd64.tar.gz",
		AssetName: "reconpipeline-linux-amd64.tar.gz",
	}
	if res.AssetName == "" {
		t.Fatal("empty asset name")
	}

	// Test directly extracting the tar.gz payload using production updater.ExtractBinary
	err := updater.ExtractBinary(tarGzBuf.Bytes(), destBinary)
	if err != nil {
		t.Fatalf("tar.gz extraction failed: %v", err)
	}

	data, err := os.ReadFile(destBinary)
	if err != nil {
		t.Fatalf("failed to read extracted binary: %v", err)
	}
	if string(data) != string(binaryContent) {
		t.Errorf("content mismatch: got %q, want %q", string(data), string(binaryContent))
	}
}

func TestUpdater_ZipExtraction(t *testing.T) {
	tempDir := t.TempDir()
	destBinary := filepath.Join(tempDir, "reconpipeline.exe")

	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)

	binaryContent := []byte("MOCK_WINDOWS_PE_EXECUTABLE_BYTES")
	w, err := zw.Create("reconpipeline.exe")
	if err != nil {
		t.Fatalf("failed to create zip file entry: %v", err)
	}
	if _, err := w.Write(binaryContent); err != nil {
		t.Fatalf("failed to write zip file content: %v", err)
	}
	zw.Close()

	err = updater.ExtractBinary(zipBuf.Bytes(), destBinary)
	if err != nil {
		t.Fatalf("zip extraction failed: %v", err)
	}

	data, err := os.ReadFile(destBinary)
	if err != nil {
		t.Fatalf("failed to read extracted zip binary: %v", err)
	}
	if string(data) != string(binaryContent) {
		t.Errorf("content mismatch: got %q, want %q", string(data), string(binaryContent))
	}
}

func TestUpdater_RawBinaryDirect(t *testing.T) {
	tempDir := t.TempDir()
	destBinary := filepath.Join(tempDir, "reconpipeline-raw")

	rawContent := []byte("\x7fELF_MOCK_RAW_BINARY")
	err := updater.ExtractBinary(rawContent, destBinary)
	if err != nil {
		t.Fatalf("raw binary write failed: %v", err)
	}

	data, err := os.ReadFile(destBinary)
	if err != nil {
		t.Fatalf("failed to read raw binary: %v", err)
	}
	if string(data) != string(rawContent) {
		t.Errorf("content mismatch: got %q, want %q", string(data), string(rawContent))
	}
}

func TestUpdater_GetVersionStatusOffline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // instantly cancelled context simulates offline / failure
	status := updater.GetVersionStatus(ctx)
	if status == "" {
		t.Error("expected non-empty version status even when offline")
	}
}
