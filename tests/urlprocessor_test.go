package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/frozeniceee/Reconpipeline/internal/urlprocessor"
)

func TestProcess_Merge(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")

	katanaFile := filepath.Join(dir, "katana.txt")
	gauFile := filepath.Join(dir, "gau.txt")

	katanaURLs := "https://example.com/page1\nhttps://example.com/page2\n"
	gauURLs := "https://example.com/page2\nhttps://example.com/page3\n"

	if err := os.WriteFile(katanaFile, []byte(katanaURLs), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gauFile, []byte(gauURLs), 0640); err != nil {
		t.Fatal(err)
	}

	results, err := urlprocessor.Process(katanaFile, gauFile, outDir)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	// 3 unique URLs (page1, page2, page3).
	if results.Unique != 3 {
		t.Errorf("expected 3 unique URLs, got %d", results.Unique)
	}
}

func TestProcess_Deduplication(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")

	katanaFile := filepath.Join(dir, "katana.txt")
	gauFile := filepath.Join(dir, "gau.txt")

	sameURL := "https://example.com/page\n"
	os.WriteFile(katanaFile, []byte(sameURL+sameURL), 0640)
	os.WriteFile(gauFile, []byte(sameURL), 0640)

	results, err := urlprocessor.Process(katanaFile, gauFile, outDir)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	if results.Unique != 1 {
		t.Errorf("expected 1 unique URL after deduplication, got %d", results.Unique)
	}
}

func TestProcess_Classification_API(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")

	katanaFile := filepath.Join(dir, "katana.txt")
	gauFile := filepath.Join(dir, "gau.txt")

	os.WriteFile(katanaFile, []byte("https://example.com/api/v1/users\n"), 0640)
	os.WriteFile(gauFile, []byte{}, 0640)

	results, err := urlprocessor.Process(katanaFile, gauFile, outDir)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	if results.API < 1 {
		t.Errorf("expected at least 1 API URL, got %d", results.API)
	}
}

func TestProcess_Classification_JavaScript(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")

	katanaFile := filepath.Join(dir, "katana.txt")
	gauFile := filepath.Join(dir, "gau.txt")

	os.WriteFile(katanaFile, []byte("https://example.com/assets/app.js\n"), 0640)
	os.WriteFile(gauFile, []byte{}, 0640)

	results, err := urlprocessor.Process(katanaFile, gauFile, outDir)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	if results.JavaScript < 1 {
		t.Errorf("expected at least 1 JavaScript URL, got %d", results.JavaScript)
	}
}

func TestProcess_Classification_Parameterised(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")

	katanaFile := filepath.Join(dir, "katana.txt")
	gauFile := filepath.Join(dir, "gau.txt")

	os.WriteFile(katanaFile, []byte("https://example.com/page?id=1&name=test\n"), 0640)
	os.WriteFile(gauFile, []byte{}, 0640)

	results, err := urlprocessor.Process(katanaFile, gauFile, outDir)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	if results.Parameterised < 1 {
		t.Errorf("expected at least 1 parameterised URL, got %d", results.Parameterised)
	}
}

func TestProcess_NormalisesScheme(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")

	katanaFile := filepath.Join(dir, "katana.txt")
	gauFile := filepath.Join(dir, "gau.txt")

	os.WriteFile(katanaFile, []byte("HTTPS://Example.COM/Path\n"), 0640)
	os.WriteFile(gauFile, []byte{}, 0640)

	_, err := urlprocessor.Process(katanaFile, gauFile, outDir)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	// Read normalised file and check lowercase.
	data, _ := os.ReadFile(filepath.Join(outDir, "normalized-urls.txt"))
	if !strings.Contains(string(data), "https://example.com") {
		t.Errorf("expected normalised URL with lowercase scheme+host, got: %s", string(data))
	}
}

func TestProcess_MissingFiles(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")

	// Neither file exists — should not error.
	results, err := urlprocessor.Process(
		filepath.Join(dir, "missing-katana.txt"),
		filepath.Join(dir, "missing-gau.txt"),
		outDir,
	)
	if err != nil {
		t.Fatalf("expected no error for missing files, got: %v", err)
	}
	if results.Unique != 0 {
		t.Errorf("expected 0 unique URLs, got %d", results.Unique)
	}
}

func TestCountLines(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.txt")
	os.WriteFile(f, []byte("line1\nline2\nline3\n"), 0640)

	n := urlprocessor.CountLines(f)
	if n != 3 {
		t.Errorf("expected 3 lines, got %d", n)
	}
}

func TestCountLines_MissingFile(t *testing.T) {
	n := urlprocessor.CountLines("/nonexistent/path/file.txt")
	if n != 0 {
		t.Errorf("expected 0 for missing file, got %d", n)
	}
}
