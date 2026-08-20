package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateCheckWithoutLocalDefinitions(t *testing.T) {
	srv := testDefinitionsServer(t, "9.9.9")
	t.Setenv("VYQL_DEFINITIONS_MANIFEST_URL", srv.URL+"/latest.json")

	code, out := runVyql(t, "update", "-check")
	if code != 3 {
		t.Fatalf("update -check with no local definitions exited %d, want 3:\n%s", code, out)
	}
	if !strings.Contains(out, "no definitions installed") || !strings.Contains(out, "9.9.9") {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func TestUpdateYesInstallsDefinitions(t *testing.T) {
	srv := testDefinitionsServer(t, "2.0.0")
	t.Setenv("VYQL_DEFINITIONS_MANIFEST_URL", srv.URL+"/latest.json")

	home := t.TempDir()
	t.Setenv("HOME", home)
	installDir := filepath.Join(home, ".local", "share", "vyql", "vyql")

	code, out := runVyql(t, "update", "-yes")
	if code != 0 {
		t.Fatalf("update -yes exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "installed definitions 2.0.0") {
		t.Fatalf("unexpected output:\n%s", out)
	}
	got, err := os.ReadFile(filepath.Join(installDir, "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != "2.0.0" {
		t.Fatalf("VERSION = %q, want 2.0.0", got)
	}
}

func testDefinitionsServer(t *testing.T, version string) *httptest.Server {
	t.Helper()
	dataRoot := t.TempDir()
	for _, d := range []string{"taxonomy", "packs", filepath.Join("ontology", "concepts")} {
		if err := os.MkdirAll(filepath.Join(dataRoot, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dataRoot, "VERSION"), []byte(version+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	archiveBytes := packTestTarball(t, dataRoot)
	sum := sha256.Sum256(archiveBytes)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest.json":
			_, _ = w.Write([]byte(`{
  "version": "` + version + `",
  "channel": "free",
  "sha256": "` + hex.EncodeToString(sum[:]) + `",
  "url": "http://` + r.Host + `/definitions.tar.gz"
}`))
		case "/definitions.tar.gz":
			_, _ = w.Write(archiveBytes)
		default:
			http.NotFound(w, r)
		}
	}))
}

func packTestTarball(t *testing.T, dataRoot string) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "definitions.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	err = filepath.WalkDir(dataRoot, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(dataRoot, p)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if hdr.Name == "." {
			return nil
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
