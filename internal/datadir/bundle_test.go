package datadir

import (
	"archive/tar"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallManifest(t *testing.T) {
	dataRoot := t.TempDir()
	for _, d := range []string{"taxonomy", "packs", filepath.Join("ontology", "concepts")} {
		if err := os.MkdirAll(filepath.Join(dataRoot, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dataRoot, "VERSION"), []byte("1.2.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	archivePath := packTestArchive(t, dataRoot)
	sum, err := fileSHA256(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	archiveBytes, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest.json":
			_, _ = w.Write([]byte(`{
  "version": "1.2.3",
  "channel": "free",
  "tests": false,
  "sha256": "` + sum + `",
  "url": "http://` + r.Host + `/definitions.tar.gz"
}`))
		case "/definitions.tar.gz":
			_, _ = w.Write(archiveBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dest := t.TempDir()
	m := &Manifest{
		Version: "1.2.3",
		Channel: "free",
		SHA256:  sum,
		URL:     srv.URL + "/definitions.tar.gz",
	}
	if err := InstallManifest(m, dest); err != nil {
		t.Fatal(err)
	}
	got, err := ReadVersion(dest)
	if err != nil {
		t.Fatal(err)
	}
	if got != "1.2.3" {
		t.Fatalf("VERSION = %q, want 1.2.3", got)
	}
	if !isDataRoot(dest) {
		t.Fatal("dest is not a data root")
	}
}

func TestFetchManifestRejectsNonCDNURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
  "version": "0.0.0",
  "channel": "free",
  "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "url": "https://evil.example/tarball.tar.gz"
}`))
	}))
	defer srv.Close()
	t.Setenv("VYQL_DEFINITIONS_MANIFEST_URL", srv.URL)
	_, err := FetchManifest(false)
	if err == nil {
		t.Fatal("expected error for off-CDN url")
	}
}

func packTestArchive(t *testing.T, dataRoot string) string {
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
	return path
}
