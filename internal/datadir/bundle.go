package datadir

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultFreeManifestURL is the free definitions channel on dl.vyprsec.ai.
	DefaultFreeManifestURL = "https://dl.vyprsec.ai/vyql/definitions/free/latest.json"
	// DefaultFreeWithTestsManifestURL is the free bundle that includes vyql/tests/.
	DefaultFreeWithTestsManifestURL = "https://dl.vyprsec.ai/vyql/definitions/free/with-tests/latest.json"
)

// Manifest describes one published definitions tarball on dl.vyprsec.ai.
type Manifest struct {
	Version string `json:"version"`
	Channel string `json:"channel"`
	Tests   bool   `json:"tests"`
	SHA256  string `json:"sha256"`
	URL     string `json:"url"`
}

var httpClient = &http.Client{Timeout: 5 * time.Minute}

// DefaultInstallDir is where the install script and vyql update unpack free definitions.
func DefaultInstallDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "vyql", "vyql"), nil
}

// ManifestURL returns the latest.json URL for the free channel.
func ManifestURL(withTests bool) string {
	if u := strings.TrimSpace(os.Getenv("VYQL_DEFINITIONS_MANIFEST_URL")); u != "" {
		return u
	}
	if withTests {
		return DefaultFreeWithTestsManifestURL
	}
	return DefaultFreeManifestURL
}

// FetchManifest reads latest.json from dl.vyprsec.ai.
func FetchManifest(withTests bool) (*Manifest, error) {
	manifestURL := ManifestURL(withTests)
	req, err := http.NewRequest(http.MethodGet, manifestURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch manifest: HTTP %d from %s", resp.StatusCode, manifestURL)
	}
	var m Manifest
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if err := validateManifest(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

func validateManifest(m *Manifest) error {
	if m.URL == "" {
		return fmt.Errorf("manifest has no url")
	}
	if !strings.HasPrefix(m.URL, "https://dl.vyprsec.ai/") {
		if !allowTestManifestURL(m.URL) {
			return fmt.Errorf("manifest url must be on dl.vyprsec.ai; got %s", m.URL)
		}
	}
	if len(m.SHA256) != 64 {
		return fmt.Errorf("manifest sha256 must be 64 hex digits")
	}
	if _, err := hex.DecodeString(m.SHA256); err != nil {
		return fmt.Errorf("manifest sha256 is not hex: %w", err)
	}
	return nil
}

func allowTestManifestURL(raw string) bool {
	if os.Getenv("VYQL_DEFINITIONS_MANIFEST_URL") == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

// ReadVersion returns the semver in VERSION under a data root.
func ReadVersion(root string) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("empty VERSION under %s", root)
	}
	return v, nil
}

// InstallManifest downloads m, verifies its checksum, and unpacks it into dest.
// dest becomes the data root (ontology/, packs/, taxonomy/, …).
func InstallManifest(m *Manifest, dest string) error {
	tmp, err := os.MkdirTemp("", "vyql-definitions-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	archive := filepath.Join(tmp, "definitions.tar.gz")
	if err := downloadFile(m.URL, archive); err != nil {
		return err
	}
	got, err := fileSHA256(archive)
	if err != nil {
		return err
	}
	if got != strings.ToLower(m.SHA256) {
		return fmt.Errorf("checksum mismatch: got %s want %s", got, m.SHA256)
	}

	extracted := filepath.Join(tmp, "extracted")
	if err := os.MkdirAll(extracted, 0o755); err != nil {
		return err
	}
	if err := untarGz(archive, extracted); err != nil {
		return fmt.Errorf("unpack: %w", err)
	}
	dataRoot, err := findDataRoot(extracted)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	if err := replaceDirContents(dataRoot, dest); err != nil {
		return err
	}
	if !isDataRoot(dest) {
		return fmt.Errorf("unpack did not produce a data directory at %s", dest)
	}
	return nil
}

// InstallFree downloads the current free definitions bundle into dest.
func InstallFree(dest string) error {
	m, err := FetchManifest(false)
	if err != nil {
		return err
	}
	return InstallManifest(m, dest)
}

func downloadFile(fileURL, dest string) error {
	req, err := http.NewRequest(http.MethodGet, fileURL, nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", fileURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", fileURL, resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		return fmt.Errorf("download %s: %w", fileURL, err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func untarGz(path, dest string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if strings.Contains(hdr.Name, "..") || !filepath.IsLocal(hdr.Name) {
			return fmt.Errorf("tar entry escapes destination: %s", hdr.Name)
		}
		target := filepath.Join(dest, hdr.Name)
		// Refuse to leave dest even if Join cleaned oddly on a given platform.
		rel, err := filepath.Rel(dest, target)
		if err != nil || !filepath.IsLocal(rel) {
			return fmt.Errorf("tar entry escapes destination: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)&0o777)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				_ = out.Close()
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}
		default:
			// Skip links and special entries so an archive cannot plant a
			// symlink that later entries write through.
			continue
		}
	}
}

func findDataRoot(extracted string) (string, error) {
	if isDataRoot(extracted) {
		return extracted, nil
	}
	entries, err := os.ReadDir(extracted)
	if err != nil {
		return "", err
	}
	if len(entries) == 1 && entries[0].IsDir() {
		cand := filepath.Join(extracted, entries[0].Name())
		if isDataRoot(cand) {
			return cand, nil
		}
	}
	return "", fmt.Errorf("archive did not contain ontology/concepts, packs and taxonomy")
}

func replaceDirContents(src, dest string) error {
	if err := os.RemoveAll(dest); err != nil {
		return err
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	return copyDir(src, dest)
}

func copyDir(src, dest string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dest, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		mode := info.Mode().Perm()
		if mode == 0 {
			mode = 0o644
		}
		return os.WriteFile(target, data, mode)
	})
}
