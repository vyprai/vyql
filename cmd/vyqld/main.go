// Command vyqld is a thin HTTP service that wraps the vyql CLI. Each request
// gets source code onto local disk (uploaded archive, git clone, or a
// server-local path), shells out to `vyql scan -format <fmt>`, and streams the
// scanner's output straight back. The engine is treated as a black box: vyqld
// adds no analysis of its own, only transport, isolation, and lifecycle.
//
// Usage:
//
//	vyqld [-addr :8080] [-bin vyql] [-home /opt/vyql] [-max-concurrency 4]
//
// Configuration (flags override env):
//
//	-addr             listen address                  (env VYQLD_ADDR,  default :8080)
//	-bin              path to the vyql binary         (env VYQL_BIN,    default "vyql" on PATH)
//	-home             VYQL_HOME data dir for the CLI  (env VYQL_HOME)
//	-max-concurrency  in-flight scans allowed         (env VYQLD_MAX_CONCURRENCY, default NumCPU)
//	-scan-timeout     per-scan timeout                (env VYQLD_SCAN_TIMEOUT, default 5m)
//	-max-upload       max archive upload size (bytes) (env VYQLD_MAX_UPLOAD, default 256MiB)
//	-allow-local-path permit scanning server-local paths (env VYQLD_ALLOW_LOCAL_PATH, default false)
package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type config struct {
	addr           string
	bin            string
	home           string
	maxConcurrency int
	scanTimeout    time.Duration
	maxUpload      int64
	allowLocalPath bool
}

func loadConfig() config {
	c := config{
		addr:           envOr("VYQLD_ADDR", ":8080"),
		bin:            envOr("VYQL_BIN", "vyql"),
		home:           os.Getenv("VYQL_HOME"),
		maxConcurrency: envIntOr("VYQLD_MAX_CONCURRENCY", runtime.NumCPU()),
		scanTimeout:    envDurOr("VYQLD_SCAN_TIMEOUT", 5*time.Minute),
		maxUpload:      int64(envIntOr("VYQLD_MAX_UPLOAD", 256<<20)),
		allowLocalPath: envBoolOr("VYQLD_ALLOW_LOCAL_PATH", false),
	}
	flag.StringVar(&c.addr, "addr", c.addr, "listen address")
	flag.StringVar(&c.bin, "bin", c.bin, "path to the vyql binary")
	flag.StringVar(&c.home, "home", c.home, "VYQL_HOME data dir passed to the CLI")
	flag.IntVar(&c.maxConcurrency, "max-concurrency", c.maxConcurrency, "max in-flight scans")
	flag.DurationVar(&c.scanTimeout, "scan-timeout", c.scanTimeout, "per-scan timeout")
	flag.Int64Var(&c.maxUpload, "max-upload", c.maxUpload, "max archive upload size in bytes")
	flag.BoolVar(&c.allowLocalPath, "allow-local-path", c.allowLocalPath, "permit scanning server-local paths")
	flag.Parse()
	if c.maxConcurrency < 1 {
		c.maxConcurrency = 1
	}
	return c
}

func main() {
	cfg := loadConfig()

	// Resolve the binary once at startup so misconfiguration fails loudly here
	// rather than on the first request.
	binPath, err := exec.LookPath(cfg.bin)
	if err != nil {
		log.Fatalf("vyqld: cannot find vyql binary %q: %v", cfg.bin, err)
	}
	cfg.bin = binPath
	if cfg.home == "" {
		log.Printf("vyqld: warning: VYQL_HOME not set; the CLI will fall back to ancestor-directory search")
	}

	srv := &server{cfg: cfg, sem: make(chan struct{}, cfg.maxConcurrency)}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", srv.handleHealth)
	mux.HandleFunc("POST /scan", srv.handleScan)

	// MCP over Streamable HTTP at /mcp. Stateless + JSON responses keep it simple
	// for request/response tool calls; one server instance is reused (it holds no
	// per-session state).
	mcpSrv := srv.mcpServer()
	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return mcpSrv },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true},
	)
	mux.Handle("/mcp", mcpHandler)
	mux.Handle("/mcp/", mcpHandler)

	httpSrv := &http.Server{
		Addr:              cfg.addr,
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
	}
	log.Printf("vyqld: listening on %s (bin=%s home=%s max-concurrency=%d); REST POST /scan, MCP /mcp",
		cfg.addr, cfg.bin, cfg.home, cfg.maxConcurrency)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("vyqld: server error: %v", err)
	}
}

type server struct {
	cfg config
	sem chan struct{} // bounds concurrent scans
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "ok",
		"bin":             s.cfg.bin,
		"home":            s.cfg.home,
		"max_concurrency": s.cfg.maxConcurrency,
	})
}

// scanRequest is the JSON body accepted for git-clone and local-path modes.
// Archive uploads use multipart/form-data instead (field "archive").
type scanRequest struct {
	GitURL  string `json:"git_url"`
	Ref     string `json:"ref"`     // optional branch/tag/sha for git mode
	Path    string `json:"path"`    // server-local path (requires -allow-local-path)
	Profile string   `json:"profile"` // optional threat-model profile passthrough
	Format  string   `json:"format"`  // json (default) | sarif | text | graph-json
	Exclude []string `json:"exclude"` // optional glob patterns to skip (e.g. ["test","examples","*.spec.js"])
}

func (s *server) handleScan(w http.ResponseWriter, r *http.Request) {
	// Admission control: bound concurrent scans, honoring client cancellation.
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-r.Context().Done():
		writeErr(w, http.StatusServiceUnavailable, "server busy, request cancelled")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.scanTimeout)
	defer cancel()

	dir, req, cleanup, err := s.prepareWorkspace(ctx, w, r)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		// prepareWorkspace already wrote the response on error.
		return
	}

	format := normalizeFormat(req.Format)
	out, scanErr := s.runScan(ctx, dir, format, req.Profile, req.Exclude)
	if scanErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			writeErr(w, http.StatusGatewayTimeout, "scan exceeded timeout")
			return
		}
		writeErr(w, http.StatusBadGateway, "scan failed: "+scanErr.Error())
		return
	}

	switch format {
	case "sarif", "json", "graph-json":
		w.Header().Set("Content-Type", "application/json")
	default:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	w.WriteHeader(http.StatusOK)
	w.Write(out)
}

// prepareWorkspace materializes the request's source tree into a temp dir and
// returns the dir to scan, the parsed request, and a cleanup func. On error it
// writes the HTTP response itself and returns a non-nil error.
func (s *server) prepareWorkspace(ctx context.Context, w http.ResponseWriter, r *http.Request) (string, scanRequest, func(), error) {
	contentType := r.Header.Get("Content-Type")

	work, err := os.MkdirTemp("", "vyqld-")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot create workspace")
		return "", scanRequest{}, nil, err
	}
	cleanup := func() { os.RemoveAll(work) }

	// Multipart upload mode: an archive in form field "archive".
	if strings.HasPrefix(contentType, "multipart/form-data") {
		var req scanRequest
		// Cap the upload before any parsing reads the body.
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.maxUpload)
		file, hdr, ferr := r.FormFile("archive")
		if ferr != nil {
			cleanup()
			writeErr(w, http.StatusBadRequest, "expected an 'archive' file field")
			return "", req, nil, ferr
		}
		defer file.Close()
		req.Profile = r.FormValue("profile")
		req.Format = r.FormValue("format")
		if ex := strings.TrimSpace(r.FormValue("exclude")); ex != "" {
			req.Exclude = strings.Split(ex, ",")
		}
		if eerr := extractArchive(file, hdr.Filename, work); eerr != nil {
			cleanup()
			writeErr(w, http.StatusBadRequest, "cannot extract archive: "+eerr.Error())
			return "", req, nil, eerr
		}
		return work, req, cleanup, nil
	}

	// JSON body mode: git clone or server-local path.
	var req scanRequest
	if r.Body != nil {
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		if derr := dec.Decode(&req); derr != nil && !errors.Is(derr, io.EOF) {
			cleanup()
			writeErr(w, http.StatusBadRequest, "invalid JSON body: "+derr.Error())
			return "", req, nil, derr
		}
	}

	switch {
	case req.GitURL != "":
		if gerr := gitClone(ctx, req.GitURL, req.Ref, work); gerr != nil {
			cleanup()
			writeErr(w, http.StatusBadGateway, "git clone failed: "+gerr.Error())
			return "", req, nil, gerr
		}
		return work, req, cleanup, nil

	case req.Path != "":
		if !s.cfg.allowLocalPath {
			cleanup()
			writeErr(w, http.StatusForbidden, "local-path scanning is disabled (set -allow-local-path)")
			return "", req, nil, errors.New("local path disabled")
		}
		abs, perr := filepath.Abs(req.Path)
		if perr != nil {
			cleanup()
			writeErr(w, http.StatusBadRequest, "bad path")
			return "", req, nil, perr
		}
		if st, serr := os.Stat(abs); serr != nil || !st.IsDir() {
			cleanup()
			writeErr(w, http.StatusBadRequest, "path does not exist or is not a directory")
			return "", req, nil, errors.New("bad path")
		}
		cleanup() // nothing to clean for a borrowed local path
		return abs, req, func() {}, nil

	default:
		cleanup()
		writeErr(w, http.StatusBadRequest, "provide a multipart 'archive' upload, or a JSON body with 'git_url' or 'path'")
		return "", req, nil, errors.New("no source")
	}
}

// runScan shells out to `vyql scan` and returns its stdout.
func (s *server) runScan(ctx context.Context, dir, format, profile string, exclude []string) ([]byte, error) {
	args := []string{"scan", "-format", format}
	if profile != "" {
		args = append(args, "-profile", profile)
	}
	if len(exclude) > 0 {
		args = append(args, "-exclude", strings.Join(exclude, ","))
	}
	args = append(args, dir)
	return s.runVyql(ctx, args...)
}

// runVyql execs the vyql CLI with VYQL_HOME set and returns stdout, or an error
// carrying a truncated stderr on a non-zero exit.
func (s *server) runVyql(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, s.cfg.bin, args...)
	cmd.Env = os.Environ()
	if s.cfg.home != "" {
		cmd.Env = append(cmd.Env, "VYQL_HOME="+s.cfg.home)
	}
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return nil, fmt.Errorf("%v: %s", err, truncate(msg, 2000))
		}
		return nil, err
	}
	return []byte(stdout.String()), nil
}

func gitClone(ctx context.Context, url, ref, dest string) error {
	args := []string{"clone", "--depth", "1"}
	if ref != "" {
		args = append(args, "--branch", ref)
	}
	args = append(args, "--", url, dest)
	cmd := exec.CommandContext(ctx, "git", args...)
	// Never let git prompt for credentials on a private/invalid URL — fail fast.
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=true")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v: %s", err, truncate(strings.TrimSpace(stderr.String()), 500))
	}
	return nil
}

// extractArchive unpacks a .tar.gz/.tgz or .zip into dest, guarding against
// path-traversal entries (zip-slip). Unknown extensions are tried as tar.gz.
func extractArchive(r io.Reader, filename, dest string) error {
	name := strings.ToLower(filename)
	switch {
	case strings.HasSuffix(name, ".zip"):
		return extractZip(r, dest)
	default: // .tar.gz, .tgz, .tar, or unknown
		return extractTarGz(r, dest)
	}
}

func extractTarGz(r io.Reader, dest string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		target, err := safeJoin(dest, hdr.Name)
		if err != nil {
			return err
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
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		}
		// Symlinks and other special types are intentionally skipped.
	}
}

func extractZip(r io.Reader, dest string) error {
	// archive/zip needs a ReaderAt; buffer to a temp file.
	tmp, err := os.CreateTemp("", "vyqld-zip-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	size, err := io.Copy(tmp, r)
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(tmp, size)
	if err != nil {
		return err
	}
	for _, zf := range zr.File {
		target, err := safeJoin(dest, zf.Name)
		if err != nil {
			return err
		}
		if zf.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(f, rc)
		rc.Close()
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// safeJoin joins name onto base, rejecting entries that escape base.
func safeJoin(base, name string) (string, error) {
	target := filepath.Join(base, name)
	rel, err := filepath.Rel(base, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe archive path: %q", name)
	}
	return target, nil
}

func normalizeFormat(f string) string {
	switch strings.ToLower(strings.TrimSpace(f)) {
	case "sarif":
		return "sarif"
	case "text":
		return "text"
	case "graph-json":
		return "graph-json"
	default:
		return "json"
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envIntOr(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBoolOr(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func envDurOr(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
