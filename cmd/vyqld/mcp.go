// MCP endpoint for vyqld. In addition to the REST POST /scan, vyqld serves a
// Model Context Protocol server over Streamable HTTP at /mcp, so MCP clients
// (Claude Code/Desktop, agents) can scan remote repositories directly. The tools
// reuse vyqld's existing machinery: a git_url is shallow-cloned (or a
// server-local path is borrowed when -allow-local-path is set), the scan runs
// under the same concurrency limit and per-scan timeout, and the workspace is
// cleaned up afterwards.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const mcpVersion = "0.1.0"

// mcpServer builds the MCP server exposing vyqld's scan tools. The same server
// instance is reused across sessions (it holds no per-session state).
func (s *server) mcpServer() *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "vyql",
		Title:   "VyQL security scanner (vyqld)",
		Version: mcpVersion,
	}, nil)
	s.registerMCP(srv)
	return srv
}

func (s *server) registerMCP(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "vyql_scan",
		Annotations: mcpReadOnly("Scan"),
		Description: "Clone a git repository (git_url) — or open a server-local path when the server permits " +
			"it — and run a full VyQL security scan, returning structured findings (rule, severity, " +
			"fingerprint, source/sink) deduplicated to one per (rule, sink). The primary tool.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpScanIn) (*mcp.CallToolResult, scanOutput, error) {
		return s.mcpScan(ctx, in)
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "vyql_export",
		Annotations: mcpReadOnly("Export"),
		Description: "Scan a git_url (or allowed local path) and return the raw report as sarif (CI/code-" +
			"scanning interchange), graph-json (the structured CODE_MAPPER export), or text (human report). " +
			"For structured findings to reason over, prefer vyql_scan.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpExportIn) (*mcp.CallToolResult, any, error) {
		return s.mcpExport(ctx, in)
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "vyql_explain",
		Annotations: mcpReadOnly("Explain"),
		Description: "Scan a git_url (or allowed local path) and return each finding WITH its proof tree: " +
			"concept bindings, the taint witness path (source → sink), and negation/sanitizer evidence. Use to " +
			"understand WHY a finding fired.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpScanIn) (*mcp.CallToolResult, any, error) {
		return s.mcpExplain(ctx, in)
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "vyql_adapters",
		Annotations: mcpReadOnly("List adapters"),
		Description: "List the source/sink/control/mark vocabulary an adapter provides for a language " +
			"(e.g. lang=javascript). Pure introspection — no repository needed.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpAdaptersIn) (*mcp.CallToolResult, any, error) {
		return s.mcpAdapters(ctx, in)
	})
}

// ---- tool I/O schemas ----

type scanFinding struct {
	Rule            string `json:"rule" jsonschema:"the rule id that fired (e.g. VYQL-INJ-001)"`
	Severity        string `json:"severity" jsonschema:"info | low | medium | high | critical"`
	FP              string `json:"fp" jsonschema:"stable fingerprint (rule + binding locations)"`
	Source          string `json:"source" jsonschema:"source location file:line, empty for presence/config findings"`
	Sink            string `json:"sink" jsonschema:"sink location file:line"`
	AssumptionNoted bool   `json:"assumption_noted" jsonschema:"true if an unsound assumption was noted on the path"`
}

type scanOutput struct {
	Findings []scanFinding `json:"findings" jsonschema:"security findings, deduplicated to one per (rule, sink)"`
	Count    int           `json:"count" jsonschema:"number of findings"`
}

type mcpScanIn struct {
	GitURL  string   `json:"git_url,omitempty" jsonschema:"git repository URL to shallow-clone and scan"`
	Ref     string   `json:"ref,omitempty" jsonschema:"optional branch, tag, or sha for git_url"`
	Path    string   `json:"path,omitempty" jsonschema:"server-local path to scan (requires the server's -allow-local-path)"`
	Profile string   `json:"profile,omitempty" jsonschema:"threat-model profile; default auto-detect"`
	Exclude []string `json:"exclude,omitempty" jsonschema:"glob patterns to skip (e.g. test, *.spec.js)"`
}

type mcpExportIn struct {
	GitURL  string   `json:"git_url,omitempty" jsonschema:"git repository URL to shallow-clone and scan"`
	Ref     string   `json:"ref,omitempty" jsonschema:"optional branch, tag, or sha for git_url"`
	Path    string   `json:"path,omitempty" jsonschema:"server-local path to scan (requires the server's -allow-local-path)"`
	Format  string   `json:"format" jsonschema:"sarif | graph-json | text"`
	Profile string   `json:"profile,omitempty" jsonschema:"threat-model profile; default auto-detect"`
	Exclude []string `json:"exclude,omitempty" jsonschema:"glob patterns to skip"`
}

type mcpAdaptersIn struct {
	Lang string `json:"lang" jsonschema:"technology/adapter to list (e.g. go, javascript, java, python)"`
}

// ---- handlers ----

func (s *server) mcpScan(ctx context.Context, in mcpScanIn) (*mcp.CallToolResult, scanOutput, error) {
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return nil, scanOutput{}, err
	}
	defer release()

	dir, cleanup, err := s.materialize(ctx, in.GitURL, in.Ref, in.Path)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return nil, scanOutput{}, err
	}
	out, err := s.runScan(ctx, dir, "json", in.Profile, in.Exclude)
	if err != nil {
		return nil, scanOutput{}, fmt.Errorf("scan failed: %v", err)
	}
	var fs []scanFinding
	if err := json.Unmarshal(out, &fs); err != nil {
		return nil, scanOutput{}, fmt.Errorf("could not parse scan output: %v", err)
	}
	return nil, scanOutput{Findings: fs, Count: len(fs)}, nil
}

func (s *server) mcpExport(ctx context.Context, in mcpExportIn) (*mcp.CallToolResult, any, error) {
	switch in.Format {
	case "sarif", "graph-json", "text":
	default:
		return nil, nil, fmt.Errorf("invalid format %q (want sarif | graph-json | text)", in.Format)
	}
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer release()

	dir, cleanup, err := s.materialize(ctx, in.GitURL, in.Ref, in.Path)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return nil, nil, err
	}
	out, err := s.runScan(ctx, dir, in.Format, in.Profile, in.Exclude)
	if err != nil {
		return nil, nil, fmt.Errorf("scan failed: %v", err)
	}
	return mcpText(out), nil, nil
}

func (s *server) mcpExplain(ctx context.Context, in mcpScanIn) (*mcp.CallToolResult, any, error) {
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer release()

	dir, cleanup, err := s.materialize(ctx, in.GitURL, in.Ref, in.Path)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return nil, nil, err
	}
	args := []string{"explain"}
	if in.Profile != "" {
		args = append(args, "-profile", in.Profile)
	}
	args = append(args, dir)
	out, err := s.runVyql(ctx, args...)
	if err != nil {
		return nil, nil, fmt.Errorf("explain failed: %v", err)
	}
	return mcpText(out), nil, nil
}

func (s *server) mcpAdapters(ctx context.Context, in mcpAdaptersIn) (*mcp.CallToolResult, any, error) {
	if strings.TrimSpace(in.Lang) == "" {
		return nil, nil, errors.New("lang is required (e.g. go, javascript, java, python)")
	}
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer release()

	out, err := s.runVyql(ctx, "adapters", "-lang", in.Lang)
	if err != nil {
		return nil, nil, fmt.Errorf("adapters failed: %v", err)
	}
	return mcpText(out), nil, nil
}

// ---- helpers ----

// acquire takes a concurrency slot (honoring client cancellation) and derives a
// per-scan timeout context. The returned release frees both.
func (s *server) acquire(ctx context.Context) (context.Context, func(), error) {
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, nil, errors.New("server busy, request cancelled")
	}
	cctx, cancel := context.WithTimeout(ctx, s.cfg.scanTimeout)
	return cctx, func() { cancel(); <-s.sem }, nil
}

// materialize resolves a tool's source into a directory to scan, plus a cleanup
// func. It mirrors prepareWorkspace's git-clone and local-path branches without
// the HTTP coupling (archive upload is REST-only).
func (s *server) materialize(ctx context.Context, gitURL, ref, localPath string) (string, func(), error) {
	switch {
	case gitURL != "":
		work, err := os.MkdirTemp("", "vyqld-mcp-")
		if err != nil {
			return "", nil, err
		}
		if err := gitClone(ctx, gitURL, ref, work); err != nil {
			os.RemoveAll(work)
			return "", nil, fmt.Errorf("git clone failed: %v", err)
		}
		return work, func() { os.RemoveAll(work) }, nil

	case localPath != "":
		if !s.cfg.allowLocalPath {
			return "", nil, errors.New("local-path scanning is disabled (server started without -allow-local-path)")
		}
		abs, err := filepath.Abs(localPath)
		if err != nil {
			return "", nil, err
		}
		if st, serr := os.Stat(abs); serr != nil || !st.IsDir() {
			return "", nil, errors.New("path does not exist or is not a directory")
		}
		return abs, func() {}, nil

	default:
		return "", nil, errors.New("provide git_url or path")
	}
}

const mcpMaxText = 1 << 20 // cap text-format tool output

func mcpText(b []byte) *mcp.CallToolResult {
	text := string(b)
	if len(text) > mcpMaxText {
		text = text[:mcpMaxText] + "\n\n[output truncated]"
	}
	if strings.TrimSpace(text) == "" {
		text = "(vyql produced no output — e.g. no findings)"
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

func mcpReadOnly(title string) *mcp.ToolAnnotations {
	open := true // git_url reaches an external repository
	return &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &open, Title: title}
}
