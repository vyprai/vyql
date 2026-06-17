package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// newTestSession wires the in-process MCP server to a client over an in-memory
// transport and returns the client session. No subprocess, no stdio.
func newTestSession(t *testing.T, s *server) *mcp.ClientSession {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "vyql", Version: "test"}, nil)
	s.register(srv)

	clientT, serverT := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := srv.Connect(ctx, serverT, nil) // server before client (in-memory requirement)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func resultText(r *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range r.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// TestListTools needs no vyql binary: it checks the advertised tool surface.
func TestListTools(t *testing.T) {
	cs := newTestSession(t, &server{bin: "vyql", timeout: 30 * time.Second, maxOut: 1 << 20})

	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"vyql_scan", "vyql_export", "vyql_diff", "vyql_explain", "vyql_trace",
		"vyql_query", "vyql_adapters", "vyql_graph", "vyql_match", "vyql_resolve",
	}
	got := map[string]*mcp.Tool{}
	for _, tl := range res.Tools {
		got[tl.Name] = tl
	}
	if len(res.Tools) != len(want) {
		t.Errorf("want %d tools, got %d", len(want), len(res.Tools))
	}
	for _, name := range want {
		tl, ok := got[name]
		if !ok {
			t.Errorf("missing tool %q", name)
			continue
		}
		if tl.Annotations == nil || !tl.Annotations.ReadOnlyHint {
			t.Errorf("tool %q should be annotated read-only", name)
		}
		if tl.InputSchema == nil {
			t.Errorf("tool %q has no input schema", name)
		}
	}
}

// TestToolsExecuteCLI exercises the real exec path. It is skipped unless a vyql
// binary and data dir are discoverable.
func TestToolsExecuteCLI(t *testing.T) {
	bin := findBin()
	home := os.Getenv("VYQL_HOME")
	if bin == "" || home == "" {
		t.Skip("set VYQL_TEST_BIN (or put vyql on PATH) and VYQL_HOME to run the CLI-backed tools")
	}
	cs := newTestSession(t, &server{bin: bin, home: home, timeout: 120 * time.Second, maxOut: 1 << 20})
	ctx := context.Background()

	// adapters: pure introspection, no source path.
	r, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "vyql_adapters", Arguments: map[string]any{"lang": "python"},
	})
	if err != nil {
		t.Fatalf("call vyql_adapters: %v", err)
	}
	if r.IsError {
		t.Fatalf("vyql_adapters reported error: %s", resultText(r))
	}
	if !strings.Contains(resultText(r), "HttpInput") {
		t.Errorf("python adapters should mention HttpInput, got:\n%s", resultText(r))
	}

	// scan: a temp Flask SQL-injection file should yield VYQL-INJ-001.
	dir := t.TempDir()
	app := filepath.Join(dir, "app.py")
	if err := os.WriteFile(app, []byte(vulnPy), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err = cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "vyql_scan", Arguments: map[string]any{"path": app},
	})
	if err != nil {
		t.Fatalf("call vyql_scan: %v", err)
	}
	if r.IsError {
		t.Fatalf("vyql_scan reported error: %s", resultText(r))
	}
	if !strings.Contains(resultText(r), "VYQL-INJ-001") {
		t.Errorf("expected SQL-injection finding VYQL-INJ-001, got:\n%s", resultText(r))
	}
	if r.StructuredContent == nil {
		t.Errorf("vyql_scan should return structured content")
	}

	// vyql_diff: removing a finding between two saved scan outputs.
	before := filepath.Join(dir, "before.json")
	after := filepath.Join(dir, "after.json")
	os.WriteFile(before, []byte(`[{"rule":"VYQL-INJ-001","severity":"high","fp":"deadbeef","source":"app.py:9","sink":"app.py:12","assumption_noted":false}]`), 0o644)
	os.WriteFile(after, []byte(`[]`), 0o644)
	r, err = cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "vyql_diff", Arguments: map[string]any{"before": before, "after": after},
	})
	if err != nil {
		t.Fatalf("call vyql_diff: %v", err)
	}
	if r.IsError {
		t.Fatalf("vyql_diff reported error: %s", resultText(r))
	}
	if out := resultText(r); !strings.Contains(out, "VYQL-INJ-001") || !strings.Contains(out, "removed") {
		t.Errorf("vyql_diff should report the removed finding, got:\n%s", out)
	}

	// a missing path should surface as a tool error, not a transport failure.
	r, err = cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "vyql_scan", Arguments: map[string]any{"path": filepath.Join(dir, "nope.py")},
	})
	if err != nil {
		t.Fatalf("call vyql_scan (missing path): %v", err)
	}
	if !r.IsError {
		t.Errorf("expected IsError for a missing path")
	}
}

func findBin() string {
	if b := os.Getenv("VYQL_TEST_BIN"); b != "" {
		return b
	}
	if p, err := exec.LookPath("vyql"); err == nil {
		return p
	}
	return ""
}

const vulnPy = `import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/u")
def lookup():
    name = request.args.get("name")
    conn = sqlite3.connect("db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return str(cur.fetchall())
`
