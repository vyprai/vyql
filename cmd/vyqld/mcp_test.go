package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// mcpTestSession stands up the vyqld MCP server behind an httptest server and
// connects an MCP client over Streamable HTTP.
func mcpTestSession(t *testing.T, s *server) *mcp.ClientSession {
	t.Helper()
	handler := mcp.NewStreamableHTTPHandler(
		func(_ *http.Request) *mcp.Server { return s.mcpServer() },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true},
	)
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	cs, err := client.Connect(context.Background(),
		&mcp.StreamableClientTransport{Endpoint: ts.URL, DisableStandaloneSSE: true}, nil)
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

func TestMCPListTools(t *testing.T) {
	s := &server{cfg: config{bin: "vyql"}, sem: make(chan struct{}, 1)}
	cs := mcpTestSession(t, s)

	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"vyql_scan", "vyql_export", "vyql_explain", "vyql_adapters"}
	got := map[string]bool{}
	for _, tl := range res.Tools {
		got[tl.Name] = true
	}
	if len(res.Tools) != len(want) {
		t.Errorf("want %d tools, got %d", len(want), len(res.Tools))
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("missing tool %q", name)
		}
	}
}

func TestMCPScanLocalPath(t *testing.T) {
	bin := findBin()
	home := os.Getenv("VYQL_HOME")
	if bin == "" || home == "" {
		t.Skip("set VYQL_TEST_BIN (or put vyql on PATH) and VYQL_HOME to run the CLI-backed tools")
	}
	s := &server{
		cfg: config{bin: bin, home: home, scanTimeout: 120 * time.Second, allowLocalPath: true},
		sem: make(chan struct{}, 2),
	}
	cs := mcpTestSession(t, s)
	ctx := context.Background()

	// adapters: no source needed.
	r, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "vyql_adapters", Arguments: map[string]any{"lang": "python"},
	})
	if err != nil {
		t.Fatalf("call vyql_adapters: %v", err)
	}
	if r.IsError {
		t.Fatalf("vyql_adapters error: %s", resultText(r))
	}
	if !strings.Contains(resultText(r), "HttpInput") {
		t.Errorf("python adapters should mention HttpInput")
	}

	// scan a server-local path (allowed in this test config).
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(vulnPy), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err = cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "vyql_scan", Arguments: map[string]any{"path": dir},
	})
	if err != nil {
		t.Fatalf("call vyql_scan: %v", err)
	}
	if r.IsError {
		t.Fatalf("vyql_scan error: %s", resultText(r))
	}
	if !strings.Contains(resultText(r), "VYQL-INJ-001") || r.StructuredContent == nil {
		t.Errorf("expected structured SQL-injection finding, got:\n%s", resultText(r))
	}

	// local path is gated: a server without -allow-local-path must refuse.
	denied := &server{cfg: config{bin: bin, home: home, scanTimeout: 30 * time.Second}, sem: make(chan struct{}, 1)}
	dcs := mcpTestSession(t, denied)
	r, err = dcs.CallTool(ctx, &mcp.CallToolParams{
		Name: "vyql_scan", Arguments: map[string]any{"path": dir},
	})
	if err != nil {
		t.Fatalf("call vyql_scan (denied): %v", err)
	}
	if !r.IsError {
		t.Errorf("expected IsError when local-path scanning is disabled")
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
