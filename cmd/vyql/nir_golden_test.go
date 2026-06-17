package main

// T0.7 (plan/test-coverage-tasklist.md): NIR/USG golden snapshots. For a representative
// snippet per language, snapshot the lowered structural output (call/attr
// callee paths) and assert it stays stable — catching silent frontend regressions that no
// rule spec happens to exercise. Regenerate with VYQL_UPDATE_GOLDEN=1.
//
// Goldens are DATA (testdata/golden/<lang>.golden); only this runner is Go.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/vyprai/vyql/extract/lowering"
)

// nirGoldenCases: a representative snippet per language exercising source/assign/concat/call.
var nirGoldenCases = map[string]struct{ ext, code string }{
	"go":         {".go", "package m\nimport \"net/http\"\nfunc h(r *http.Request) {\n\tx := r.URL.Query().Get(\"q\")\n\tdb.Query(\"SELECT \" + x)\n}\n"},
	"python":     {".py", "def h():\n    x = request.args.get('q')\n    cursor.execute('SELECT ' + x)\n"},
	"javascript": {".js", "function h(req) {\n  var x = req.query.q;\n  db.query('SELECT ' + x);\n}\n"},
	"java":       {".java", "class C {\n  void h(HttpServletRequest r) {\n    String x = r.getParameter(\"q\");\n    st.executeQuery(\"SELECT \" + x);\n  }\n}\n"},
	"ruby":       {".rb", "def h\n  x = params[:q]\n  conn.execute('SELECT ' + x)\nend\n"},
	"php":        {".php", "<?php\n$x = $_GET['q'];\nmysqli_query($c, 'SELECT ' . $x);\n"},
	"rust":       {".rs", "fn h() {\n  let u = std::env::var(\"Q\").unwrap();\n  let _ = std::process::Command::new(\"sh\").arg(u);\n}\n"},
	"elixir":     {".ex", "defmodule H do\n  def h(conn, params) do\n    name = params[\"q\"]\n    System.cmd(\"sh\", [name])\n  end\nend\n"},
	"dart":       {".dart", "void h() {\n  var u = Platform.environment[\"Q\"];\n  db.rawQuery(\"SELECT \" + u);\n}\n"},
	"groovy":     {".groovy", "def h(name) {\n  def b = params.BRANCH\n  sh(\"echo \" + b)\n}\n"},
}

func usgStructuralSummary(t *testing.T, ext, code string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "snippet"+ext), []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, _, ctorTypes, _, err := extractAll([]string{dir})
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	store, err := lowering.LowerTyped(prog, true, ctorTypes)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	nodes, _ := store.AllNodes()
	var lines []string
	for _, n := range nodes {
		switch n.Type {
		case "code.Call":
			lines = append(lines, "call "+n.Prop("callee_path"))
		case "code.Attr":
			lines = append(lines, "attr "+n.Prop("callee_path"))
		}
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}

func TestNIRGolden(t *testing.T) {
	update := os.Getenv("VYQL_UPDATE_GOLDEN") == "1"
	goldenDir := "testdata/golden"
	if update {
		_ = os.MkdirAll(goldenDir, 0o755)
	}
	for lang, c := range nirGoldenCases {
		lang, c := lang, c
		t.Run(lang, func(t *testing.T) {
			got := usgStructuralSummary(t, c.ext, c.code)
			path := filepath.Join(goldenDir, lang+".golden")
			if update {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("missing golden %s (run VYQL_UPDATE_GOLDEN=1): %v", path, err)
			}
			if got != string(want) {
				t.Errorf("NIR golden mismatch for %s — frontend output changed.\n--- want ---\n%s\n--- got ---\n%s", lang, want, got)
			}
		})
	}
}
