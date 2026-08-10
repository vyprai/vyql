package main

// NIR/USG golden snapshots. For a representative
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

	"github.com/vyprai/vyql/internal/extract"
	"github.com/vyprai/vyql/internal/extract/lowering"
)

// nirGoldenCases: a representative snippet per language exercising source/assign/concat/call.
var nirGoldenCases = map[string]struct{ ext, code string }{
	"go":         {".go", "package m\nfunc h(source Source, worker Worker) {\n\tx := source.Value(\"q\")\n\tworker.Run(\"prefix \" + x)\n}\n"},
	"python":     {".py", "def h(source, worker):\n    x = source.value('q')\n    worker.run('prefix ' + x)\n"},
	"javascript": {".js", "function h(source, worker) {\n  var x = source.value('q');\n  worker.run('prefix ' + x);\n}\n"},
	"java":       {".java", "class C {\n  void h(Source source, Worker worker) {\n    String x = source.value(\"q\");\n    worker.run(\"prefix \" + x);\n  }\n}\n"},
	"ruby":       {".rb", "def h(source, worker)\n  x = source.value('q')\n  worker.run('prefix ' + x)\nend\n"},
	"php":        {".php", "<?php\nfunction h($source, $worker) {\n  $x = $source->value('q');\n  $worker->run('prefix ' . $x);\n}\n"},
	"rust":       {".rs", "fn h(source: Source, worker: Worker) {\n  let u = source.value(\"q\");\n  worker.run(format!(\"prefix {}\", u));\n}\n"},
	"elixir":     {".ex", "defmodule H do\n  def h(source, worker) do\n    name = Source.value(source, \"q\")\n    Worker.run(worker, \"prefix \" <> name)\n  end\nend\n"},
	"dart":       {".dart", "void h(source, worker) {\n  var u = source.value(\"q\");\n  worker.run(\"prefix \" + u);\n}\n"},
	"groovy":     {".groovy", "def h(source, worker) {\n  def v = source.value(\"q\")\n  worker.run(\"prefix \" + v)\n}\n"},
}

func usgStructuralSummary(t *testing.T, ext, code string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "snippet"+ext), []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, _, ctorTypes, _, err := extract.All([]string{dir}, nil)
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
