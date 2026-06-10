package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/engine"
	"github.com/vyprai/vyql/extract/frontend"
	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
)

// The REAL tree-sitter C frontend finds a command injection where untrusted input
// (getenv) flows through a buffer writer (sprintf) into system(); a constant
// command is clean.
func TestTreeSitterCCommandInjection(t *testing.T) {
	run := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "h.c")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := treesitter.ExtractC([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.CAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(twoSinkRules)
		compiled, _ := engine.CompileRules(decls, onto)
		var n int
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			n += len(fs)
		}
		return n
	}

	// getenv → sprintf(cmd, ...) → system(cmd): tainted via the buffer writer.
	vuln := `#include <stdlib.h>
void h() {
  char *host = getenv("HOST");
  char cmd[256];
  sprintf(cmd, "ping %s", host);
  system(cmd);
}`
	if run(vuln) == 0 {
		t.Fatal("expected command injection (getenv→sprintf→system), got 0")
	}

	// constant command — no taint, clean.
	safe := `void h() {
  char cmd[256];
  sprintf(cmd, "ping localhost");
  system(cmd);
}`
	if run(safe) != 0 {
		t.Fatal("constant command should be clean, got a finding")
	}
}
