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

// The REAL tree-sitter C++ frontend finds a command injection: getenv flows
// through std::string `+` concatenation into std::system; a constant is clean.
func TestTreeSitterCPP(t *testing.T) {
	run := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "h.cpp")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := treesitter.ExtractCPP([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.CPPAdapters(), nil)
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

	vuln := `#include <cstdlib>
#include <string>
void h() {
  std::string host = getenv("HOST");
  std::string cmd = "ping " + host;
  std::system(cmd.c_str());
}`
	if run(vuln) == 0 {
		t.Fatal("expected command injection (getenv→+concat→std::system), got 0")
	}

	safe := `#include <cstdlib>
void h() {
  std::system("ping localhost");
}`
	if run(safe) != 0 {
		t.Fatal("constant command should be clean, got a finding")
	}
}
