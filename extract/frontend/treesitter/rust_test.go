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

// The REAL tree-sitter Rust frontend finds a command injection: std::env::var
// flows through format! into Command::new(...).arg(cmd); a constant arg is clean.
func TestTreeSitterRust(t *testing.T) {
	run := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "main.rs")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := treesitter.ExtractRust([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.RustAdapters(), nil)
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

	vuln := `fn h() {
  let name = std::env::var("NAME").unwrap();
  let cmd = format!("ping {}", name);
  std::process::Command::new("sh").arg("-c").arg(cmd).output();
}`
	if run(vuln) == 0 {
		t.Fatal("expected command injection (env::var→format!→Command.arg), got 0")
	}

	safe := `fn h() {
  std::process::Command::new("ls").arg("-la").output();
}`
	if run(safe) != 0 {
		t.Fatal("constant args should be clean, got a finding")
	}
}
