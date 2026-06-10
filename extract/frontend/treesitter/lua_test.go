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

// The REAL tree-sitter Lua frontend finds an OpenResty command injection: an
// nginx request arg flows through `..` concat into os.execute; a constant is clean.
func TestTreeSitterLua(t *testing.T) {
	run := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "h.lua")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := treesitter.ExtractLua([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.LuaAdapters(), nil)
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

	vuln := `local function handle()
  local name = ngx.var.arg_name
  os.execute("ping " .. name)
end`
	if run(vuln) == 0 {
		t.Fatal("expected command injection (ngx.var → os.execute), got 0")
	}

	safe := `local function handle()
  os.execute("ping localhost")
end`
	if run(safe) != 0 {
		t.Fatal("constant command should be clean, got a finding")
	}
}
