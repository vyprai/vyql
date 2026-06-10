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
	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
)

func scanRuby(t *testing.T, src string) []*findings.Finding {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "users_controller.rb")
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractRuby([]string{p}, dir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if _, _, err := adapters.Apply(g, frontend.RubyAdapters(), nil); err != nil {
		t.Fatalf("adapters: %v", err)
	}
	onto := ontology.Seed()
	decls, _ := parser.Parse(sqliRule)
	compiled, errs := engine.CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	fs, err := engine.New(onto, g).Evaluate(compiled[0])
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	return fs
}

// The REAL tree-sitter Ruby frontend finds a Rails SQLi: params[:name] read,
// concatenated (and interpolated) into an ActiveRecord raw `where`/`execute`,
// and reports zero on the parameterized (placeholder) version.
func TestTreeSitterRubySQLi(t *testing.T) {
	vuln := `class UsersController
  def search
    name = params[:name]
    User.where("name = '" + name + "'")
  end

  def lookup
    id = params[:id]
    ActiveRecord::Base.connection.execute("SELECT * FROM users WHERE id = #{id}")
  end
end
`
	if got := scanRuby(t, vuln); len(got) < 2 {
		t.Fatalf("expected >=2 Rails SQLi findings (concat + interpolation), got %d", len(got))
	}

	safe := `class UsersController
  def search
    name = params[:name]
    User.where("name = ?", name)
  end
end
`
	if got := scanRuby(t, safe); len(got) != 0 {
		t.Fatalf("parameterized query should be clean, got %d", len(got))
	}
}
