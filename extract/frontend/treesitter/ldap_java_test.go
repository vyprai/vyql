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

// Expansion / Track 2 sink-breadth: Java JNDI LDAP injection (CWE-90). DirContext.search
// takes the filter as arg 1; a tainted filter is injectable. A constant filter is clean.
func TestLdapInjectionJava(t *testing.T) {
	rule := `
package vypr.injection;
rule Ldap { meta { id: "VYQL-INJ-005", severity: high } taint code.HttpInput -> code.LdapQuery }
`
	scan := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "L.java")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := treesitter.ExtractJava([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.JavaAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(rule)
		compiled, _ := engine.CompileRules(decls, onto)
		var n int
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			n += len(fs)
		}
		return n
	}

	if scan(`class L {
  void run(HttpServletRequest request, DirContext ctx) throws Exception {
    String user = request.getParameter("user");
    ctx.search("ou=people", "(uid=" + user + ")", new SearchControls());
  }
}`) == 0 {
		t.Fatal("expected LDAP-injection finding for tainted DirContext filter, got 0")
	}
	if scan(`class L {
  void run(DirContext ctx) throws Exception {
    ctx.search("ou=people", "(uid=admin)", new SearchControls());
  }
}`) != 0 {
		t.Fatal("a constant LDAP filter is clean, got a finding")
	}
}
