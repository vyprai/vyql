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

// The GENERATED tree-sitter Solidity grammar (raw grammar.js → tree-sitter
// generate → cgo-wrapped) finds an arbitrary external call and a privileged
// selfdestruct driven by attacker-controlled (public function) parameters.
func TestTreeSitterSolidity(t *testing.T) {
	run := func(src string) map[string]int {
		dir := t.TempDir()
		p := filepath.Join(dir, "C.sol")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := treesitter.ExtractSolidity([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.SolidityAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(`
package vypr.smartcontract;
rule ExternalCall { meta { id: "VYQL-SC-001", severity: high } taint core.UserControlledData -> code.ExternalCall }
rule PrivilegedDestruct { meta { id: "VYQL-SC-002", severity: critical } taint core.UserControlledData -> code.PrivilegedOp }
`)
		compiled, errs := engine.CompileRules(decls, onto)
		if len(errs) != 0 {
			t.Fatalf("compile: %v", errs)
		}
		byRule := map[string]int{}
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			for _, f := range fs {
				byRule[f.RuleID]++
			}
		}
		return byRule
	}

	vuln := run(`contract Bank {
  address owner;
  function withdraw(address to, uint amt) public {
    to.call{value: amt}("");
  }
  function kill(address target) public {
    selfdestruct(target);
  }
}`)
	if vuln["VYQL-SC-001"] == 0 {
		t.Fatalf("expected arbitrary external call (tainted to.call), got %v", vuln)
	}
	if vuln["VYQL-SC-002"] == 0 {
		t.Fatalf("expected privileged selfdestruct (tainted param), got %v", vuln)
	}

	safe := run(`contract Bank {
  address owner;
  function payout() public {
    owner.transfer(1);
  }
}`)
	if len(safe) != 0 {
		t.Fatalf("transfer to a state-var address should be clean, got %v", safe)
	}
}
