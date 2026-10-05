package treesitter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/solvers"
	"github.com/vyprai/vyql/internal/usg"
)

// rustLowered lowers src, written to one .rs file, and returns the graph.
func rustLowered(t *testing.T, src string) usg.Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "lib.rs")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := ExtractRust([]string{path}, dir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	return g
}

// The one call node in the graph whose callee path is want.
func rustCall(t *testing.T, g usg.Store, want string) usg.Node {
	t.Helper()
	ids, _ := g.NodesOfType("code.Call")
	var found []usg.Node
	for _, id := range ids {
		if n, ok, _ := g.GetNode(id); ok && n.Prop("callee_path") == want {
			found = append(found, n)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one %s call, got %d", want, len(found))
	}
	return found[0]
}

func rustExits(t *testing.T, g usg.Store) []usg.Node {
	t.Helper()
	ids, _ := g.NodesOfType(usg.ExitNodeType)
	var out []usg.Node
	for _, id := range ids {
		if n, ok, _ := g.GetNode(id); ok {
			out = append(out, n)
		}
	}
	return out
}

// A `return` written inside a branch ends the function without reaching what follows the
// branch. Every other frontend marks that; Rust was lowering the statement as a bare
// expression, so the branch read as falling through and no CFG solver could tell the two
// apart. The operand keeps its place in the body — its calls are still lowered.
func TestRustReturnInsideABranchIsAnExitMarker(t *testing.T) {
	g := rustLowered(t, `
pub fn pick(c: bool) -> i32 {
    if c {
        log::warn!("no");
        return 1;
    }
    finish()
}
`)
	warn := rustCall(t, g, "warn")
	exits := rustExits(t, g)
	if len(exits) != 1 {
		t.Fatalf("want one exit marker for the return inside the branch, got %d", len(exits))
	}
	if r := exits[0].Prop("region"); r != warn.Prop("region") {
		t.Errorf("exit marker region = %q, want the arm's %q", r, warn.Prop("region"))
	}
	if o, w := exits[0].Prop("order"), warn.Prop("order"); o <= w {
		t.Errorf("exit marker order %s must follow the operand's %s", o, w)
	}
}

// A `return` at the top level of the body needs no marker — nothing after it runs at all —
// and one in a closure leaves the closure, not the function that passes it.
func TestRustReturnOutsideABranchIsNotAnExitMarker(t *testing.T) {
	g := rustLowered(t, `
pub fn pick(items: &[i32]) -> i32 {
    for it in items {
        return *it;
    }
    0
}
`)
	if n := len(rustExits(t, g)); n != 0 {
		t.Errorf("a loop body and the function's own tail are not exits of a branch, got %d markers", n)
	}
}

// The shape the scope check of CVE-2025-31477 is written in, at its two revisions: the
// check sits inside the surviving arm of a conditional and the openers follow the
// construct. In the vulnerable revision the absent-configuration arm falls through to the
// opener, so the check is on some paths only; in the fixed one it returns, so every path
// to the opener passed the check. That difference is exactly what forward dominance has
// to see, and it is invisible to region ancestry alone.
func TestRustBranchGuardDominatesTheFollowOnCallOnlyWhenTheSiblingArmLeaves(t *testing.T) {
	const head = `
pub struct OpenScope { pub open: Option<regex::Regex> }
impl OpenScope {
    pub fn open(&self, path: &str) -> Result<(), ()> {
        if let Some(re) = &self.open {
            if !re.is_match(path) {
                return Err(());
            }
`
	const vuln = head + `
        }
        ::open::that_detached(path);
        Ok(())
    }
}
`
	const fixed = head + `
        } else {
            return Err(());
        }
        ::open::that_detached(path);
        Ok(())
    }
}
`
	vulnerable := rustLowered(t, vuln)
	check := rustCall(t, vulnerable, "re.is_match")
	opener := rustCall(t, vulnerable, "open.that_detached")
	if solvers.Dominates(vulnerable, solvers.NewExitIndex(vulnerable), check.ID, opener.ID) {
		t.Error("the arm that carries no configuration falls through to the opener, so the check is on some paths only")
	}

	fixedGraph := rustLowered(t, fixed)
	check = rustCall(t, fixedGraph, "re.is_match")
	opener = rustCall(t, fixedGraph, "open.that_detached")
	if !solvers.Dominates(fixedGraph, solvers.NewExitIndex(fixedGraph), check.ID, opener.ID) {
		t.Error("with the sibling arm returning, every path to the opener passed the check")
	}
}
