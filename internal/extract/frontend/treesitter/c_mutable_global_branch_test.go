package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
)

// cCalleePaths lowers one C file and returns the callee path of every call in the graph.
func cCalleePaths(t *testing.T, src string) map[string]bool {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "app.c")
	if err := os.WriteFile(file, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	ids, err := g.NodesOfType("code.Call")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, id := range ids {
		n, ok, err := g.GetNode(id)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			out[n.Prop("callee_path")] = true
		}
	}
	return out
}

// A C file-scope flag is a variable, not a constant: `static bool debug_mode = false;` says
// what it holds before main runs, and the setter three functions down says what it holds
// afterwards. Folding `if (debug_mode)` on the initializer alone deletes the whole arm from
// the graph, so the call it guards cannot be labelled by a binding or judged by a rule on
// either the vulnerable or the fixed revision — the branch is not there to look at.
func TestCBranchOnFileScopeFlagSurvivesBothArms(t *testing.T) {
	paths := cCalleePaths(t, `
#include <stdbool.h>

static bool debug_mode = false;

void enable_debug(void) { debug_mode = true; }

void handle(const char *user)
{
    if (debug_mode) {
        run_command(user);
    } else {
        log_only(user);
    }
}
`)
	if !paths["run_command"] {
		t.Error("the guarded arm of `if (debug_mode)` is missing: folded on the declaration-site initializer")
	}
	if !paths["log_only"] {
		t.Error("the fallback arm of `if (debug_mode)` is missing")
	}
}

// The same for a comparison against an integer flag rather than a bare truth test: the fold
// runs through constInt as well as constBool, and both read the module scope. The writer here
// is an ordinary configuration setter, and it is enough to make the flag a variable.
func TestCBranchOnComparedFileScopeFlagSurvivesBothArms(t *testing.T) {
	paths := cCalleePaths(t, `
static int level = 0;

void configure(int n) { level = n; }

void handle(const char *user)
{
    if (level == 1) {
        run_command(user);
    } else {
        log_only(user);
    }
}
`)
	if !paths["run_command"] {
		t.Error("`if (level == 1)` folded away its guarded arm despite configure() writing level")
	}
	if !paths["log_only"] {
		t.Error("the fallback arm of `if (level == 1)` is missing")
	}
}

// A file-scope constant nobody writes still folds, so C files do not lose constant folding
// wholesale — only the flags the file itself reassigns.
func TestCBranchOnUnwrittenFileScopeConstantStillFolds(t *testing.T) {
	paths := cCalleePaths(t, `
#include <stdbool.h>

static const bool FEATURE_ON = false;

void handle(const char *user)
{
    if (FEATURE_ON) {
        run_command(user);
    } else {
        log_only(user);
    }
}
`)
	if paths["run_command"] {
		t.Error("a branch on a file-scope constant the file never writes did not fold")
	}
	if !paths["log_only"] {
		t.Error("the surviving arm of the folded branch is missing")
	}
}
