package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// ccContextTokensFor returns the function-scope context tokens the C/C++ frontend
// emits for one function of one source file.
func ccContextTokensFor(t *testing.T, name, file string, src string) []string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, file)
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	var prog nir.Program
	var err error
	if strings.HasSuffix(file, ".cpp") {
		prog, err = ExtractCPP([]string{path}, dir)
	} else {
		prog, err = ExtractC([]string{path}, dir)
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(prog.Modules) != 1 {
		t.Fatalf("modules = %d, want 1", len(prog.Modules))
	}
	for _, st := range prog.Modules[0].Body {
		fn, ok := st.(nir.FuncDef)
		if ok && fn.Name == name {
			return fn.ContextTokens
		}
	}
	t.Fatalf("function %q not extracted: %#v", name, prog.Modules[0].Body)
	return nil
}

func ccHasToken(tokens []string, want string) bool {
	for _, tok := range tokens {
		if tok == want {
			return true
		}
	}
	return false
}

// The CVE-2018-10017 shape, reduced: a channel cursor walked by one loop, left one
// element past the end, and dereferenced by a later loop. The fix resets the cursor
// before that loop and steps it in the loop's own header.
//
// Both halves of the fix are invisible to the rest of the function-scope context: the
// reset `pChn = state.Chn;` is textually identical to the one the earlier walk already
// makes, so `assign:pChn=state.Chn` is in the dedup'd token set either way, and a
// `for` header's update clause was tokenized nowhere. Only the (loop, cursor) pair
// tells the two apart.
const ccStaleCursorVulnerable = `
void GetLength(PlayState &state) {
	for(int row = 0; row < state.rows; row++) {
		ModChannel *pChn = state.Chn;
		for(int nChn = 0; nChn < GetNumChannels(); nChn++, pChn++) {
			estimate(pChn->rowCommand.command, pChn->rowCommand.param);
		}
		if(GetType() == MOD_TYPE_IT) {
			for(int nChn = 0; nChn < GetNumChannels(); nChn++) {
				if(pChn->rowCommand.command == CMD_S3MCMDEX) {
					state.chnSettings[nChn].patLoop = state.elapsed;
				}
			}
		}
	}
}
`

const ccStaleCursorFixed = `
void GetLength(PlayState &state) {
	for(int row = 0; row < state.rows; row++) {
		ModChannel *pChn = state.Chn;
		for(int nChn = 0; nChn < GetNumChannels(); nChn++, pChn++) {
			estimate(pChn->rowCommand.command, pChn->rowCommand.param);
		}
		if(GetType() == MOD_TYPE_IT) {
			pChn = state.Chn;
			for(int nChn = 0; nChn < GetNumChannels(); nChn++, pChn++) {
				if(pChn->rowCommand.command == CMD_S3MCMDEX) {
					state.chnSettings[nChn].patLoop = state.elapsed;
				}
			}
		}
	}
}
`

func TestCPPFunctionContextSeparatesStaleCursorFromResetCursor(t *testing.T) {
	vulnerable := ccContextTokensFor(t, "GetLength", "vulnerable.cpp", ccStaleCursorVulnerable)
	fixed := ccContextTokensFor(t, "GetLength", "fixed.cpp", ccStaleCursorFixed)

	const stale = "loop_cursor:pChn:def=loop_carried:step=no"
	if !ccHasToken(vulnerable, stale) {
		t.Fatalf("vulnerable context missing %q; context=%q", stale, strings.Join(vulnerable, "\x00"))
	}
	if ccHasToken(fixed, stale) {
		t.Fatalf("fixed context carries %q; context=%q", stale, strings.Join(fixed, "\x00"))
	}

	// The reset the fix adds is textually identical to the one already there, so the
	// assignment token cannot be what separates them. Assert that directly, or a
	// later change that "fixes" this by making the assign token positional would
	// leave this test passing for the wrong reason.
	for _, tokens := range [][]string{vulnerable, fixed} {
		if !ccHasToken(tokens, "assign:pChn=state.Chn") {
			t.Fatalf("expected assign:pChn=state.Chn in both contexts; context=%q", strings.Join(tokens, "\x00"))
		}
	}

	// The other half: the loop's own update clause, which no token recorded before.
	if !ccHasToken(fixed, "loop_update:nChn++,pChn++") {
		t.Fatalf("fixed context missing loop_update for the stepped loop; context=%q", strings.Join(fixed, "\x00"))
	}
	if !ccHasToken(vulnerable, "loop_update:nChn++") {
		t.Fatalf("vulnerable context missing loop_update for the unstepped loop; context=%q", strings.Join(vulnerable, "\x00"))
	}
}

func TestCLoopCursorTokensReportStepAndReachingDefinition(t *testing.T) {
	tokens := ccContextTokensFor(t, "walk", "walk.c", `
void walk(struct node *head, int n) {
	struct node *p = head;
	for (int i = 0; i < n; i++, p++) {
		use(p->value);
	}
	for (int i = 0; i < n; i++) {
		use(p->value);
	}
	p = head;
	while (p) {
		use(p->value);
		p = p->next;
	}
}
`)
	for _, want := range []string{
		// first loop: reset just above it, and it advances the cursor itself
		"loop_cursor:p:def=straight:step=yes",
		// second loop: reads what the first loop left, and never advances it
		"loop_cursor:p:def=loop_carried:step=no",
		// while loop: reset just above it, advanced in its body rather than a header
		"loop_cursor:p:def=straight:step=yes",
		"loop_update:i++,p++",
		"loop_update:i++",
	} {
		if !ccHasToken(tokens, want) {
			t.Fatalf("C loop-cursor context missing %q; context=%q", want, strings.Join(tokens, "\x00"))
		}
	}
}

// A cursor reset on one arm of a branch only is still "may be loop-carried" at the
// loop below: the arm that does not reset leaves whatever the earlier loop left.
func TestCLoopCursorJoinKeepsLoopCarriedAcrossPartialReset(t *testing.T) {
	tokens := ccContextTokensFor(t, "walk", "join.c", `
void walk(struct node *head, int n, int flag) {
	struct node *p = head;
	for (int i = 0; i < n; i++, p++) {
		use(p->value);
	}
	if (flag) {
		p = head;
	}
	for (int i = 0; i < n; i++) {
		use(p->value);
	}
}
`)
	const stale = "loop_cursor:p:def=loop_carried:step=no"
	if !ccHasToken(tokens, stale) {
		t.Fatalf("partial reset should stay loop-carried; missing %q; context=%q", stale, strings.Join(tokens, "\x00"))
	}
}

// An indexed read off a base pointer does not depend on where an earlier loop left
// the cursor, so it is not reported as one.
func TestCLoopCursorSkipsIndexedBaseReads(t *testing.T) {
	tokens := ccContextTokensFor(t, "walk", "indexed.c", `
void walk(struct node *head, int n) {
	struct node *p = head;
	for (int i = 0; i < n; i++, p++) {
		use(p->value);
	}
	for (int i = 0; i < n; i++) {
		use(p[i].value);
	}
}
`)
	for _, unwanted := range []string{"loop_cursor:p:def=loop_carried:step=no"} {
		if ccHasToken(tokens, unwanted) {
			t.Fatalf("indexed read reported as a stale cursor: %q; context=%q", unwanted, strings.Join(tokens, "\x00"))
		}
	}
}
