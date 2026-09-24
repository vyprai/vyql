package golang_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	gofrontend "github.com/vyprai/vyql/internal/extract/frontend/golang"
	"github.com/vyprai/vyql/internal/extract/lowering"
)

// goFunctionContextOf extracts files as one program and returns the str_args of
// fn's analysis.function.context node.
func goFunctionContextOf(t *testing.T, files map[string]string, fn string) string {
	t.Helper()
	dir := t.TempDir()
	var paths []string
	for name, src := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	prog, err := gofrontend.Extract(paths, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context" {
			continue
		}
		if tokens := n.Prop("str_args"); strings.Contains(tokens, "function_name:"+fn+"\x00") || strings.HasSuffix(tokens, "function_name:"+fn) {
			return tokens
		}
	}
	t.Fatalf("no function context for %s; nodes=%#v", fn, nodes)
	return ""
}

// The helper this test's caller delegates to lives in another file of its
// package, because the unit Go resolves a bare identifier call against is the
// package, not the file.
var goDelegatedCalleeFiles = map[string]string{
	"containment.go": `package store

import (
	"fmt"
	"path/filepath"
	"strings"
)

func checkContained(name string) error {
	clean := filepath.Clean(name)
	if strings.HasPrefix(clean, "..") {
		return fmt.Errorf("escapes root")
	}
	return nil
}
`,
	"write.go": `package store

import "os"

func handler(name string) {
	if err := checkContained(name); err != nil {
		return
	}
	os.WriteFile(name, nil, 0o600)
}
`,
}

func TestGoFunctionContextIncludesDelegatedCalleeFacts(t *testing.T) {
	tokens := goFunctionContextOf(t, goDelegatedCalleeFiles, "handler")
	for _, want := range []string{
		"callee:call_path=filepath.Clean",
		"callee:call_path=strings.HasPrefix",
		"callee:call=HasPrefix",
		"callee:literal=..",
		"callee:literal=escapes root",
	} {
		if !strings.Contains(tokens, want) {
			t.Fatalf("handler's context lacks delegated fact %q; tokens=%q", want, tokens)
		}
	}
	// The re-keyed facts must not merge into the caller's own families: asking
	// what handler itself does (`call_path:`) still cannot be answered by what
	// checkContained does. The spellings differ on the separator, so the
	// substring test is exact.
	for _, own := range []string{"call_path:filepath.Clean", "call_path:strings.HasPrefix", "literal:escapes root"} {
		if strings.Contains(tokens, own) {
			t.Fatalf("delegated fact leaked into handler's own family %q; tokens=%q", own, tokens)
		}
	}
}

func TestGoDelegatedCalleeFactsAreOneHopAndBareIdentifierOnly(t *testing.T) {
	tokens := goFunctionContextOf(t, map[string]string{
		"check.go": `package store

import (
	"path/filepath"
	"strings"
)

type reviewer struct{ prefix string }

func (r reviewer) review(path string) bool {
	return strings.EqualFold(path, r.prefix)
}

func checkInner(base, target string) bool {
	rel, err := filepath.Rel(base, target)
	return err == nil && rel != ".."
}

func checkOuter(name string) bool {
	return strings.HasPrefix(name, "sandbox/") && checkInner("sandbox", name)
}
`,
		"write.go": `package store

import "os"

func handler(r reviewer, name string) {
	if !r.review(name) {
		return
	}
	if !checkOuter(name) {
		return
	}
	os.WriteFile(name, nil, 0o600)
}
`,
	}, "handler")
	// One link: checkOuter's own behaviour crosses, and the call it makes to
	// checkInner crosses only as a call path, never as checkInner's behaviour.
	if !strings.Contains(tokens, "callee:call_path=strings.HasPrefix") {
		t.Fatalf("handler's context lacks the first hop's fact; tokens=%q", tokens)
	}
	if strings.Contains(tokens, "filepath.Rel") {
		t.Fatalf("the hop recursed past its first link; tokens=%q", tokens)
	}
	// A member call needs a receiver resolved, which the hop does not do:
	// reviewer.review's behaviour stays behind even though handler calls it.
	if strings.Contains(tokens, "EqualFold") {
		t.Fatalf("a member call's behaviour crossed the hop; tokens=%q", tokens)
	}
}

func TestGoDelegatedCalleeFactsSeparateCheckingFromNonCheckingHelpers(t *testing.T) {
	// The two callers differ only in what the helper they call does, which is
	// the discrimination the delegated facts exist to carry: before them, these
	// two contexts were identical apart from the helpers' names.
	files := map[string]string{
		"helpers.go": `package store

import (
	"fmt"
	"path/filepath"
	"strings"
)

func checkContained(name string) error {
	clean := filepath.Clean(name)
	if strings.HasPrefix(clean, "..") {
		return fmt.Errorf("escapes root")
	}
	return nil
}

func logAccess(name string) {
	fmt.Println("access", name)
}
`,
		"write.go": `package store

import "os"

func guarded(name string) {
	if err := checkContained(name); err != nil {
		return
	}
	os.WriteFile(name, nil, 0o600)
}

func unguarded(name string) {
	logAccess(name)
	os.WriteFile(name, nil, 0o600)
}
`,
	}
	guardedTokens := goFunctionContextOf(t, files, "guarded")
	unguardedTokens := goFunctionContextOf(t, files, "unguarded")
	if !strings.Contains(guardedTokens, "callee:call_path=strings.HasPrefix") {
		t.Fatalf("guarded's context lacks the delegated containment fact; tokens=%q", guardedTokens)
	}
	if strings.Contains(unguardedTokens, "callee:call_path=strings.HasPrefix") {
		t.Fatalf("unguarded's context carries a containment fact no helper it calls performs; tokens=%q", unguardedTokens)
	}
}
