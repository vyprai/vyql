package resultpolicy_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// A finding's fingerprint is the identity a user carries between commands: they copy `fp=`
// out of a report and paste it into a baseline, or join graph-json against SARIF for the
// same scan. That only works while every surface publishes the same number.
//
// It has not always. Baselines and graph-json once called a second implementation on the
// domain type while the text report, JSON and SARIF used the policy — so `-baseline`
// suppressed nothing and reported every entry as stale, silently. The second
// implementation is gone, and this test is what stops it coming back: a new output format,
// or a well-meaning `f.Fingerprint()` helper, fails here rather than in someone's pipeline.
func TestEveryOutputSurfacePublishesThePolicyFingerprint(t *testing.T) {
	root := repoRoot(t)
	// Every file that publishes a finding identity to a user or to a file on disk.
	surfaces := []string{
		"cmd/vyql/baseline.go",
		"cmd/vyql/main.go",
		"cmd/vyql/debug.go",
		"internal/sarif/sarif.go",
		"internal/graphjson/graphjson.go",
		"internal/nexus/nexus.go",
	}
	for _, rel := range surfaces {
		t.Run(rel, func(t *testing.T) {
			path := filepath.Join(root, rel)
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("surface %s no longer exists; update this list rather than deleting the guard", rel)
			}
			for _, call := range fingerprintCalls(t, path) {
				if call != "resultpolicy.Fingerprint" && call != "resultpolicy.IdentityPolicy.FingerprintFinding" {
					t.Errorf("%s calls %s; every surface must publish resultpolicy.Fingerprint, "+
						"or a user who copies fp= from one output into another gets a silent non-match", rel, call)
				}
			}
		})
	}
}

// No second implementation may exist to be called. The one that shipped was a method on the
// domain type, which is why it read as the obvious thing to reach for.
func TestOnlyTheResultPolicyOwnsFingerprinting(t *testing.T) {
	root := repoRoot(t)
	allowed := map[string]bool{
		"internal/resultpolicy/identity.go": true,
		// Unrelated senses of the word: cache keys and content hashes, not finding identity.
		"internal/solvers/contract.go":             true,
		"internal/extract/lowering/incremental.go": true,
		"internal/bindings/incremental.go":         true,
		"cmd/vyql/scancache.go":                    true,
		"internal/graphsync/graphsync.go":          true,
	}
	var offenders []string
	err := filepath.Walk(filepath.Join(root, "internal"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if allowed[rel] {
			return nil
		}
		for _, fn := range declaredFingerprintFuncs(t, path) {
			offenders = append(offenders, rel+": "+fn)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("a second finding-fingerprint implementation exists; identity belongs to "+
			"internal/resultpolicy alone:\n  %s", strings.Join(offenders, "\n  "))
	}
}

// fingerprintCalls returns every call in the file whose name ends in Fingerprint, qualified.
func fingerprintCalls(t *testing.T, path string) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !strings.HasSuffix(sel.Sel.Name, "Fingerprint") {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		out = append(out, pkg.Name+"."+sel.Sel.Name)
		return true
	})
	return out
}

// declaredFingerprintFuncs returns functions and methods that compute a finding's identity.
// Matched on the name plus a *findings.Finding in the signature, so cache-key and
// content-hash helpers that share the word are not swept up.
func declaredFingerprintFuncs(t *testing.T, path string) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var out []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || !strings.Contains(fn.Name.Name, "Fingerprint") {
			continue
		}
		if takesOrIsAFinding(fn) {
			out = append(out, fn.Name.Name)
		}
	}
	return out
}

func takesOrIsAFinding(fn *ast.FuncDecl) bool {
	isFinding := func(e ast.Expr) bool {
		star, ok := e.(*ast.StarExpr)
		if !ok {
			return false
		}
		sel, ok := star.X.(*ast.SelectorExpr)
		if ok {
			return sel.Sel.Name == "Finding"
		}
		id, ok := star.X.(*ast.Ident)
		return ok && id.Name == "Finding"
	}
	if fn.Recv != nil {
		for _, f := range fn.Recv.List {
			if isFinding(f.Type) {
				return true
			}
		}
	}
	for _, f := range fn.Type.Params.List {
		if isFinding(f.Type) {
			return true
		}
	}
	return false
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find the repository root")
		}
		dir = parent
	}
}
