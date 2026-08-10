package engine

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

// Demand analysis decides which concepts the binding layer bothers to label. A concept it
// fails to collect is a binding that is pruned, which is a finding that never appears — and
// nothing reports it, because a pruned scan and a clean scan look the same.
//
// The way that happens is a new rule-syntax variant: someone adds an exception kind, the
// type switch below has no case for it, and it falls through collecting nothing. These tests
// read both sides out of the source and compare them, so adding the variant fails here
// instead of quietly narrowing what gets scanned.
func TestEveryExceptionKindIsHandledByDemandAnalysis(t *testing.T) {
	declared := typesImplementing(t, "isException")
	if len(declared) < 5 {
		t.Fatalf("found only %d exception kinds; the marker-method scan is broken, not the code", len(declared))
	}
	handled := caseTypesIn(t, demandSourcePath(t), "addException")
	assertHandlesAll(t, "parser.Exception", declared, handled)
}

// The Expr side is narrower on purpose: only the variants that can name a concept have to be
// collected. The list is spelled out so that adding one is a decision, not an omission —
// a new concept-bearing expression fails here until it is either handled or listed as
// carrying no concept.
func TestConceptBearingExprKindsAreHandledByDemandAnalysis(t *testing.T) {
	// Expression kinds that carry no concept, so demand analysis correctly ignores them.
	// Adding to this list is the explicit way to say "this one cannot name a concept".
	noConcept := map[string]bool{
		"Cmp": true, "Has": true, "Lacks": true, "Matches": true, "InSameFunction": true,
		"True": true, "False": true, "Exists": true, "CountCmp": true, "Reaches": true,
		"SameValue": true, "Dominates": true, "PostDominates": true, "PathCovered": true,
		"ArgIsLiteral": true, "ArgMatches": true, "PropCmp": true, "RegionCmp": true,
		// NotIn compares a resolved scalar against literal values, and a bare Ref is an
		// existence test on a bound variable (engine/match.go:213, :228). Neither names a
		// concept — contrast Is, whose Concept field does.
		"NotIn": true, "Ref": true,
	}
	declared := typesImplementing(t, "isExpr")
	if len(declared) < 5 {
		t.Fatalf("found only %d expr kinds; the marker-method scan is broken, not the code", len(declared))
	}
	handled := caseTypesIn(t, demandSourcePath(t), "addExpr")
	var missing []string
	for _, name := range declared {
		if handled[name] || noConcept[name] {
			continue
		}
		missing = append(missing, name)
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("parser.Expr kinds neither handled by demand analysis nor listed as carrying no "+
			"concept:\n  %s\n\nIf one of these can name a concept, add a case to addExpr — a missed "+
			"concept prunes a binding and silently drops findings. If it cannot, add it to noConcept "+
			"with that as the reason.", strings.Join(missing, "\n  "))
	}
}

func assertHandlesAll(t *testing.T, iface string, declared []string, handled map[string]bool) {
	t.Helper()
	var missing []string
	for _, name := range declared {
		if !handled[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("%s kinds not handled by demand analysis:\n  %s\n\nEach one falls through "+
			"collecting no concept, which prunes bindings and silently drops findings.",
			iface, strings.Join(missing, "\n  "))
	}
}

// typesImplementing returns the parser types carrying the given marker method, which is how
// that package closes its sum types.
func typesImplementing(t *testing.T, marker string) []string {
	t.Helper()
	var out []string
	dir := filepath.Join(repoRoot(t), "internal", "parser")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != marker || fn.Recv == nil || len(fn.Recv.List) == 0 {
				continue
			}
			if name := receiverTypeName(fn.Recv.List[0].Type); name != "" {
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// caseTypesIn returns the parser types named in the type-switch cases of the given function.
func caseTypesIn(t *testing.T, path, fnName string) map[string]bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	out := map[string]bool{}
	inspect := func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSwitchStmt)
		if !ok {
			return true
		}
		for _, stmt := range ts.Body.List {
			clause, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			for _, expr := range clause.List {
				if sel, ok := expr.(*ast.SelectorExpr); ok {
					out[sel.Sel.Name] = true
				}
			}
		}
		return true
	}
	ast.Inspect(file, func(n ast.Node) bool {
		// Both switches live inside closures assigned in BindingConcepts, so match on the
		// variable the closure is bound to rather than on a top-level func name.
		switch x := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range x.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || id.Name != fnName || i >= len(x.Rhs) {
					continue
				}
				ast.Inspect(x.Rhs[i], inspect)
			}
		}
		return true
	})
	if len(out) == 0 {
		t.Fatalf("no type-switch cases found for %s; this guard is not reading the code it claims to", fnName)
	}
	return out
}

func receiverTypeName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.StarExpr:
		return receiverTypeName(x.X)
	}
	return ""
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

func demandSourcePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "internal", "engine", "demand.go")
}
