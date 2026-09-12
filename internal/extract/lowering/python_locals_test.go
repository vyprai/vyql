package lowering

import (
	"slices"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/usg"
)

// localsSnapshotProg is one Python function holding a request parameter, a binding derived
// from it, and a `sink(...)` call whose argument the caller supplies. `request` is the flow's
// origin (a parameter is where an unsourced taint starts in these tests) and the sink
// argument at sinkLoc is where it has to arrive.
func localsSnapshotProg(body []nir.Stmt, file string) nir.Program {
	return nir.Program{Modules: []nir.Module{{
		Key:  file,
		File: file,
		Body: []nir.Stmt{
			nir.FuncDef{Name: "handler", Loc: file + ":1", Params: []string{"request"}, Body: body},
		},
	}}}
}

func localsSnapshotParam(t *testing.T, g usg.Store, file string) string {
	t.Helper()
	return findNodeID(t, g, "code.Param", "name", "request", "loc", file+":1")
}

// localsSnapshotReaches reports whether the request parameter reaches the argument of the
// sink call written at sinkLoc.
func localsSnapshotReaches(t *testing.T, g usg.Store, file, sinkLoc string) bool {
	t.Helper()
	reach, err := usg.BFS(g, localsSnapshotParam(t, g, file), "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	return reach[findNodeID(t, g, "code.Arg", "loc", sinkLoc)]
}

// localsSnapshotCall is the no-argument builtin call, at the loc it is written at.
func localsSnapshotCall(loc string) nir.Expr {
	return nir.Call{Callee: nir.Name{ID: "locals", Loc: loc}, Path: "locals", Method: "locals", Loc: loc}
}

// A template key the snapshot does not hold would raise KeyError at runtime; the lowerer
// cannot read a named slot for it, so it falls back to the whole snapshot rather than read
// nothing. Sound over-approximation, never silence.
func TestLocalsSnapshotUnknownTemplateKeyFallsBackToWholeScope(t *testing.T) {
	const file = "app.py"
	prog := localsSnapshotProg([]nir.Stmt{
		nir.Assign{Targets: []string{"name"}, Value: nir.Call{
			Callee: nir.Attr{Base: nir.Name{ID: "request", Loc: file + ":2"}, Attr: "get", Path: "request.get", Loc: file + ":2"},
			Args:   []nir.Expr{nir.Const{Value: "\"pagename\"", Loc: file + ":2"}},
			Path:   "request.get", Method: "get", Loc: file + ":2",
		}},
		nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: "sink", Loc: file + ":3"},
			Args: []nir.Expr{nir.Format{
				Parts: []nir.Expr{nir.Const{Value: "\"%(missing)s\"", Loc: file + ":3"}, localsSnapshotCall(file + ":3")},
				Loc:   file + ":3",
			}},
			Path: "sink", Method: "sink", Loc: file + ":3",
		}},
	}, file)
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	if !localsSnapshotReaches(t, g, file, file+":3") {
		t.Fatalf("a template key the snapshot does not hold dropped the whole-scope fallback")
	}
}

// The relation is Python's builtin. The same call spelling in another language's module names
// whatever that language's `locals` is, and the scope is not tied to its result.
func TestLocalsSnapshotIsPythonOnly(t *testing.T) {
	const file = "app.php"
	prog := localsSnapshotProg([]nir.Stmt{
		nir.Assign{Targets: []string{"name"}, Value: nir.Call{
			Callee: nir.Attr{Base: nir.Name{ID: "$request", Loc: file + ":2"}, Attr: "get", Path: "$request.get", Loc: file + ":2"},
			Args:   []nir.Expr{nir.Const{Value: "\"pagename\"", Loc: file + ":2"}},
			Path:   "$request.get", Method: "get", Loc: file + ":2",
		}},
		nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: "sink", Loc: file + ":3"},
			Args: []nir.Expr{nir.Format{
				Parts: []nir.Expr{nir.Const{Value: "\"%(name)s\"", Loc: file + ":3"}, localsSnapshotCall(file + ":3")},
				Loc:   file + ":3",
			}},
			Path: "sink", Method: "sink", Loc: file + ":3",
		}},
	}, file)
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	if localsSnapshotReaches(t, g, file, file+":3") {
		t.Fatalf("a non-Python locals() call was read as the Python scope snapshot")
	}
}

// A snapshot held in a variable keeps its slots, so a later read through the alias is still
// element-sensitive: the named binding is what arrives, not the whole scope beside it.
func TestLocalsSnapshotSlotsSurviveAnAlias(t *testing.T) {
	const file = "app.py"
	prog := localsSnapshotProg([]nir.Stmt{
		nir.Assign{Targets: []string{"name"}, Value: nir.Call{
			Callee: nir.Attr{Base: nir.Name{ID: "request", Loc: file + ":2"}, Attr: "get", Path: "request.get", Loc: file + ":2"},
			Args:   []nir.Expr{nir.Const{Value: "\"pagename\"", Loc: file + ":2"}},
			Path:   "request.get", Method: "get", Loc: file + ":2",
		}},
		nir.Assign{Targets: []string{"scope"}, Value: localsSnapshotCall(file + ":3")},
		nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: "sink", Loc: file + ":4"},
			Args: []nir.Expr{nir.Index{
				Base: nir.Name{ID: "scope", Loc: file + ":4"},
				Key:  nir.Const{Value: "\"name\"", Loc: file + ":4"},
				Path: "scope", Loc: file + ":4",
			}},
			Path: "sink", Method: "sink", Loc: file + ":4",
		}},
	}, file)
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	if !localsSnapshotReaches(t, g, file, file+":4") {
		t.Fatalf("the named slot of an aliased locals() snapshot lost its taint")
	}
}

// ... and the slot the alias does not name stays out of it.
func TestLocalsSnapshotAliasedReadStaysElementSensitive(t *testing.T) {
	const file = "app.py"
	prog := localsSnapshotProg([]nir.Stmt{
		nir.Assign{Targets: []string{"name"}, Value: nir.Call{
			Callee: nir.Attr{Base: nir.Name{ID: "request", Loc: file + ":2"}, Attr: "get", Path: "request.get", Loc: file + ":2"},
			Args:   []nir.Expr{nir.Const{Value: "\"pagename\"", Loc: file + ":2"}},
			Path:   "request.get", Method: "get", Loc: file + ":2",
		}},
		nir.Assign{Targets: []string{"scope"}, Value: localsSnapshotCall(file + ":3")},
		nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: "sink", Loc: file + ":4"},
			Args: []nir.Expr{nir.Index{
				Base: nir.Name{ID: "scope", Loc: file + ":4"},
				Key:  nir.Const{Value: "\"action\"", Loc: file + ":4"},
				Path: "scope", Loc: file + ":4",
			}},
			Path: "sink", Method: "sink", Loc: file + ":4",
		}},
	}, file)
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	if localsSnapshotReaches(t, g, file, file+":4") {
		t.Fatalf("an aliased read of an absent slot read the binding beside it")
	}
}

// The keys a %-format template names: every conversion and width form, once each in
// first-mention order, with `%%` reading as an escaped percent rather than as a slot.
func TestPyFormatMappingKeys(t *testing.T) {
	template := `<input value="%(name_escaped)s" action=%(action)s> %% %(count)05d %%(not_a_slot)s %(name_escaped)r`
	got := pyFormatMappingKeys(template)
	want := []string{"name_escaped", "action", "count"}
	if !slices.Equal(got, want) {
		t.Fatalf("pyFormatMappingKeys() = %q, want %q", got, want)
	}
}
