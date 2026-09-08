package lowering

import (
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/usg"
)

// structFieldProgram is a setter that stores its second argument into a field of the *Rule it
// is handed, and a method on Rule that reads that field back and passes it on. Nothing calls
// either function, and the method is declared FIRST, so the read is lowered before the write
// that fills the field exists. The two ends meet through the declared field or not at all.
func structFieldProgram(file string) nir.Program {
	return nir.Program{Modules: []nir.Module{{
		Key:  "fw",
		File: file,
		Body: []nir.Stmt{
			nir.ClassDef{Name: "Rule", Loc: file + ":1"},
			nir.FuncDef{
				Name: "Apply", Recv: "Rule", RecvName: "r", Loc: file + ":3",
				Body: []nir.Stmt{nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "run", Loc: file + ":4"},
					Path:   "run", Method: "run", Loc: file + ":4",
					Args: []nir.Expr{nir.Attr{Base: nir.Name{ID: "r", Loc: file + ":4"}, Attr: "Spec", Path: "r.Spec", Loc: file + ":4"}},
				}}},
			},
			nir.FuncDef{
				Name: "setSpec", Params: []string{"r", "spec"},
				ParamTypes: map[string]string{"r": "Rule", "spec": "string"}, Loc: file + ":7",
				Body: []nir.Stmt{nir.Assign{
					Targets: []string{"r.Spec"},
					Value:   nir.Name{ID: "spec", Loc: file + ":8"},
					Loc:     file + ":8",
				}},
			},
		},
	}}}
}

// The store and the read share no object and no call, so the declared field is the only thing
// that can carry the value between them — and the read being lowered first must not lose it.
func TestAStructFieldCarriesTaintBetweenFunctionsThatShareNoObject(t *testing.T) {
	g, err := Lower(structFieldProgram("fw.go"), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	reachable, err := usg.BFS(g, findNodeID(t, g, "code.Param", "name", "spec"), "FLOWS", 20)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[findNodeID(t, g, "code.Arg", "loc", "fw.go:4")] {
		t.Fatal("the value stored into r.Spec did not reach the method that reads it")
	}
}

// The join is keyed on a Go struct's declared field. Every other frontend models a field write
// as a method-less path call the object-sensitive slots already handle, so a module that is not
// Go keeps exactly the flows it had.
func TestAStructFieldJoinIsNotAppliedOutsideGo(t *testing.T) {
	g, err := Lower(structFieldProgram("fw.py"), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	reachable, err := usg.BFS(g, findNodeID(t, g, "code.Param", "name", "spec"), "FLOWS", 20)
	if err != nil {
		t.Fatal(err)
	}
	if reachable[findNodeID(t, g, "code.Arg", "loc", "fw.py:4")] {
		t.Fatal("a non-Go module picked up the type-keyed field join")
	}
}
