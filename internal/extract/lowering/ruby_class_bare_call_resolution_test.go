package lowering

import (
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/usg"
)

// A spec overrides one method of a library class the way RSpec spells it — an anonymous
// subclass built in a block on the right side of an assignment:
//
//	files = Class.new(Rack::Files) do
//	  def filesize(_); 10000 end
//	end.new(DOCROOT)
//
// The block now lowers beside the statement that holds the call (a value-position block used
// to have no body in the graph at all), and its `def filesize` registers as a top-level
// function: Ruby keys every file to the one module "", so the stub lands in the same flat
// namespace as the library. A bare call inside the class — `filesize path` in Files#serving —
// then resolved to the stub, because the module-level lookup won over the class's own method,
// and the value the class computes for itself never reached its own body: the stub returns a
// constant. In Ruby a bare call dispatches on self, so the enclosing class's own method is
// what runs; the top-level def is Object's last-resort private and may not capture it.
func TestRubyBareCallInsideAClassResolvesToItsOwnMethodOverATopLevelDef(t *testing.T) {
	prog := nir.Program{SelfName: "self", Modules: []nir.Module{{
		Key:  "",
		File: "lib/app/files.rb",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "Files", Loc: "lib/app/files.rb:2", Body: []nir.Stmt{
				nir.FuncDef{Name: "filesize", Loc: "lib/app/files.rb:3", Params: []string{"path"}, Body: []nir.Stmt{
					nir.Return{Value: nir.Name{ID: "path", Loc: "lib/app/files.rb:3"}},
				}},
				nir.FuncDef{Name: "serving", Loc: "lib/app/files.rb:5", Params: []string{"path"}, Body: []nir.Stmt{
					nir.Assign{Targets: []string{"size"}, Value: nir.Call{
						Callee: nir.Name{ID: "filesize", Loc: "lib/app/files.rb:6"},
						Args:   []nir.Expr{nir.Name{ID: "path", Loc: "lib/app/files.rb:6"}},
						Path:   "filesize", Method: "filesize", Loc: "lib/app/files.rb:6",
					}},
					// a subscript write: headers["content-range"] = "bytes */#{size}"
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Attr{Base: nir.Name{ID: "headers", Loc: "lib/app/files.rb:7"}, Attr: "[]", Path: "headers[]", Loc: "lib/app/files.rb:7"},
						Args:   []nir.Expr{nir.Format{Parts: []nir.Expr{nir.Name{ID: "size", Loc: "lib/app/files.rb:7"}}, Loc: "lib/app/files.rb:7"}},
						Path:   "headers[]", Method: "", Loc: "lib/app/files.rb:7",
					}},
				}},
			}},
		},
	}, {
		// declared after the class, so it is the module-level `filesize` that last-wins
		Key:  "",
		File: "test/spec_files.rb",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "filesize", Loc: "test/spec_files.rb:9", Params: []string{"_"}, Body: []nir.Stmt{
				nir.Return{Value: nir.Const{Loc: "test/spec_files.rb:9", Value: "10000"}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	src := inheritedParamNode(t, g, "Files", "serving", "path")
	writeArg := findNodeID(t, g, "code.Arg", "loc", "lib/app/files.rb:7")
	stubParam := findNodeID(t, g, "code.Param", "name", "_")
	reachable, err := usg.BFS(g, src, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[writeArg] {
		t.Fatalf("the class's own filesize is what its bare call runs; the value it computes " +
			"must reach the write the class makes with it")
	}
	if reachable[stubParam] {
		t.Fatalf("a spec's top-level override captured the class's bare call to its own method")
	}
}
