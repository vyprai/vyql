package lowering

import (
	"testing"

	"github.com/vyprai/vyql/extract/nir"
	"github.com/vyprai/vyql/usg"
)

func maybeNodeID(t *testing.T, g usg.Store, typ string, props ...string) string {
	t.Helper()
	ids, err := g.NodesOfType(typ)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		node, ok, err := g.GetNode(id)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			continue
		}
		match := true
		for i := 0; i < len(props); i += 2 {
			if node.Prop(props[i]) != props[i+1] {
				match = false
				break
			}
		}
		if match {
			return id
		}
	}
	return ""
}

func TestReachabilityPrunesOnlyDefiniteExits(t *testing.T) {
	tests := []struct {
		name          string
		prefix        []nir.Stmt
		wantReachable bool
	}{
		{"return", []nir.Stmt{nir.Return{Value: nir.Const{Value: "safe", Loc: "app.py:2"}}}, false},
		{"raise", []nir.Stmt{nir.Terminate{Kind: "raise", Loc: "app.py:2"}}, false},
		{"true length guard", []nir.Stmt{nir.If{
			Cond: nir.BinOp{Op: ">=", Left: nir.Call{Callee: nir.Name{ID: "len"}, Args: []nir.Expr{nir.Name{ID: "source"}}, Path: "len", Method: "len"}, Right: nir.Const{Value: "0"}},
			Then: []nir.Stmt{nir.Return{}},
		}}, false},
		{"unknown numeric guard", []nir.Stmt{nir.If{
			Cond: nir.BinOp{Op: ">=", Left: nir.Name{ID: "source"}, Right: nir.Const{Value: "0"}},
			Then: []nir.Stmt{nir.Return{}},
		}}, true},
		{"shadowed len", []nir.Stmt{
			nir.Assign{Targets: []string{"len"}, Value: nir.Name{ID: "custom_len"}},
			nir.If{Cond: nir.BinOp{Op: ">=", Left: nir.Call{Callee: nir.Name{ID: "len"}, Args: []nir.Expr{nir.Name{ID: "source"}}, Path: "len", Method: "len"}, Right: nir.Const{Value: "0"}}, Then: []nir.Stmt{nir.Return{}}},
		}, true},
		{"nested return", []nir.Stmt{nir.FuncDef{Name: "inner", Body: []nir.Stmt{nir.Return{}}}}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := append([]nir.Stmt(nil), test.prefix...)
			body = append(body, nir.ExprStmt{Value: nir.Call{
				Callee: nir.Name{ID: "sink"}, Args: []nir.Expr{nir.Name{ID: "source"}},
				Path: "sink", Method: "sink", Loc: "app.py:9",
			}})
			prog := nir.Program{Modules: []nir.Module{{Key: "app", File: "app.py", Body: []nir.Stmt{
				nir.FuncDef{Name: "page", Params: []string{"source"}, Loc: "app.py:1", Body: body},
			}}}}
			g, err := Lower(prog, true)
			if err != nil {
				t.Fatal(err)
			}
			source := findNodeID(t, g, "code.Param", "name", "source")
			sink := maybeNodeID(t, g, "code.Call", "callee_path", "sink")
			reachable := false
			if sink != "" {
				seen, err := usg.BFS(g, source, "FLOWS", 32)
				if err != nil {
					t.Fatal(err)
				}
				reachable = seen[sink]
			}
			if reachable != test.wantReachable {
				t.Fatalf("reachable=%v, want %v", reachable, test.wantReachable)
			}
		})
	}
}
