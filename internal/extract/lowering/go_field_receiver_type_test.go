package lowering

import (
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// A Go struct field's DECLARED type is the dispatch fact for a method called on it. The
// client-wrapper idiom — `type APIClient struct { http *httpClient }` with the method body
// calling `s.http.get(...)` — hands the wrapper's return to its caller through exactly one
// edge: the resolved callee's Return flowing to the call site. Without a route that reads
// the field's declaration, resolution falls back to the unique-method-name guess, which a
// name like `get` loses in any program large enough to wrap its HTTP client, and the
// wrapper chain dead-ends at the callee's Return: every `s.http.get` caller looks untainted
// by whatever the wrapper fetched.
func TestGoFieldReceiverMethodResolvesThroughDeclaredFieldType(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "notary",
		File: "api_client.go",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "httpClient", Loc: "http_client.go:1", Body: []nir.Stmt{
				nir.FuncDef{Name: "do", Recv: "httpClient", RecvName: "s", Params: []string{"request"},
					Body: []nir.Stmt{nir.Return{Value: nir.Call{
						Callee: nir.Attr{Base: nir.Attr{Base: nir.Name{ID: "s", Loc: "http_client.go:3"}, Attr: "client", Path: "s.client"}, Attr: "Do", Path: "s.client.Do", Loc: "http_client.go:3"},
						Path:   "s.client.Do", Method: "Do", Loc: "http_client.go:3",
					}}}, Loc: "http_client.go:2"},
				nir.FuncDef{Name: "get", Recv: "httpClient", RecvName: "s", Params: []string{"endpoint"},
					Body: []nir.Stmt{nir.Return{Value: nir.Call{
						Callee: nir.Attr{Base: nir.Name{ID: "s", Loc: "http_client.go:7"}, Attr: "do", Path: "s.do", Loc: "http_client.go:7"},
						Args:   []nir.Expr{nir.Name{ID: "endpoint", Loc: "http_client.go:7"}},
						Path:   "s.do", Method: "do", Loc: "http_client.go:7",
					}}}, Loc: "http_client.go:6"},
			}},
			// the struct declaration: the field's type is written here and nowhere else
			nir.ClassDef{Name: "APIClient", Loc: "api_client.go:1", Body: []nir.Stmt{
				nir.Assign{Targets: []string{"http"}, Value: nir.Const{Loc: "api_client.go:2"}, Type: "httpClient", Decl: true, Loc: "api_client.go:2"},
			}},
			nir.FuncDef{Name: "submissionLogs", Recv: "APIClient", RecvName: "s", Params: []string{"id"}, Loc: "api_client.go:4", Body: []nir.Stmt{
				nir.Assign{Targets: []string{"metadataResp", "err"}, Loc: "api_client.go:5", Value: nir.Call{
					Callee: nir.Attr{Base: nir.Attr{Base: nir.Name{ID: "s", Loc: "api_client.go:5"}, Attr: "http", Path: "s.http"}, Attr: "get", Path: "s.http.get", Loc: "api_client.go:5"},
					Args:   []nir.Expr{nir.Name{ID: "id", Loc: "api_client.go:5"}},
					Path:   "s.http.get", Method: "get", Loc: "api_client.go:5",
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	wrapperRet := findNodeID(t, g, "code.Return", "func", "get")
	call := findNodeID(t, g, "code.Call", "callee_path", "s.http.get")
	edges, err := g.OutEdges(wrapperRet, "FLOWS")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range edges {
		if e.Dst == call {
			return // the wrapper's return reached its caller: the chain is whole
		}
	}
	t.Fatalf("httpClient.get's return has no FLOWS edge to the s.http.get call site (edges: %v)", edges)
}
