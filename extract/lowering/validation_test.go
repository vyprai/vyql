package lowering

import (
	"testing"

	"github.com/vyprai/vyql/extract/nir"
	"github.com/vyprai/vyql/usg"
)

func validationProgram(evidence nir.Expr, target string, before bool) nir.Program {
	validation := nir.Validation{Target: target, Evidence: evidence, Kind: "character_rejection", Loc: "app.py:3"}
	sink := nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: "sink"}, Args: []nir.Expr{nir.Name{ID: "rendered"}},
		Path: "sink", Method: "sink", Loc: "app.py:4",
	}}
	tail := []nir.Stmt{validation, sink}
	if !before {
		tail = []nir.Stmt{sink, validation}
	}
	body := []nir.Stmt{nir.Assign{Targets: []string{"rendered"}, Loc: "app.py:2", Value: nir.Format{
		Parts: []nir.Expr{nir.Name{ID: "value", Loc: "app.py:2"}}, Loc: "app.py:2",
	}}}
	body = append(body, tail...)
	return nir.Program{Modules: []nir.Module{{Key: "app", File: "app.py", Body: []nir.Stmt{
		nir.FuncDef{Name: "page", Params: []string{"value", "other", "blocked"}, Loc: "app.py:1", Body: body},
	}}}}
}

func validationCalls(t *testing.T, g usg.Store) []string {
	t.Helper()
	ids, err := g.NodesOfType("code.Call")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, id := range ids {
		node, ok, err := g.GetNode(id)
		if err != nil {
			t.Fatal(err)
		}
		if ok && node.Prop("callee_path") == "analysis.validation.character_rejection" {
			out = append(out, id)
		}
	}
	return out
}

func TestCharacterValidationWrapsOnlyCurrentDerivedValues(t *testing.T) {
	tests := []struct {
		name                   string
		evidence               nir.Expr
		target                 string
		validationBeforeSink   bool
		wantWrapperOnValuePath bool
	}{
		{"literal list", nir.Seq{Parts: []nir.Expr{nir.Const{Value: "<"}, nir.Const{Value: ">"}, nir.Const{Value: "'"}, nir.Const{Value: "\""}}}, "value", true, true},
		{"dynamic set", nir.Name{ID: "blocked"}, "value", true, false},
		{"unrelated target", nir.Seq{Parts: []nir.Expr{nir.Const{Value: "<"}}}, "other", true, false},
		{"post sink", nir.Seq{Parts: []nir.Expr{nir.Const{Value: "<"}, nir.Const{Value: ">"}}}, "value", false, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			g, err := Lower(validationProgram(test.evidence, test.target, test.validationBeforeSink), true)
			if err != nil {
				t.Fatal(err)
			}
			value := findNodeID(t, g, "code.Param", "name", "value")
			sink := findNodeID(t, g, "code.Call", "callee_path", "sink")
			fromValue, err := usg.BFS(g, value, "FLOWS", 64)
			if err != nil {
				t.Fatal(err)
			}
			wrapperOnValuePath := false
			wrapperReachesSink := false
			for _, wrapper := range validationCalls(t, g) {
				if !fromValue[wrapper] {
					continue
				}
				wrapperOnValuePath = true
				fromWrapper, err := usg.BFS(g, wrapper, "FLOWS", 64)
				if err != nil {
					t.Fatal(err)
				}
				wrapperReachesSink = wrapperReachesSink || fromWrapper[sink]
			}
			if wrapperOnValuePath != test.wantWrapperOnValuePath {
				t.Fatalf("wrapperOnValuePath=%v, want %v", wrapperOnValuePath, test.wantWrapperOnValuePath)
			}
			if test.validationBeforeSink && test.wantWrapperOnValuePath && !wrapperReachesSink {
				t.Fatal("pre-sink validation wrapper did not reach sink")
			}
			if !test.validationBeforeSink && (!fromValue[sink] || wrapperReachesSink) {
				t.Fatalf("post-sink ordering lost: sourceToSink=%v wrapperToSink=%v", fromValue[sink], wrapperReachesSink)
			}
		})
	}
}
