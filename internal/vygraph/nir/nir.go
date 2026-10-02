// Package nir declares the closed low-level code schema — the Normalized IR the
// per-language frontends lower source into. NIR is mechanism:
// structure and dataflow only, no domain normalization, no security, no framework
// knowledge. The Expr set is a closed, governed ISA surface: lowering and every
// solver switch on it exhaustively, and it is extended centrally and rarely — a
// construct that does not fit is stamped approx_lowered or escalated as a
// mechanism gap, never silently mis-lowered.
package nir

import (
	"fmt"

	"github.com/vyprai/vyql/internal/vygraph/graph"
)

// ExprMembers is the closed set. This list is the ISA; adding a member is an
// engine change with design review, never a frontend's private business.
var ExprMembers = []string{
	"code.Name", "code.Const",
	"code.Attr", "code.Index", "code.Call",
	"code.Format", "code.Seq", "code.Pair", "code.Lambda",
	"code.If", "code.Loop", "code.Switch", "code.Try",
	"code.Transparent", "code.BinOp", "code.Unary", "code.Ternary",
	"code.FuncDef", "code.ParamEntry",
}

// common is the inline field block every code node carries: its location for
// findings, and the Region/Order pair the cfg solver's dominance predicates read
// . Stored inline because on a million-node graph that is the
// dominant memory saving; approx_lowered is the fidelity marker that caps
// confidence when a witness crosses an approximately-lowered region.
func common() []graph.FieldSpec {
	return []graph.FieldSpec{
		{Name: "file", Kind: graph.KindString},
		{Name: "line", Kind: graph.KindInt},
		{Name: "col", Kind: graph.KindInt},
		{Name: "region", Kind: graph.KindString},
		{Name: "order", Kind: graph.KindInt},
		{Name: "approx_lowered", Kind: graph.KindBool},
	}
}

func str(name string) graph.FieldSpec { return graph.FieldSpec{Name: name, Kind: graph.KindString} }

// pathFields are the two typed paths on Attr/Index/Call: the raw syntactic local
// name (never resolution-dependent, matched by syntactic-fidelity bindings) and
// the import-resolved qualified name (matched by resolved bindings, may reach
// high confidence). The old single ambiguous Path conflated the two and is
// retired.
func pathFields() []graph.FieldSpec {
	return []graph.FieldSpec{str("path"), str("qualified_path")}
}

// Register declares the whole closed set plus the three structural edge types
// into a schema registry: FLOWS (the intraprocedural value substrate), CALLS
// (the resolved call graph), and child (parse-tree containment).
func Register(s *graph.Schemas) error {
	members := map[string][]graph.FieldSpec{
		"code.Name":        {str("local")},
		"code.Const":       {str("value")},
		"code.Attr":        append(pathFields(), str("attr")),
		"code.Index":       append(pathFields(), str("key_path")),
		"code.Call":        append(pathFields(), str("callee"), str("method"), graph.FieldSpec{Name: "argc", Kind: graph.KindInt}, graph.FieldSpec{Name: "is_ctor", Kind: graph.KindBool}, graph.FieldSpec{Name: "effects", Kind: graph.KindBool}),
		"code.Format":      {str("text")},
		"code.Seq":         {str("key_path")},
		"code.Pair":        {str("key")},
		"code.Lambda":      {{Name: "param_count", Kind: graph.KindInt}},
		"code.If":          {},
		"code.Loop":        {},
		"code.Switch":      {},
		"code.Try":         {},
		"code.Transparent": {str("kind")}, // await / spread / unpack — taint passes through
		"code.BinOp":       {str("op")},
		"code.Unary":       {str("op")},
		"code.Ternary":     {},
		"code.FuncDef":     {str("name"), str("qualified_name"), {Name: "param_count", Kind: graph.KindInt}},
		// ParamEntry is the generic parameter fact: name, the raw decorator
		// tokens on the enclosing function, and its region/order. The
		// framework-specific interpretation is a VyQL framework model, not here.
		"code.ParamEntry": {str("name"), str("scope"), {Name: "decorators", Kind: graph.KindList, Elem: graph.KindString}},
	}
	// A node's identity is its location: two producers lowering the same source
	// construct resolve to one record.
	key := []string{"file", "line", "col"}

	for _, m := range ExprMembers {
		fields := append(common(), members[m]...)
		if err := s.Register(&graph.TypeSchema{Type: m, Layer: graph.LayerLow, Fields: fields, Key: key}); err != nil {
			return fmt.Errorf("nir: %w", err)
		}
	}
	for _, e := range []string{"FLOWS", "CALLS", "child"} {
		if err := s.Register(&graph.TypeSchema{Type: e, Layer: graph.LayerLow, Fields: nil, Key: nil}); err != nil {
			return fmt.Errorf("nir: %w", err)
		}
	}
	return nil
}

// Stamp writes the common inline block onto a field record: the source location,
// the structured region path and program order (the cfg substrate), and the
// approximate-lowering marker.
func Stamp(f *graph.Fields, file string, line, col int, region string, order int, approx bool) {
	f.Set("file", graph.Str(file))
	f.Set("line", graph.Int(int64(line)))
	f.Set("col", graph.Int(int64(col)))
	f.Set("region", graph.Str(region))
	f.Set("order", graph.Int(int64(order)))
	f.Set("approx_lowered", graph.Bool(approx))
}
