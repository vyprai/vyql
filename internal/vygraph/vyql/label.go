package vyql

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vyprai/vyql/internal/vygraph/graph"
)

// ApplyAdapters evaluates every binding in the knowledge base against the store
// and attaches concept labels to matching nodes. Confidence is the adapter's
// fidelity cap (syntactic caps at medium, resolved at high) and provenance
// carries the manifest's trust tier with build kind labeled.
//
// 1b matcher semantics (structural only — mechanism, D10-safe): code.path("a.b")
// matches nodes whose resolved path is a.b, has it as a dotted-segment prefix
// (a.b.c), or ends with it as a dotted-segment suffix (x.a.b). Segment
// boundaries are load-bearing: the argument never matches inside a segment.
// Where filters evaluate against the matched node's typed fields; a binding
// whose filter fails labels nothing.
func ApplyAdapters(kb *KB, g *graph.Store) error {
	for _, a := range kb.Adapters() {
		conf := ladderFloat(FidelityCap(a.Fidelity))
		for _, b := range a.Bindings {
			call, ok := b.Matcher.(*Call)
			if !ok {
				return fmt.Errorf("adapter %s: matcher is not a call", a.Tech)
			}
			nodes, err := matchNodes(g, call)
			if err != nil {
				return fmt.Errorf("adapter %s: %w", a.Tech, err)
			}
			for _, n := range nodes {
				if b.Where != nil {
					ok, err := evalWhere(g, b.Where, n)
					if err != nil {
						return fmt.Errorf("adapter %s: where: %w", a.Tech, err)
					}
					if !ok {
						continue
					}
				}
				if err := g.AddLabel(graph.Label{
					Target:     n.ID,
					Concept:    b.Concept,
					Confidence: conf,
					Prov: graph.Provenance{
						Producer: "binding:" + a.Tech,
						Build:    graph.BuildLabeled,
						Trust:    kb.Trust,
					},
				}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// pathMatches implements segment-boundary equality, prefix, and suffix.
func pathMatches(path, arg string) bool {
	if path == arg {
		return true
	}
	if strings.HasPrefix(path, arg+".") {
		return true
	}
	if strings.HasSuffix(path, "."+arg) {
		return true
	}
	return false
}

// segTailMatch reports whether a decorator token ends with the glob's segment
// tail: *.route matches app.route, route matches app.route, but rou matches
// nothing — the boundary is a whole segment, never a fragment.
func segTailMatch(token, glob string) bool {
	segs := func(s string) []string { return strings.Split(s, ".") }
	t, gp := segs(token), segs(glob)
	if len(gp) > len(t) {
		return false
	}
	for i := 1; i <= len(gp); i++ {
		g := gp[len(gp)-i]
		if g == "*" {
			continue
		}
		if t[len(t)-i] != g {
			return false
		}
	}
	return true
}

// ladderFloat maps the ordinal ladder onto the 0..1 confidence the graph record
// carries: signal=0, possibility=0.25, low=0.5, medium=0.75, high=1.
func ladderFloat(c Confidence) float64 {
	return float64(c) / float64(ConfHigh)
}

// evalWhere evaluates a boolean where clause against a node's typed fields.
// Field references bind to the matched node regardless of the variable name —
// a 1b binding has exactly one implicit node binding.
func evalWhere(g *graph.Store, e Expr, n graph.Node) (bool, error) {
	switch x := e.(type) {
	case *Call:
		// decorated_by(glob): a parameter entry of the enclosing function carries
		// a raw decorator token matching the glob's segment tail.
		if x.Name == "decorated_by" && len(x.Args) == 1 {
			lit, ok := x.Args[0].(*Literal)
			if !ok || lit.Kind != TokString {
				return false, fmt.Errorf("decorated_by takes a string glob")
			}
			glob := unquote(lit.Text)
			for _, arg := range childArgs(g, n) {
				if arg.Type != "code.ParamEntry" {
					continue
				}
				d, ok := arg.Fields.Get("decorators")
				if !ok || d.Kind != graph.KindList {
					continue
				}
				for _, tok := range d.L {
					if segTailMatch(tok.S, glob) {
						return true, nil
					}
				}
			}
			return false, nil
		}
		return false, fmt.Errorf("unsupported call in where")
	case *Literal:
		if x.Kind != TokBool {
			return false, fmt.Errorf("literal %q is not boolean", x.Text)
		}
		return x.Text == "true", nil
	case *Not:
		v, err := evalWhere(g, x.X, n)
		if err != nil {
			return false, err
		}
		return !v, nil
	case *BinOp:
		switch x.Op {
		case "and":
			l, err := evalWhere(g, x.L, n)
			if err != nil || !l {
				return l, err
			}
			return evalWhere(g, x.R, n)
		case "or":
			l, err := evalWhere(g, x.L, n)
			if err != nil {
				return false, err
			}
			if l {
				return true, nil
			}
			return evalWhere(g, x.R, n)
		}
		l, err := evalOperand(g, x.L, n)
		if err != nil {
			return false, err
		}
		r, err := evalOperand(g, x.R, n)
		if err != nil {
			return false, err
		}
		return compareValues(g, n, x.Op, l, r)
	}
	return false, fmt.Errorf("where clause is not boolean")
}

func evalOperand(g *graph.Store, e Expr, n graph.Node) (graph.Value, error) {
	switch x := e.(type) {
	case *Literal:
		switch x.Kind {
		case TokString:
			return graph.Str(unquote(x.Text)), nil
		case TokNumber:
			var i int64
			if _, err := fmt.Sscanf(x.Text, "%d", &i); err != nil {
				return graph.Value{}, fmt.Errorf("bad number %q", x.Text)
			}
			return graph.Int(i), nil
		case TokBool:
			return graph.Bool(x.Text == "true"), nil
		}
		return graph.Value{}, fmt.Errorf("unsupported literal")
	case *Name:
		// Enum member: compare as its string form.
		return graph.Str(x.Name), nil
	case *FieldRef:
		if len(x.Fields) != 1 {
			return graph.Value{}, fmt.Errorf("nested field chains are not evaluable in 1b")
		}
		v, ok := n.Fields.Get(x.Fields[0])
		if !ok {
			return graph.Value{}, fmt.Errorf("node %s has no field %q", n.ID, x.Fields[0])
		}
		return v, nil
	}
	return graph.Value{}, fmt.Errorf("unsupported where operand")
}

func compareValues(g *graph.Store, n graph.Node, op string, l, r graph.Value) (bool, error) {
	if l.Kind != r.Kind {
		return false, fmt.Errorf("comparing %s with %s", l.Kind, r.Kind)
	}
	switch l.Kind {
	case graph.KindInt:
		return cmpOrd(op, l.I < r.I, l.I == r.I, l.I > r.I), nil
	case graph.KindString, graph.KindEnum:
		if l.Kind == graph.KindEnum && isOrdering(op) {
			ord, err := enumOrder(g, n, l, r)
			if err != nil {
				return false, err
			}
			return cmpOrd(op, ord < 0, ord == 0, ord > 0), nil
		}
		switch op {
		case "contains":
			return strings.Contains(l.S, r.S), nil
		case "starts_with":
			return strings.HasPrefix(l.S, r.S), nil
		case "under":
			return l.S == r.S || strings.HasPrefix(l.S, r.S+"."), nil
		case "matches":
			ok, err := regexp.MatchString(r.S, l.S)
			if err != nil {
				return false, fmt.Errorf("bad pattern %q: %w", r.S, err)
			}
			return ok, nil
		}
		return cmpOrd(op, l.S < r.S, l.S == r.S, l.S > r.S), nil
	case graph.KindBool:
		if op == "==" {
			return l.B == r.B, nil
		}
		if op == "!=" {
			return l.B != r.B, nil
		}
		return false, fmt.Errorf("booleans support == and != only")
	}
	return false, fmt.Errorf("unsupported comparison of %s", l.Kind)
}

func isOrdering(op string) bool {
	return op == "<" || op == "<=" || op == ">" || op == ">="
}

// enumOrder resolves the ordinal comparison of two enum members through the
// node's schema, where the member order is declared.
func enumOrder(g *graph.Store, n graph.Node, l, r graph.Value) (int, error) {
	ts, ok := g.SchemaOf(n.Type)
	if !ok {
		return 0, fmt.Errorf("node type %q has no schema for enum ordering", n.Type)
	}
	idx := map[string]int{}
	for _, f := range ts.Fields {
		if f.Kind == graph.KindEnum {
			for i, m := range f.Enum {
				idx[m] = i
			}
		}
	}
	li, ok := idx[l.S]
	if !ok {
		return 0, fmt.Errorf("%q is not a member of the enum", l.S)
	}
	ri, ok := idx[r.S]
	if !ok {
		return 0, fmt.Errorf("%q is not a member of the enum", r.S)
	}
	switch {
	case li < ri:
		return -1, nil
	case li > ri:
		return 1, nil
	}
	return 0, nil
}

func cmpOrd(op string, lt, eq, gt bool) bool {
	switch op {
	case "==":
		return eq
	case "!=":
		return !eq
	case "<":
		return lt
	case "<=":
		return lt || eq
	case ">":
		return gt
	case ">=":
		return gt || eq
	}
	return false
}
