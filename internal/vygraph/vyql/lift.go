package vyql

import (
	"fmt"
	"strings"

	"github.com/vyprai/vyql/internal/vygraph/graph"
)

// matchNodes is the shared low-node matcher used by bindings, lifts, and
// framework routes. code.path and code.call match the import-resolved
// qualified_path (a resolved binding cannot mint high confidence off a raw
// name); code.syntacticPath matches the syntactic path; code.func selects
// function definitions.
func matchNodes(g *graph.Store, call *Call) ([]graph.Node, error) {
	argPats := func() ([]string, error) {
		var pats []string
		for _, a := range call.Args {
			lit, ok := a.(*Literal)
			if !ok || lit.Kind != TokString {
				return nil, fmt.Errorf("%s takes string literal patterns", call.Name)
			}
			pats = append(pats, unquote(lit.Text))
		}
		return pats, nil
	}
	matchTyped := func(field string, types ...string) ([]graph.Node, error) {
		pats, err := argPats()
		if err != nil {
			return nil, err
		}
		var out []graph.Node
		for _, typ := range types {
			for _, n := range g.NodesOfType(typ) {
				v, has := n.Fields.Get(field)
				if !has || v.Kind != graph.KindString {
					continue
				}
				if len(pats) == 0 {
					out = append(out, n)
					continue
				}
				for _, p := range pats {
					if pathMatches(v.S, p) {
						out = append(out, n)
						break
					}
				}
			}
		}
		return out, nil
	}
	// A call's receiver base shares the call's start position (the Attr
	// `a.b` under the Call `a.b(...)`). Both carry the path, so matchers and
	// lifts would double-fire per site; the Call is the canonical site.
	dedupeReceivers := func(calls, attrs []graph.Node) []graph.Node {
		if len(calls) == 0 {
			return attrs
		}
		callPos := map[string]bool{}
		for _, c := range calls {
			callPos[posKey(c)] = true
		}
		out := attrs[:0]
		for _, a := range attrs {
			if !callPos[posKey(a)] {
				out = append(out, a)
			}
		}
		return out
	}
	_ = dedupeReceivers

	switch call.Name {
	case "code.func":
		pats, err := argPats()
		if err != nil {
			return nil, err
		}
		var out []graph.Node
		for _, n := range g.NodesOfType("code.FuncDef") {
			if len(pats) == 0 {
				out = append(out, n)
				continue
			}
			name, _ := n.Fields.Get("name")
			for _, p := range pats {
				if pathMatches(name.S, p) {
					out = append(out, n)
					break
				}
			}
		}
		return out, nil
	case "code.call":
		return matchTyped("qualified_path", "code.Call")
	case "code.path":
		calls, _ := matchTyped("qualified_path", "code.Call")
		attrs, _ := matchTyped("qualified_path", "code.Attr")
		idx, _ := matchTyped("qualified_path", "code.Index")
		return append(append(calls, dedupeReceivers(calls, attrs)...), idx...), nil
	case "code.syntacticPath":
		calls, _ := matchTyped("path", "code.Call")
		attrs, _ := matchTyped("path", "code.Attr")
		idx, _ := matchTyped("path", "code.Index")
		return append(append(calls, dedupeReceivers(calls, attrs)...), idx...), nil
	default:
		return nil, fmt.Errorf("unknown matcher %q", call.Name)
	}
}

// routeFact is one framework-computed route: which handler serves which method
// and path. The framework model is knowledge; this is the fact it produces.
type routeFact struct {
	handler, method, path string
}

// frameworkFacts evaluates a framework model's route declarations over the
// graph: each route matches registration calls (code.call on the registration
// surface) and extracts method/path/handler expressions from the call.
func frameworkFacts(g *graph.Store, fw FrameworkDecl) ([]routeFact, error) {
	var facts []routeFact
	for _, rt := range fw.Routes {
		call, ok := rt.On.(*Call)
		if !ok {
			return nil, fmt.Errorf("framework %s: route on must be a matcher call", fw.Name)
		}
		nodes, err := matchNodes(g, call)
		if err != nil {
			return nil, fmt.Errorf("framework %s: %w", fw.Name, err)
		}
		for _, n := range nodes {
			if rt.Where != nil {
				ok, err := evalWhere(g, rt.Where, n)
				if err != nil {
					return nil, err
				}
				if !ok {
					continue
				}
			}
			fact := routeFact{}
			for _, fe := range []struct {
				e    Expr
				dst  *string
				name string
			}{{rt.Method, &fact.method, "method"}, {rt.Path, &fact.path, "path"}, {rt.Handler, &fact.handler, "handler"}} {
				if fe.e == nil {
					continue
				}
				v, err := evalRouteExpr(g, fe.e, n)
				if err != nil {
					return nil, fmt.Errorf("framework %s: route %s: %w", fw.Name, fe.name, err)
				}
				*fe.dst = v.S
			}
			facts = append(facts, fact)
		}
	}
	return facts, nil
}

// evalRouteExpr evaluates a route-field expression over the registration call:
// callee.method reads the call's method field; arg(N) reads its Nth child
// argument (-1 = last); a literal passes through.
func evalRouteExpr(g *graph.Store, e Expr, n graph.Node) (graph.Value, error) {
	switch x := e.(type) {
	case *Literal:
		if x.Kind != TokString {
			return graph.Value{}, fmt.Errorf("route literals are strings")
		}
		return graph.Str(unquote(x.Text)), nil
	case *FieldRef:
		if len(x.Fields) == 1 {
			if v, ok := n.Fields.Get(x.Fields[0]); ok {
				return v, nil
			}
		}
		if x.Var == "callee" && len(x.Fields) == 1 && x.Fields[0] == "method" {
			if v, ok := n.Fields.Get("method"); ok {
				return v, nil
			}
		}
		return graph.Value{}, fmt.Errorf("route field ref %s.%v unresolvable", x.Var, x.Fields)
	case *Call:
		if x.Name == "arg" && len(x.Args) == 1 {
			lit, ok := x.Args[0].(*Literal)
			if !ok || lit.Kind != TokNumber {
				return graph.Value{}, fmt.Errorf("arg takes a number")
			}
			var idx int
			if _, err := fmt.Sscanf(lit.Text, "%d", &idx); err != nil {
				return graph.Value{}, err
			}
			args := childArgs(g, n)
			if len(args) == 0 {
				return graph.Value{}, fmt.Errorf("call has no child arguments")
			}
			if idx < 0 {
				idx += len(args)
			}
			if idx < 0 || idx >= len(args) {
				return graph.Value{}, fmt.Errorf("arg %s out of range", lit.Text)
			}
			arg := args[idx]
			for _, f := range []string{"local", "value", "path"} {
				if v, ok := arg.Fields.Get(f); ok {
					return v, nil
				}
			}
			return graph.Str(arg.ID), nil
		}
	}
	return graph.Value{}, fmt.Errorf("unsupported route expression")
}

// childArgs returns a node's child argument nodes in insertion order.
func childArgs(g *graph.Store, n graph.Node) []graph.Node {
	var out []graph.Node
	for _, e := range g.Out(n.ID, "child") {
		if c, ok := g.Node(e.To); ok {
			out = append(out, c)
		}
	}
	return out
}

// ApplyLifts runs every lift declaration: match low nodes, build high nodes
// with mapped fields, back them to their sources, and merge duplicates by
// identity. Framework lifts build entrypoints from the model's route facts.
func ApplyLifts(kb *KB, g *graph.Store) error {
	facts := map[string][]routeFact{}
	for _, f := range kb.Files {
		for _, fw := range f.Frameworks {
			fr, err := frameworkFacts(g, fw)
			if err != nil {
				return err
			}
			facts[fw.Name] = fr
		}
	}
	for _, f := range kb.Files {
		for _, l := range f.Lifts {
			if l.FromDoc {
				if err := applyDocLift(kb, g, l); err != nil {
					return err
				}
				continue
			}
			if l.Framework != "" {
				if err := applyFrameworkLift(kb, g, l, facts[l.Framework]); err != nil {
					return err
				}
				continue
			}
			call, ok := l.From.(*Call)
			if !ok {
				return fmt.Errorf("lift %s: from must be a matcher call", l.Target)
			}
			nodes, err := matchNodes(g, call)
			if err != nil {
				return fmt.Errorf("lift %s: %w", l.Target, err)
			}
			for _, n := range nodes {
				if l.Where != nil {
					ok, err := evalWhere(g, l.Where, n)
					if err != nil {
						return err
					}
					if !ok {
						continue
					}
				}
				if err := applyLiftOne(kb, g, l, n); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func applyFrameworkLift(kb *KB, g *graph.Store, l LiftDecl, facts []routeFact) error {
	for _, fact := range facts {
		var handler graph.Node
		found := false
		for _, n := range g.NodesOfType("code.FuncDef") {
			if name, ok := n.Fields.Get("name"); ok && name.S == fact.handler {
				handler = n
				found = true
				break
			}
		}
		if !found {
			continue // a registration whose handler is not in the graph: skip, not error
		}
		var fields graph.Fields
		for _, lf := range l.Fields {
			v := graph.Value{}
			switch x := lf.Value.(type) {
			case *FieldRef:
				switch {
				case len(x.Fields) == 1 && x.Fields[0] == "method":
					v = graph.Str(fact.method)
				case len(x.Fields) == 1 && x.Fields[0] == "path":
					v = graph.Str(fact.path)
				case len(x.Fields) == 1 && x.Fields[0] == "handler":
					if hv, ok := handler.Fields.Get("name"); ok {
						v = hv
					}
				default:
					if hv, ok := handler.Fields.Get(strings.Join(x.Fields, ".")); ok {
						v = hv
					}
				}
			case *Literal:
				if x.Kind == TokString {
					v = graph.Str(unquote(x.Text))
				}
			}
			if v.Kind != 0 || v.S != "" || v.I != 0 {
				fields.Set(lf.Name, v)
			}
		}
		for _, copy := range l.Copies {
			if copy == "filters" {
				fields.Set("filters", filtersFromFlows(g, handler))
			}
		}
		if err := upsertHigh(kb, g, l.Target, fields, handler); err != nil {
			return err
		}
	}
	return nil
}

func applyLiftOne(kb *KB, g *graph.Store, l LiftDecl, n graph.Node) error {
	var fields graph.Fields
	for _, lf := range l.Fields {
		v, err := evalLiftExpr(g, lf.Value, n)
		if err != nil {
			return fmt.Errorf("lift %s field %q: %w", l.Target, lf.Name, err)
		}
		fields.Set(lf.Name, coerce(g, l.Target, lf.Name, v))
	}
	for _, copy := range l.Copies {
		switch copy {
		case "filters":
			fields.Set("filters", filtersFromFlows(g, n))
		default:
			return fmt.Errorf("lift %s: unknown copy form %q", l.Target, copy)
		}
	}
	return upsertHigh(kb, g, l.Target, fields, n)
}

// coerce re-mints a string literal toward the target field's declared kind —
// an enum field takes its member as an enum value, so AddNode's membership
// check governs rather than a kind mismatch.
func coerce(g *graph.Store, target, field string, v graph.Value) graph.Value {
	ts, ok := g.SchemaOf(target)
	if !ok || v.Kind != graph.KindString {
		return v
	}
	for _, f := range ts.Fields {
		if f.Name == field && f.Kind == graph.KindEnum {
			return graph.Value{Kind: graph.KindEnum, S: v.S}
		}
	}
	return v
}

// evalLiftExpr evaluates a field-map expression over the matched low node:
// .field reads the node's typed field; callee.method reads a call's method;
// a literal passes through.
func evalLiftExpr(g *graph.Store, e Expr, n graph.Node) (graph.Value, error) {
	switch x := e.(type) {
	case *Literal:
		switch x.Kind {
		case TokString:
			return graph.Str(unquote(x.Text)), nil
		case TokNumber:
			var i int64
			if _, err := fmt.Sscanf(x.Text, "%d", &i); err != nil {
				return graph.Value{}, err
			}
			return graph.Int(i), nil
		case TokBool:
			return graph.Bool(x.Text == "true"), nil
		}
		return graph.Value{}, fmt.Errorf("unsupported literal")
	case *Name:
		// A bare name in a lift field map resolves as its text; coerce re-mints
		// toward the target's declared kind (enum members arrive this way).
		return graph.Str(x.Name), nil
	case *FieldRef:
		if x.Var == "callee" && len(x.Fields) == 1 && x.Fields[0] == "method" {
			if v, ok := n.Fields.Get("method"); ok {
				return v, nil
			}
		}
		if len(x.Fields) == 1 {
			if v, ok := n.Fields.Get(x.Fields[0]); ok {
				return v, nil
			}
			return graph.Value{}, fmt.Errorf("node has no field %q", x.Fields[0])
		}
		return graph.Value{}, fmt.Errorf("nested field chains are not part of this subset")
	}
	return graph.Value{}, fmt.Errorf("unsupported lift expression")
}

// applyDocLift builds high nodes from doc.* origins: select roots by their
// inherited kind, descend the optional at-path ([*] fans over seq elements),
// map fields by walking keyed child edges.
func applyDocLift(kb *KB, g *graph.Store, l LiftDecl) error {
	var roots []graph.Node
	for _, typ := range []string{"doc.Map", "doc.Seq"} {
		for _, n := range g.NodesOfType(typ) {
			if v, ok := n.Fields.Get("path"); ok && v.S == "$" {
				if k, ok := n.Fields.Get("kind"); ok && k.S == l.DocKind {
					roots = append(roots, n)
				}
			}
		}
	}
	var origins []graph.Node
	for _, root := range roots {
		if l.At == "" {
			origins = append(origins, root)
			continue
		}
		origins = append(origins, descend(g, root, l.At)...)
	}
	for _, origin := range origins {
		var fields graph.Fields
		for _, lf := range l.Fields {
			v := docField(g, origin, lf)
			if v.Kind != 0 || v.S != "" || v.I != 0 || v.B {
				fields.Set(lf.Name, coerce(g, l.Target, lf.Name, v))
			}
		}
		if err := upsertHigh(kb, g, l.Target, fields, origin); err != nil {
			return err
		}
	}
	return nil
}

// descend walks an at-path: dotted keys and [*] fan-out over sequences.
func descend(g *graph.Store, n graph.Node, at string) []graph.Node {
	if at == "" {
		return []graph.Node{n}
	}
	seg, rest := at, ""
	for i := 0; i < len(at); i++ {
		if at[i] == '.' && (i+1 < len(at) && at[i+1] != '*' || i+1 >= len(at)) {
			seg, rest = at[:i], at[i+1:]
			break
		}
	}
	if seg == "*" || seg == "[*]" {
		var out []graph.Node
		for _, e := range g.Out(n.ID, "child") {
			if c, ok := g.Node(e.To); ok {
				out = append(out, descend(g, c, rest)...)
			}
		}
		return out
	}
	var out []graph.Node
	for _, e := range g.Out(n.ID, "child") {
		kf, ok := e.Fields.Get("key")
		if !ok || kf.S != strings.TrimSuffix(seg, "[*]") {
			continue
		}
		if c, ok := g.Node(e.To); ok {
			out = append(out, descend(g, c, rest)...)
		}
	}
	return out
}

// docField resolves one field-map entry over a doc origin: .key walks a keyed
// child (dotted via ."a.b" quoted descent); a literal passes through.
func docField(g *graph.Store, origin graph.Node, lf LiftField) graph.Value {
	switch x := lf.Value.(type) {
	case *Literal:
		switch x.Kind {
		case TokString:
			return graph.Str(unquote(x.Text))
		case TokNumber:
			var i int64
			if _, err := fmt.Sscanf(x.Text, "%d", &i); err == nil {
				return graph.Int(i)
			}
		case TokBool:
			return graph.Bool(x.Text == "true")
		}
		return graph.Value{}
	case *FieldRef:
		cur := origin
		for _, key := range x.Fields {
			found := false
			for _, e := range g.Out(cur.ID, "child") {
				kf, ok := e.Fields.Get("key")
				if ok && kf.S == key {
					if c, ok := g.Node(e.To); ok {
						cur = c
						found = true
						break
					}
				}
			}
			if !found {
				return graph.Value{}
			}
		}
		if v, ok := cur.Fields.Get("value"); ok {
			return typedScalar(v.S)
		}
		return graph.Value{}
	}
	return graph.Value{}
}

// typedScalar re-mints a scalar's text toward its natural kind so the target
// schema's typed fields validate.
func typedScalar(s string) graph.Value {
	if s == "true" || s == "false" {
		return graph.Bool(s == "true")
	}
	var i int64
	if _, err := fmt.Sscanf(s, "%d", &i); err == nil {
		return graph.Int(i)
	}
	return graph.Str(s)
}

// filtersFromFlows implements the copy form: the frontend's resolved FLOWS
// reaching the node's child arguments, copied as the list of bound upstream
// value names with resolved provenance.
func filtersFromFlows(g *graph.Store, n graph.Node) graph.Value {
	seen := map[string]bool{}
	var names []graph.Value
	add := func(id string) {
		src, ok := g.Node(id)
		if !ok || seen[id] {
			return
		}
		seen[id] = true
		if v, ok := src.Fields.Get("local"); ok {
			names = append(names, v)
			return
		}
		if v, ok := src.Fields.Get("path"); ok {
			names = append(names, v)
			return
		}
		names = append(names, graph.Str(src.ID))
	}
	for _, e := range g.In(n.ID, "FLOWS") {
		add(e.From)
	}
	for _, arg := range childArgs(g, n) {
		for _, e := range g.In(arg.ID, "FLOWS") {
			add(e.From)
		}
	}
	if names == nil {
		names = []graph.Value{}
	}
	return graph.Value{Kind: graph.KindList, Elem: graph.KindString, L: names}
}

// upsertHigh builds or merges the high node for one backing, and wires the
// automatic backs edge.
func upsertHigh(kb *KB, g *graph.Store, target string, fields graph.Fields, backing graph.Node) error {
	id := "lift:" + target + ":" + backing.ID
	high := graph.Node{
		ID:     id,
		Type:   target,
		Layer:  graph.LayerHigh,
		Fields: fields,
		Prov:   graph.Provenance{Producer: "lift", Build: graph.BuildLifted, Trust: kb.Trust},
	}
	if err := g.Upsert(high); err != nil {
		return err
	}
	// Lifts evaluate to a fixpoint with rules: re-applying
	// a lift must not fail on the backs edge it already built.
	for _, e := range g.Out(id, graph.EdgeBacks) {
		if e.To == backing.ID {
			return nil
		}
	}
	return g.AddEdge(graph.Edge{
		ID: "backs:" + id, Type: graph.EdgeBacks, From: id, To: backing.ID,
		Prov: graph.Provenance{Producer: "lift", Build: graph.BuildLifted, Trust: kb.Trust},
	})
}

// ApplyRelates derives high-level edges from low-level structure: by
// resolution follows the call graph between the endpoints' backings; over
// FLOWS follows the value graph.
func ApplyRelates(kb *KB, g *graph.Store) error {
	for _, f := range kb.Files {
		for _, r := range f.Relates {
			if r.By == "ref" {
				// The key-equality join: A.fromField == B.toField across the
				// two lifted node sets — the cross-domain resolution edge
				// (anchor) is ordinary data.
				toField := r.ToField
				if i := strings.LastIndex(toField, "."); i >= 0 {
					toField = toField[i+1:]
				}
				for _, a := range g.NodesOfType(r.From) {
					av, ok := a.Fields.Get(r.FromField)
					if !ok || av.S == "" {
						continue
					}
					for _, b := range g.NodesOfType(r.To) {
						bv, ok := b.Fields.Get(toField)
						if !ok || bv.S != av.S {
							continue
						}
						if err := g.AddEdge(graph.Edge{
							ID:   "relate:" + r.Edge + ":" + a.ID + ":" + b.ID,
							Type: r.Edge, From: a.ID, To: b.ID,
							Prov: graph.Provenance{Producer: "relate", Build: graph.BuildRelated, Trust: kb.Trust},
						}); err != nil {
							return err
						}
					}
				}
				continue
			}
			lowType := "CALLS"
			if r.By == "FLOWS" {
				lowType = "FLOWS"
			}
			for _, a := range g.NodesOfType(r.From) {
				ba, ok := g.Backing(a.ID)
				if !ok {
					continue
				}
				for _, e := range g.Out(ba.ID, lowType) {
					for _, b := range g.NodesOfType(r.To) {
						bb, ok := g.Backing(b.ID)
						if !ok || bb.ID != e.To {
							continue
						}
						he := graph.Edge{
							ID:   "relate:" + r.Edge + ":" + a.ID + ":" + b.ID,
							Type: r.Edge, From: a.ID, To: b.ID,
							Prov: graph.Provenance{Producer: "relate", Build: graph.BuildRelated, Trust: kb.Trust},
						}
						if err := g.AddEdge(he); err != nil {
							return err
						}
					}
				}
			}
		}
	}
	return nil
}

// posKey renders a node's file:line:col site key.
func posKey(n graph.Node) string {
	var b [3]string
	f, _ := n.Fields.Get("file")
	l, _ := n.Fields.Get("line")
	c, _ := n.Fields.Get("col")
	b[0], b[1], b[2] = f.S, l.String(), c.String()
	return b[0] + ":" + b[1] + ":" + b[2]
}
