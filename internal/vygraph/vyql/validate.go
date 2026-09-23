package vyql

import (
	"fmt"
	"sort"

	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/ontology"
)

// Knowledge is the validated world a file is checked against: the concept
// ontology, the graph type schemas, and the threat lattice.
type Knowledge struct {
	Onto    *ontology.Ontology
	Schemas *graph.Schemas
	Threats map[string]ThreatDecl

	// RuleCaps records per-rule confidence caps discovered during validation
	// (a rule naming a low-level NIR type is capped at medium).
	RuleCaps map[string]Confidence

	// ruleIDs tracks meta.id uniqueness across every validated file.
	ruleIDs map[string]string
}

// NewKnowledge builds an empty knowledge state over the given schemas.
func NewKnowledge(schemas *graph.Schemas) *Knowledge {
	return &Knowledge{
		Onto:     ontology.New(),
		Schemas:  schemas,
		Threats:  map[string]ThreatDecl{},
		RuleCaps: map[string]Confidence{},
		ruleIDs:  map[string]string{},
	}
}

// BuildKnowledge validates the declarations of files (concepts, threats) into a
// fresh Knowledge and returns every problem found — never stopping at the first.
func BuildKnowledge(files []*File, schemas *graph.Schemas) (*Knowledge, []error) {
	kb := NewKnowledge(schemas)
	var errs []error

	for _, f := range files {
		for _, c := range f.Concepts {
			if err := kb.addConcept(c); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for _, f := range files {
		for _, th := range f.Threats {
			if _, dup := kb.Threats[th.Name]; dup {
				errs = append(errs, fmt.Errorf("%d:%d: threat %q already defined", th.Pos.Line, th.Pos.Col, th.Name))
				continue
			}
			kb.Threats[th.Name] = th
		}
	}
	for _, f := range files {
		for _, th := range f.Threats {
			for _, parent := range th.Subsumes {
				if _, ok := kb.Threats[parent]; !ok {
					errs = append(errs, fmt.Errorf("%d:%d: threat %q subsumes unknown threat %q",
						th.Pos.Line, th.Pos.Col, th.Name, parent))
				}
			}
		}
	}
	if cyc := threatCycle(kb.Threats); cyc != "" {
		errs = append(errs, fmt.Errorf("threat lattice has a subsumes cycle through %q", cyc))
	}
	return kb, errs
}

// addConcept converts a declaration into an ontology concept, mapping every
// vocabulary error onto the declaration's position.
func (kb *Knowledge) addConcept(c ConceptDecl) error {
	kinds := make([]ontology.Kind, len(c.Kinds))
	for i, k := range c.Kinds {
		kinds[i] = ontology.Kind(k)
	}
	oc := ontology.Concept{
		Name:         c.Name,
		Kinds:        kinds,
		Refines:      c.Refines,
		Taint:        c.Taint,
		VulnerableTo: c.VulnerableTo,
		EnabledBy:    c.EnabledBy,
		Neutralizes:  c.Neutralizes,
		Defends:      c.Defends,
		CWE:          c.CWE,
	}
	if err := kb.Onto.Add(oc); err != nil {
		return fmt.Errorf("%d:%d: concept %q: %w", c.Pos.Line, c.Pos.Col, c.Name, err)
	}
	return nil
}

func threatCycle(threats map[string]ThreatDecl) string {
	const (
		white = 0
		grey  = 1
		black = 2
	)
	color := map[string]int{}
	var visit func(string) string
	visit = func(name string) string {
		color[name] = grey
		for _, parent := range threats[name].Subsumes {
			if color[parent] == grey {
				return parent
			}
			if color[parent] == white {
				if hit := visit(parent); hit != "" {
					return hit
				}
			}
		}
		color[name] = black
		return ""
	}
	names := make([]string, 0, len(threats))
	for n := range threats {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if color[n] == white {
			if hit := visit(n); hit != "" {
				return hit
			}
		}
	}
	return ""
}

// Validate checks one file against kb and returns every problem. It also records
// per-rule confidence caps into kb.RuleCaps (a rule naming a low-level type is
// capped, not rejected).
func Validate(f *File, kb *Knowledge) []error {
	var errs []error
	fail := func(pos Pos, format string, args ...any) {
		errs = append(errs, fmt.Errorf("%d:%d: %s", pos.Line, pos.Col, fmt.Sprintf(format, args...)))
	}

	for _, a := range f.Adapters {
		if a.Fidelity != "syntactic" && a.Fidelity != "resolved" {
			fail(a.Pos, "adapter %q: fidelity must be syntactic or resolved, got %q", a.Tech, a.Fidelity)
		}
		for _, b := range a.Bindings {
			kb.checkBinding(b, fail)
		}
	}

	seenIDs := map[string]bool{}
	for _, r := range f.Rules {
		if !r.Meta.HasMeta || r.Meta.ID == "" {
			fail(r.Pos, "rule %q must declare meta { id: \"...\" }", r.Name)
		} else if seenIDs[r.Meta.ID] {
			fail(r.Pos, "rule id %q is already used in this file", r.Meta.ID)
		} else if other, dup := kb.ruleIDs[r.Meta.ID]; dup {
			fail(r.Pos, "rule id %q already used by %q", r.Meta.ID, other)
		} else {
			seenIDs[r.Meta.ID] = true
			kb.ruleIDs[r.Meta.ID] = r.Name
		}
		if r.Meta.Severity != "" && !severities[r.Meta.Severity] {
			fail(r.Pos, "rule %q: unknown severity %q", r.Name, r.Meta.Severity)
		}
		if r.Meta.ConfidenceFloor != "" {
			if _, ok := ParseConfidence(r.Meta.ConfidenceFloor); !ok {
				fail(r.Pos, "rule %q: unknown confidence_floor %q", r.Name, r.Meta.ConfidenceFloor)
			}
		}
		kb.checkBody(r.Name, r.Body, fail)
	}
	for _, q := range f.Queries {
		kb.checkBody(q.Name, q.Body, fail)
		for _, alt := range q.Alts {
			kb.checkBody(q.Name, alt, fail)
		}
	}
	return errs
}

// checkBinding enforces the D7 boundary at the binding layer: the binding
// keyword must match the bound concept's kind facet; label accepts any kind.
func (kb *Knowledge) checkBinding(b BindingDecl, fail func(Pos, string, ...any)) {
	if b.Keyword != "label" {
		c, ok := kb.Onto.Get(b.Concept)
		if !ok {
			fail(b.Pos, "binding names undefined concept %q", b.Concept)
			return
		}
		if !c.HasKind(ontology.Kind(b.Keyword)) {
			fail(b.Pos, "%s binding must target a concept of kind %q; %q is %v",
				b.Keyword, b.Keyword, b.Concept, c.Kinds)
		}
	}
	call, ok := b.Matcher.(*Call)
	if !ok {
		fail(b.Pos, "matcher must be a call")
		return
	}
	if call.Name != "code.path" {
		fail(b.Pos, "unknown matcher %q (the 1b surface implements code.path)", call.Name)
	}
}

// varInfo is what a node pattern binds a variable to: a schema-typed node
// (typed-field checking applies, and the rule is capped) or a concept-typed
// node (fields are domain-level and unchecked until lift, Phase 2).
type varInfo struct {
	schema *graph.TypeSchema // nil for concept-bound variables
}

// ftype is the resolved type of a where-clause operand.
type ftype struct {
	known bool
	k     graph.Kind
	elem  graph.Kind // list element kind
	enum  []string   // enum members
}

var unknownType = ftype{}

// checkBody validates a rule or query body: concept references exist, patterns
// bind concept-or-type only (a type caps the rule), and typed where operands
// match the schema.
func (kb *Knowledge) checkBody(name string, b RuleBody, fail func(Pos, string, ...any)) {
	if b.Sugar != nil {
		for _, c := range []struct {
			ref string
			pos Pos
		}{{b.Sugar.From, b.Sugar.FromPos}, {b.Sugar.To, b.Sugar.ToPos}} {
			if c.ref == "" {
				continue
			}
			if _, ok := kb.Onto.Get(c.ref); !ok {
				fail(c.pos, "rule %q: sugar names undefined concept %q", name, c.ref)
			}
		}
	}

	env := map[string]varInfo{}
	for _, pat := range b.Match {
		for _, n := range pat.Nodes {
			typ := n.TypeOrConcept
			if ts, isType := kb.Schemas.Lookup(typ); isType {
				if n.Var != "" {
					env[n.Var] = varInfo{schema: ts}
					kb.RuleCaps[name] = CapLowLevelType // low-level NIR type: cap, don't reject
				}
			} else if _, isConcept := kb.Onto.Get(typ); isConcept {
				if n.Var != "" {
					env[n.Var] = varInfo{}
				}
			} else {
				fail(n.Pos, "rule %q: %q is neither a registered type nor a defined concept", name, typ)
			}
		}
	}

	if b.Where != nil {
		kb.typeExpr(b.Where, env, name, fail)
	}
	if b.Unless != nil && b.Unless.Concept != "" {
		if _, ok := kb.Onto.Get(b.Unless.Concept); !ok {
			fail(b.Unless.Pos, "rule %q: unless names undefined concept %q", name, b.Unless.Concept)
		}
	}
}

// typeExpr resolves and checks one expression, reporting violations via fail.
func (kb *Knowledge) typeExpr(e Expr, env map[string]varInfo, rule string, fail func(Pos, string, ...any)) ftype {
	switch x := e.(type) {
	case *Literal:
		switch x.Kind {
		case TokString:
			return ftype{known: true, k: graph.KindString}
		case TokNumber:
			return ftype{known: true, k: graph.KindInt}
		case TokBool:
			return ftype{known: true, k: graph.KindBool}
		}
		return unknownType
	case *Name:
		// A bare name resolves only as an enum member against a typed operand;
		// that coercion happens in typeBinOp. Standalone it is unresolved.
		return unknownType
	case *FieldRef:
		return kb.typeFieldRef(x, env, rule, fail)
	case *Not:
		kb.typeExpr(x.X, env, rule, fail)
		return ftype{known: true, k: graph.KindBool}
	case *BinOp:
		return kb.typeBinOp(x, env, rule, fail)
	case *Call:
		switch x.Name {
		case "any", "all":
			if len(x.Args) != 1 {
				fail(x.Pos, "rule %q: %s takes one argument", rule, x.Name)
				return unknownType
			}
			t := kb.typeExpr(x.Args[0], env, rule, fail)
			if !t.known || t.k != graph.KindList {
				fail(x.Pos, "rule %q: %s quantifies a list field", rule, x.Name)
				return unknownType
			}
			return ftype{known: true, k: t.elem, enum: t.enum}
		case "count":
			return ftype{known: true, k: graph.KindInt}
		default:
			fail(x.Pos, "rule %q: unknown function %q in where", rule, x.Name)
			return unknownType
		}
	}
	return unknownType
}

func (kb *Knowledge) typeFieldRef(x *FieldRef, env map[string]varInfo, rule string, fail func(Pos, string, ...any)) ftype {
	if len(x.Fields) == 0 {
		return unknownType
	}
	if len(x.Fields) > 1 {
		fail(x.Pos, "rule %q: nested field chains are not part of the 1b surface", rule)
		return unknownType
	}
	vi, bound := env[x.Var]
	if !bound {
		fail(x.Pos, "rule %q: variable %q is not bound by a pattern", rule, x.Var)
		return unknownType
	}
	// Concept-bound variables carry no field schema in 1b: their fields are
	// domain-level and unchecked until lift lands (Phase 2).
	if vi.schema == nil {
		return unknownType
	}
	spec, ok := fieldSpecOf(vi.schema, x.Fields[0])
	if !ok {
		fail(x.Pos, "rule %q: type %q has no field %q", rule, vi.schema.Type, x.Fields[0])
		return unknownType
	}
	return ftype{known: true, k: spec.Kind, elem: spec.Elem, enum: spec.Enum}
}

func fieldSpecOf(ts *graph.TypeSchema, name string) (graph.FieldSpec, bool) {
	for _, f := range ts.Fields {
		if f.Name == name {
			return f, true
		}
	}
	return graph.FieldSpec{}, false
}

func (kb *Knowledge) typeBinOp(x *BinOp, env map[string]varInfo, rule string, fail func(Pos, string, ...any)) ftype {
	switch x.Op {
	case "and", "or":
		for _, side := range []Expr{x.L, x.R} {
			t := kb.typeExpr(side, env, rule, fail)
			if t.known && t.k != graph.KindBool {
				fail(side.exprPos(), "rule %q: %s needs boolean operands", rule, x.Op)
				return unknownType
			}
		}
		return ftype{known: true, k: graph.KindBool}
	case "has":
		var concept string
		switch r := x.R.(type) {
		case *Name:
			concept = r.Name
		case *FieldRef:
			concept = joinDotted(r.Var, r.Fields)
		default:
			fail(x.Pos, "rule %q: has needs a concept on the right", rule)
			return unknownType
		}
		if _, ok := kb.Onto.Get(concept); !ok {
			fail(x.Pos, "rule %q: has names undefined concept %q", rule, concept)
			return unknownType
		}
		return ftype{known: true, k: graph.KindBool}
	}

	lt := kb.typeExpr(x.L, env, rule, fail)
	rt := kb.typeExpr(x.R, env, rule, fail)

	// Enum members arrive as bare Names; coerce them toward the typed side.
	if n, isName := x.R.(*Name); isName && lt.known {
		if lt.k == graph.KindEnum {
			if !enumHas(lt.enum, n.Name) {
				fail(x.Pos, "rule %q: %q is not a member of the field's enum", rule, n.Name)
				return unknownType
			}
			rt = ftype{known: true, k: graph.KindEnum}
		} else {
			fail(x.Pos, "rule %q: bare name %q only resolves against an enum field", rule, n.Name)
			return unknownType
		}
	}
	if n, isName := x.L.(*Name); isName && rt.known {
		if rt.k == graph.KindEnum {
			if !enumHas(rt.enum, n.Name) {
				fail(x.Pos, "rule %q: %q is not a member of the field's enum", rule, n.Name)
				return unknownType
			}
			lt = ftype{known: true, k: graph.KindEnum}
		} else {
			fail(x.Pos, "rule %q: bare name %q only resolves against an enum field", rule, n.Name)
			return unknownType
		}
	}

	switch x.Op {
	case "==", "!=":
		if lt.known && rt.known && lt.k != rt.k {
			fail(x.Pos, "rule %q: %s compares %s with %s", rule, x.Op, lt.k, rt.k)
			return unknownType
		}
		return ftype{known: true, k: graph.KindBool}
	case "<", "<=", ">", ">=":
		for _, t := range []ftype{lt, rt} {
			if t.known && t.k != graph.KindInt && t.k != graph.KindEnum {
				fail(x.Pos, "rule %q: ordering operators need numeric or enum operands, got %s", rule, t.k)
				return unknownType
			}
		}
		return ftype{known: true, k: graph.KindBool}
	case "in":
		if rt.known && rt.k != graph.KindList {
			fail(x.Pos, "rule %q: in needs a list on the right", rule)
			return unknownType
		}
		if lt.known && rt.known && rt.k == graph.KindList && lt.k != rt.elem {
			fail(x.Pos, "rule %q: in tests membership of a list<%s>, got %s", rule, rt.elem, lt.k)
			return unknownType
		}
		return ftype{known: true, k: graph.KindBool}
	case "matches", "contains", "starts_with", "under":
		for _, t := range []ftype{lt, rt} {
			if t.known && t.k != graph.KindString {
				fail(x.Pos, "rule %q: %s needs string operands, got %s", rule, x.Op, t.k)
				return unknownType
			}
		}
		return ftype{known: true, k: graph.KindBool}
	}
	fail(x.Pos, "rule %q: unknown operator %q", rule, x.Op)
	return unknownType
}

func enumHas(enum []string, s string) bool {
	for _, e := range enum {
		if e == s {
			return true
		}
	}
	return false
}

func joinDotted(head string, rest []string) string {
	out := head
	for _, r := range rest {
		out += "." + r
	}
	return out
}
