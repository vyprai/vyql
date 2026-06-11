// Package parser implements the VyQL rule-layer parser (docs/05), ported from
// poc/vyql/parser.py. It parses `rule`, `query`, and `state_machine`
// declarations into an AST consumed by the engine.
package parser

// --- declarations --------------------------------------------------------

// Decl is a top-level declaration (Rule or StateMachine).
type Decl interface{ isDecl() }

// Rule is a `rule`/`query` declaration. Name is the short PascalCase rule name;
// Package is the enclosing `package <namespace>` (if any). QualifiedName joins
// them (vendor.category.RuleName).
type Rule struct {
	Name    string
	Package string
	Meta    map[string]any // values are string or []string
	Body    Stmt
	Clauses []Clause
	IsQuery bool
}

func (*Rule) isDecl() {}

// QualifiedName returns the namespaced rule id. If the rule name is already
// dotted (legacy), it is returned as-is.
func (r *Rule) QualifiedName() string {
	if r.Package == "" || containsDot(r.Name) {
		return r.Name
	}
	return r.Package + "." + r.Name
}

func containsDot(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return true
		}
	}
	return false
}

// ConceptDecl is an ontology concept declaration. The kind is a type
// annotation in the header — `concept Deserialization : sink { … }` — not a
// redundant body field. Name is the short PascalCase name; Package is the
// enclosing `package <namespace>` (or the prefix if the header name is dotted).
// Fields holds the kind-dependent typing/standards attributes (values are
// string or []string), e.g. vulnerable_to, neutralizes, refines, cwe.
type ConceptDecl struct {
	Name    string
	Package string
	Kind    string
	Fields  map[string]any
}

func (*ConceptDecl) isDecl() {}

// QualifiedName returns the namespaced concept id `<package>.<Name>`.
func (c *ConceptDecl) QualifiedName() string {
	if c.Package == "" {
		return c.Name
	}
	return c.Package + "." + c.Name
}

// AdapterDecl is an `adapter <tech> { … }` declaration (docs/07): the
// framework→concept content. Each mapping labels a source (input call path) or a
// sink (call method/path) with a concept.
type AdapterDecl struct {
	Name     string
	Meta     map[string]any
	Mappings []AdapterMapping
}

func (*AdapterDecl) isDecl() {}

// AdapterMapping is one `source`/`sink`/`type`/`control` line in an adapter.
type AdapterMapping struct {
	Kind       string // "source" | "sink_method" | "sink_path" | "type" | "control"
	Pattern    string // the callee path / method token (a string literal or dotted name)
	Concept    string // the concept it maps to (qualified); for "type", the type name
	Constraint string // optional `on <type>` receiver-type constraint for sinks
	ArgIndex   int    // which argument is the dangerous one (default 0; `arg N`)
	ValMatches []string // `val "substr"` (repeatable, AND) — fire only when every substr is in some arg/option literal
	ValAbsents []string // `nval "substr"` (repeatable, AND) — fire only when no arg/option literal contains any substr
}

// ThreatDecl is a `threat <ns>.<Name> { cwe: [...] }` weakness-class declaration
// (docs/06 typing vocabulary).
type ThreatDecl struct {
	Name    string
	Package string
	Fields  map[string]any
}

func (*ThreatDecl) isDecl() {}

func (t *ThreatDecl) QualifiedName() string {
	if t.Package == "" {
		return t.Name
	}
	return t.Package + "." + t.Name
}

// StateMachine is a `state_machine` declaration.
type StateMachine struct {
	Name        string
	States      []string
	Initial     string
	Transitions [][2]string // (from, to)
}

func (*StateMachine) isDecl() {}

// --- statements (rule body) ----------------------------------------------

// Stmt is a rule body: FlowStmt or MatchStmt.
type Stmt interface{ isStmt() }

// Endpoint is a flow endpoint: a concept with an optional binding.
type Endpoint struct {
	Concept string
	Binding string // "" = none
}

// FlowStmt is `taint|flow|reach|assume A -> B`.
type FlowStmt struct {
	Verb string
	Src  Endpoint
	Dst  Endpoint
}

func (*FlowStmt) isStmt() {}

// MatchStmt is `match <target> as id`.
type MatchStmt struct {
	TargetKind string // "concept" | "transition" (action concepts are "concept")
	Concept    string
	Binding    string
	FromState  string // transition
	ToState    string
	Machine    string
}

func (*MatchStmt) isStmt() {}

// --- clauses -------------------------------------------------------------

// Clause is a where/unless/along clause.
type Clause struct {
	Kind   string    // "where" | "unless" | "along"
	Where  Expr      // for where
	Unless Exception // for unless
	Along  []string  // for along
}

// Exception is an unless exception.
type Exception interface{ isException() }

type SanitizedBy struct{ Concept string }
type GuardedBy struct{ Concept string }
type ExprException struct{ Expr Expr }

func (SanitizedBy) isException()   {}
func (GuardedBy) isException()     {}
func (ExprException) isException() {}

// --- expressions ---------------------------------------------------------

// Expr is a where/unless predicate expression.
type Expr interface{ isExpr() }

// Ref is a dotted reference: id ("." id)*.
type Ref struct{ Parts []string }

func (Ref) isExpr() {}

func (r Ref) String() string {
	out := ""
	for i, p := range r.Parts {
		if i > 0 {
			out += "."
		}
		out += p
	}
	return out
}

type And struct{ Parts []Expr }
type Not struct{ Inner Expr }

// Arg is a solver-call argument (a ref, optionally bound `as name`).
type Arg struct {
	Ref     Ref
	Binding string // "" = unbound
}

type SolverCall struct {
	Verb    string
	Args    []Arg
	Binding string
}

type HoldsAssetKind struct {
	Ref   Ref
	Kinds []string
}

type Has struct {
	Ref     Ref
	Concept string
}

type Is struct {
	Ref     Ref
	Concept string
}

type Cmp struct {
	Ref   Ref
	Op    string // "==" | "!="
	Value any    // string or []string
}

// NotIn is `<ref> not in [<set>]` — set non-membership of a scalar property
// (docs/11: workload drift, `p.image not in p.workload.declared_images`).
type NotIn struct {
	Ref    Ref
	Values []string
	Negate bool // true = `not in` (default); false = `in`
}

func (And) isExpr()            {}
func (Not) isExpr()            {}
func (SolverCall) isExpr()     {}
func (HoldsAssetKind) isExpr() {}
func (Has) isExpr()            {}
func (Is) isExpr()             {}
func (Cmp) isExpr()            {}
func (NotIn) isExpr()          {}

// FlowVerbs / SolverVerbs (docs/05).
var FlowVerbs = map[string]bool{"taint": true, "flow": true, "reach": true, "assume": true}
var SolverVerbs = map[string]bool{"taint": true, "flow": true, "reach": true, "assume": true, "can_access": true}
