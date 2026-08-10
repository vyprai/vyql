// Package parser implements the VyQL v2 definition parser and compiles
// authored definitions into the scanner IR consumed by the engine and graph labeler.
package parser

// --- declarations --------------------------------------------------------

// Decl is a scanner IR declaration compiled from a VyQL v2 definition.
type Decl interface{ isDecl() }

// Rule is a compiled finding/query rule. Name is the short PascalCase rule name;
// Package is the enclosing v2 module. QualifiedName joins them as
// module.RuleName.
type Rule struct {
	Name    string
	Package string
	Meta    map[string]any // values are string or []string
	Body    Stmt
	Clauses []Clause
}

func (*Rule) isDecl() {}

// QualifiedName returns the namespaced rule id.
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

// ConceptDecl is an ontology concept declaration. Kind is the v2 concept kind
// such as source, sink, check, issue, fact, asset, exposure, principal,
// privilege, or state. Fields holds kind-dependent typing and standards
// attributes such as vulnerable_to, neutralizes, refines, and cwe.
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

// ThreatDecl is a weakness-class declaration from the v2 typing vocabulary.
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

// ReviewDecl attaches review/triage presentation metadata to a concept. The
// scanner still labels concepts through bindings/rules; this declaration only
// controls `vyql scan --flags` categorization, expected checks, and reader guidance.
type ReviewDecl struct {
	Concept string
	Fields  map[string]any
}

func (*ReviewDecl) isDecl() {}

// ProfileDecl is an application-archetype threat-modelling profile. It selects
// trust boundaries, relevant rule packs, and auto-detection predicates.
type ProfileDecl struct {
	Name   string
	Fields map[string]any
}

func (*ProfileDecl) isDecl() {}

// PackDecl groups rules, bindings, profiles, and review output for activation.
type PackDecl struct {
	Name   string
	Fields map[string]any
}

func (*PackDecl) isDecl() {}

// --- statements (rule body) ----------------------------------------------

// Stmt is a scanner IR rule body.
type Stmt interface{ isStmt() }

// Endpoint is a flow endpoint: a concept with an optional binding.
type Endpoint struct {
	Concept string
	Binding string // "" = none
}

// FlowStmt invokes a two-endpoint solver capability such as taint,
// reachability, or grant.
type FlowStmt struct {
	Verb          string
	Src           Endpoint
	Dst           Endpoint
	SemanticQuery bool // true when lowered from raw semantic-tier `query ... reaches ...`
}

func (*FlowStmt) isStmt() {}

// OrderStmt fires when one concept instance can reach another on a CFG path.
// It models type-state and temporal checks such as reentrancy and TOCTOU.
type OrderStmt struct {
	First  Endpoint
	Second Endpoint
	Loc    string
}

func (*OrderStmt) isStmt() {}

// MatchStmt fires on an existing concept or transition fact.
type MatchStmt struct {
	TargetKind     string // "concept" | "transition" (action concepts are "concept")
	Concept        string
	Binding        string
	Relation       string
	RelationProp   string
	RelatedConcept string
	FromState      string // transition
	ToState        string
	Machine        string
}

func (*MatchStmt) isStmt() {}

// --- clauses -------------------------------------------------------------

// Clause is a scanner IR where/unless clause.
type Clause struct {
	Kind   string    // "where" | "unless"
	Where  Expr      // for where
	Unless Exception // for unless
}

// Exception is a v2 coverage exception.
type Exception interface{ isException() }

type PathCoveredBy struct{ Concept string }
type EndpointCoveredBy struct{ Concept string }
type SameReceiverCoveredBy struct{ Concept string }
type SameScopeCoveredBy struct{ Concept string }
type GlobalCoveredBy struct{ Concept string }
type DominatesCoveredBy struct{ Concept string }
type PostDominatesCoveredBy struct{ Concept string }
type ExprException struct{ Expr Expr }

func (PathCoveredBy) isException()          {}
func (EndpointCoveredBy) isException()      {}
func (SameReceiverCoveredBy) isException()  {}
func (SameScopeCoveredBy) isException()     {}
func (GlobalCoveredBy) isException()        {}
func (DominatesCoveredBy) isException()     {}
func (PostDominatesCoveredBy) isException() {}
func (ExprException) isException()          {}

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
type Or struct{ Parts []Expr }
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

type Is struct {
	Ref     Ref
	Concept string
}

type Cmp struct {
	Ref   Ref
	Op    string // "==" | "!=" | ">=" | "<=" | ">" | "<"
	Value any    // string, int, or []string
}

// NotIn is `<ref> not in [<set>]` — set non-membership of a scalar property
// (docs/11: workload drift, `p.image not in p.workload.declared_images`).
type NotIn struct {
	Ref    Ref
	Values []string
	Negate bool // true = `not in` (default); false = `in`
}

func (And) isExpr()            {}
func (Or) isExpr()             {}
func (Not) isExpr()            {}
func (SolverCall) isExpr()     {}
func (HoldsAssetKind) isExpr() {}
func (Is) isExpr()             {}
func (Cmp) isExpr()            {}
func (NotIn) isExpr()          {}

// FlowVerbs / SolverVerbs (docs/05).
var FlowVerbs = map[string]bool{"taint": true, "reach": true, "grant": true}
var SolverVerbs = map[string]bool{"taint": true, "reach": true, "grant": true, "can_access": true, "dominates": true}
