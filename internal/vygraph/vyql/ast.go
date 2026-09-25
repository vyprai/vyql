package vyql

// AST for the 1b grammar subset. Nodes carry source positions where the parser can
// report errors (validation and compile errors must name file:line:col).

// File is one parsed .vyql module file.
type File struct {
	Module     string
	Manifest   *Manifest // non-nil when the file uses the block form (module.vyql)
	Concepts   []ConceptDecl
	Threats    []ThreatDecl
	Adapters   []AdapterDecl
	Rules      []RuleDecl
	Queries    []QueryDecl
	Lifts      []LiftDecl
	Relates    []RelateDecl
	Frameworks []FrameworkDecl
	GuardHints []GuardHintDecl
}

// LiftDecl builds a high-level node from matched low-level nodes, mapping
// fields and automatically backing the target to its source.
type LiftDecl struct {
	Target    string      // high type, e.g. code.Entrypoint
	From      Expr        // matcher call: code.func(), code.call(...), code.syntacticPath(...)
	Where     Expr        // optional predicate (decorated_by(glob), field comparisons)
	Fields    []LiftField // ordered field map
	Copies    []string    // fields using the copy form `from flows(self) by resolution`
	Framework string      // non-empty: lift from a framework model's route facts
	// Doc-lift form: from doc where kind == "..." at "path".
	FromDoc bool
	DocKind string
	At      string // optional path selector; [*] targets every seq element
	Pos     Pos
}

// LiftField is one target-field binding.
type LiftField struct {
	Name  string
	Value Expr
}

// RelateDecl derives a high-level edge between high nodes from low-level
// structure — by resolution (the call graph), over FLOWS (the value graph), or
// by ref (a key equality across nodes: the cross-domain resolution join).
type RelateDecl struct {
	Edge string // edge type name, e.g. calls, anchor
	From string // high type A
	To   string // high type B
	By   string // "resolution" | "FLOWS" | "ref"
	// by ref: FromField == ToType.ToField over the two node sets.
	FromField, ToField string
	Pos                Pos
}

// FrameworkDecl interprets generic low-level facts (route-registration calls,
// decorators) into framework knowledge — VyQL, never the frontend.
type FrameworkDecl struct {
	Name   string
	Routes []RouteDecl
	Pos    Pos
}

// RouteDecl is one route rule of a framework model.
type RouteDecl struct {
	On      Expr // matcher call selecting registration calls or functions
	Where   Expr // optional predicate
	Method  Expr // expr over the match, e.g. callee.method or a literal
	Path    Expr // e.g. arg(0)
	Handler Expr // e.g. arg(-1)
	Pos     Pos
}

// Manifest is the module block: identity, requirements, imports, and the trust
// tier every declaration in the module is stamped with.
type Manifest struct {
	Module           string
	Version          string
	RequiresOntology string
	RequiresEngine   string
	Imports          []ManifestImport
	Provenance       string // generated | validated | reviewed | trusted
	Pos              Pos
}

// ManifestImport is one import entry, optionally kind-qualified.
type ManifestImport struct {
	Kind string // pattern | query | concept | adapter | model, or empty
	Name string
}

// Pos is a 1-based source position.
type Pos struct{ Line, Col int }

// ConceptDecl is a Layer-2 concept. Kinds are the raw text from the declaration;
// validation checks them against the closed ten-kind set.
type ConceptDecl struct {
	Name         string
	Kinds        []string
	Refines      string
	Taint        []string
	VulnerableTo []string
	EnabledBy    []string
	Neutralizes  []string
	Defends      []string
	CWE          []string
	Pos          Pos
}

// ThreatDecl is a threat with its subsumption parents.
type ThreatDecl struct {
	Name     string
	Subsumes []string
	Pos      Pos
}

// AdapterDecl is a Layer-3 binding module for one technology.
type AdapterDecl struct {
	Tech     string
	Fidelity string // syntactic | resolved (defaults to syntactic)
	Bindings []BindingDecl
	Pos      Pos
}

// BindingDecl binds a matcher to a concept. Keyword must match the concept's kind
// facet (validation); a bare string matcher desugars to code.path("...").
type BindingDecl struct {
	Keyword string // source | sink | control | guard | label
	Matcher Expr   // a Call (matcher) — string sugar desugared by the parser
	Where   Expr   // optional native filter
	Concept string
	Arg     int // sink-only: which argument position carries the dangerous string (-1 = all)
	Pos     Pos
}

// RuleDecl is a Layer-4 rule.
type RuleDecl struct {
	Name string
	Meta RuleMeta
	Body RuleBody
	Pos  Pos
}

// RuleMeta carries the rule's metadata block.
type RuleMeta struct {
	ID              string
	Severity        string
	CWE             []string
	ConfidenceFloor string
	HasMeta         bool
}

// QueryDecl is a named derived-set definition; Alts are the "or { ... }" bodies.
type QueryDecl struct {
	Name   string
	Params []string
	Body   RuleBody
	Alts   []RuleBody
	Pos    Pos
}

// RuleBody is the shared shape of rule and query bodies. Rules end in an emit
// (and optional unless); queries end in `yield <var>`.
type RuleBody struct {
	Match    []Pattern // non-empty for match bodies
	Sugar    *Sugar    // non-nil for sugar bodies (taint/reach/present)
	Where    Expr
	Deviates *Deviates // non-nil for deviation bodies (signal-only)
	Emit     EmitKind  // Finding or Signal
	Unless   *Suppressor
	Yield    string // query form: the yielded binding variable
	Pos      Pos
}

// Deviates is the deviation clause: peers by a registered selector, the
// missing guard-ish feature, and the knobs.
type Deviates struct {
	Selector  string // same_router | same_model | same_annotation_class
	Feature   string // the concept whose absence is the signal
	MinGroup  int
	Threshold float64
	Pos       Pos
}

// GuardHintDecl is a declared guard-ish seed: an identifier shape mapping to
// the concept it seeds — versioned knowledge, never hidden solver state.
type GuardHintDecl struct {
	Glob    string
	Concept string
	Pos     Pos
}

// EmitKind distinguishes the two output streams.
type EmitKind uint8

const (
	EmitFinding EmitKind = iota
	EmitSignal
)

// Sugar is a desugaring shorthand: taint A -> B, reach A -> B, present C.
type Sugar struct {
	Verb    string // taint | reach | present
	From    string // concept name (taint/reach source side; the concept for present)
	To      string // concept name (sink side; empty for present)
	FromPos Pos
	ToPos   Pos
}

// Pattern is one match pattern: a chain of nodes joined by edges.
type Pattern struct {
	Nodes []NodePattern
	Edges []EdgePattern
}

// NodePattern is ( var : TypeOrConcept { field: literal, ... } ).
type NodePattern struct {
	Var           string // may be empty (anonymous)
	TypeOrConcept string
	Fields        []FieldConst
	Pos           Pos
}

// FieldConst is one `field: literal` constraint inside a node pattern.
type FieldConst struct {
	Name    string
	Literal Expr // a Literal
}

// EdgePattern is -[:TYPE]-> or <-[:TYPE]-.
type EdgePattern struct {
	Type    string
	Reverse bool
	Pos     Pos
}

// Suppressor is the unless-clause.
type Suppressor struct {
	Kind    string // sanitized_by | guarded_by | closed_by | anchored
	Concept string // empty for anchored
	Pos     Pos
}

// ---- expressions (where clauses, matcher arguments) ----

// Expr is a native-expression AST node.
type Expr interface{ exprPos() Pos }

// FieldRef is var.field or var.f1.f2 — the lexer produced a dotted ident.
type FieldRef struct {
	Var    string
	Fields []string
	Pos    Pos
}

// Name is a bare identifier awaiting validation's resolution (enum member, concept
// reference, or an error).
type Name struct {
	Name string
	Pos  Pos
}

// Literal is a string/number/bool literal.
type Literal struct {
	Kind TokenKind // TokString | TokNumber | TokBool
	Text string
	Pos  Pos
}

// BinOp covers comparisons, string ops, in, and `x has Concept`.
type BinOp struct {
	Op   string // == != < <= > >= in matches contains starts_with under has
	L, R Expr
	Pos  Pos
}

// Not is negation.
type Not struct{ X Expr }

// Call is a matcher (code.path("x")) or a builtin (any/all/count).
type Call struct {
	Name string
	Args []Expr
	Pos  Pos
}

func (e *FieldRef) exprPos() Pos { return e.Pos }
func (e *Name) exprPos() Pos     { return e.Pos }
func (e *Literal) exprPos() Pos  { return e.Pos }
func (e *BinOp) exprPos() Pos    { return e.Pos }
func (e *Not) exprPos() Pos      { return e.X.exprPos() }
func (e *Call) exprPos() Pos     { return e.Pos }
