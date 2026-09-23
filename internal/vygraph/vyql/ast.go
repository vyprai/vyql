package vyql

// AST for the 1b grammar subset. Nodes carry source positions where the parser can
// report errors (validation and compile errors must name file:line:col).

// File is one parsed .vyql module file.
type File struct {
	Module   string
	Concepts []ConceptDecl
	Threats  []ThreatDecl
	Adapters []AdapterDecl
	Rules    []RuleDecl
	Queries  []QueryDecl
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
	Match  []Pattern // non-empty for match bodies
	Sugar  *Sugar    // non-nil for sugar bodies (taint/reach/present)
	Where  Expr
	Emit   EmitKind // Finding or Signal
	Unless *Suppressor
	Yield  string // query form: the yielded binding variable
	Pos    Pos
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
