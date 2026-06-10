// Package nir is the Normalized IR (docs/20) — the coherent representation
// every language frontend targets, ported from poc/extract/nir.py.
//
// This is where "AST node coherence" lives. Tree-sitter, go/ast, CPython ast,
// acorn/ESTree, and Ripper produce structurally unrelated trees; each frontend
// translates its parse tree into THIS small, uniform node set. The shared
// lowering engine (package lowering) then does dataflow + import/type resolution
// ONCE over NIR — so adding a language (or swapping a parser) is a frontend only,
// never resolution or rule code.
//
// NIR is semantic-shaped, not syntax-shaped: it carries exactly what the
// dataflow + resolution engine needs and nothing language-specific. loc strings
// are display paths ("rel/file.py:12"); module/import keys are source-root keys
// used for resolution (may differ from display paths).
package nir

// Expr is the NIR expression interface (a closed set, switched on in lowering).
type Expr interface{ isExpr() }

// Name is a variable reference.
type Name struct {
	ID  string
	Loc string
}

// Const is a literal / constant (carries no taint of its own).
type Const struct {
	Loc string
	// Value is the unquoted literal text for STRING constants, used by
	// value-matching sinks (`val "..."`, e.g. CORS '*', cipher 'ECB'); empty otherwise.
	Value string
}

// Attr is an attribute access base.attr; Path is the dotted callee path for
// adapter matching, e.g. "req.body".
type Attr struct {
	Base Expr
	Attr string
	Path string
	Loc  string
}

// Index is a subscript x[k]; Path is the dotted callee path.
type Index struct {
	Base Expr
	Path string
	Loc  string
}

// Call is a call expression; Path is the callee path (e.g. "db.query") and
// Method is its last segment (e.g. "query").
type Call struct {
	Callee Expr
	Args   []Expr
	Path   string
	Method string
	Loc    string
}

// Format is a taint-propagating string build (f-string, %, +, .format).
type Format struct {
	Parts []Expr
	Loc   string
}

// Seq is a tuple / list / array.
type Seq struct {
	Parts []Expr
	Loc   string
}

// Pair is a named key/value entry: a keyword argument (`verify=False`), a
// dict/object/hash entry (`{algorithm: "none"}`), or a struct field
// (`tls.Config{InsecureSkipVerify: true}`). Key is the literal name; taint flows
// through Value. Used by named-value matching (`val "key=value"`); frontends that
// don't emit Pair keep flattening such entries to their Value (no key).
type Pair struct {
	Key   string
	Value Expr
	Loc   string
}

// Lambda is an inline anonymous function (e.g. an Express arrow handler).
type Lambda struct {
	Params []string
	Body   []Stmt
	Loc    string
}

// Thru is a transparent wrapper (await, starred) that passes taint through.
type Thru struct{ Inner Expr }

func (Name) isExpr()   {}
func (Const) isExpr()  {}
func (Attr) isExpr()   {}
func (Index) isExpr()  {}
func (Call) isExpr()   {}
func (Format) isExpr() {}
func (Seq) isExpr()    {}
func (Pair) isExpr()   {}
func (Lambda) isExpr() {}
func (Thru) isExpr()   {}

// Stmt is the NIR statement interface (a closed set, switched on in lowering).
type Stmt interface{ isStmt() }

// Assign binds Value to each of Targets.
type Assign struct {
	Targets []string
	Value   Expr
}

// AugAssign is x += y.
type AugAssign struct {
	Target string
	Value  Expr
	Loc    string
}

// Return returns Value from the enclosing function.
type Return struct{ Value Expr }

// ExprStmt is an expression evaluated for effect.
type ExprStmt struct{ Value Expr }

// FuncDef is a function/method definition.
type FuncDef struct {
	Name   string
	Params []string
	Body   []Stmt
	Loc    string
}

// ClassDef is a class definition.
type ClassDef struct {
	Name string
	Body []Stmt
	Loc  string
}

// Block is a flattened control-flow body, processed once in scope
// (flow-approximate, like the per-language extractors).
type Block struct{ Stmts []Stmt }

func (Assign) isStmt()    {}
func (AugAssign) isStmt() {}
func (Return) isStmt()    {}
func (ExprStmt) isStmt()  {}
func (FuncDef) isStmt()   {}
func (ClassDef) isStmt()  {}
func (Block) isStmt()     {}

// Import is one import binding. Module is the target module key (source-root
// key) or file path; Symbol is set for `from m import s` (empty for plain module
// import); IsModule distinguishes `import m` (true) from `from m import s`.
type Import struct {
	Local    string
	Module   string
	Symbol   string
	IsModule bool
}

// Module is a source file with its imports and top-level body. Key is the
// source-root module key used for resolution; File is the display path.
type Module struct {
	Key     string
	File    string
	Imports []Import
	Body    []Stmt
}

// Program is a set of modules plus the receiver name used for self/this
// resolution (defaults to "self" when zero).
type Program struct {
	Modules  []Module
	SelfName string
}

// Self returns the configured receiver name, defaulting to "self".
func (p Program) Self() string {
	if p.SelfName == "" {
		return "self"
	}
	return p.SelfName
}
