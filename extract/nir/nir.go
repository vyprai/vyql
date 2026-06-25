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

import "encoding/gob"

// register every concrete Expr/Stmt so gob can (de)serialize the interface fields of Module
// — used by the parse cache and the incremental-lowering delta cache.
func init() {
	for _, v := range []any{
		Name{}, Const{}, Attr{}, Index{}, Call{}, Format{}, Seq{}, Pair{}, Lambda{}, Thru{},
		BinOp{}, Unary{}, Ternary{},
		Assign{}, AugAssign{}, Return{}, ExprStmt{}, FuncDef{}, ClassDef{}, Block{}, If{},
		Loop{}, Switch{}, Try{},
	} {
		gob.Register(v)
	}
}

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
	// value-matching adapters (`val "..."`, e.g. option names or modes); empty otherwise.
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

// Index is a subscript x[k]; Path is the dotted callee path. Key is the index/key
// expression (may be nil) — used for container element-sensitivity (x[a] vs x[b]).
type Index struct {
	Base Expr
	Key  Expr
	Path string
	Loc  string
}

// Call is a call expression; Path is the callee path (e.g. "db.query") and
// Method is its last segment (e.g. "query").
type Call struct {
	Callee  Expr
	Args    []Expr
	Path    string
	Method  string
	Loc     string
	Effects []CallEffect
	// IsCtor marks a constructor / `new T(args)` call: the constructed object contains its
	// arguments, so the lowerer flows tainted args into the call result (wrapper-object taint).
	IsCtor bool
}

// CallEffect is adapter-declared dataflow for calls with out-parameters or accumulator
// arguments. It is intentionally generic: adapters name the API, while lowering only
// applies "argument/result flows into destination argument".
type CallEffect struct {
	DestArg      int
	SourceArg    int
	SourceResult bool
}

// Format is a taint-propagating string build (f-string, %, +, .format).
type Format struct {
	Parts []Expr
	Loc   string
}

// Seq is a tuple / list / array.
type Seq struct {
	Parts   []Expr
	Loc     string
	KeyPath []string
}

// Pair is a named key/value entry: a keyword argument (`enabled=false`), a
// dict/object/hash entry (`{mode: "fast"}`), or a struct field
// (`Options{Limit: 10}`). Key is the literal name; taint flows
// through Value. Used by named-value matching (`val "key=value"`); frontends that
// don't emit Pair keep flattening such entries to their Value (no key).
type Pair struct {
	Key   string
	Value Expr
	Loc   string
}

// Lambda is an inline anonymous function (e.g. an Express arrow handler).
type Lambda struct {
	Params        []string
	ParamTypes    map[string]string
	ParamEntries  []ParamEntry
	Body          []Stmt
	Loc           string
	ContextTokens []string
}

// Thru is a transparent wrapper (await, starred) that passes taint through.
type Thru struct{ Inner Expr }

// BinOp is a binary arithmetic/comparison/logical operation that preserves its operator
// (e.g. `-`, `*`, `>`, `==`, `&&`). Used for compile-time constant evaluation of opaque
// branch conditions so the dead branch can be pruned. String `+` stays a Format (concat).
type BinOp struct {
	Op          string
	Left, Right Expr
	Loc         string
}

// Unary is a unary operation preserving its operator (`!`, `-`), for constant evaluation.
type Unary struct {
	Op      string
	Operand Expr
	Loc     string
}

// Ternary is a conditional expression `Cond ? Then : Else`. When Cond is a compile-time
// constant the dead arm is pruned; otherwise both arms flow (over-approximation).
type Ternary struct {
	Cond, Then, Else Expr
	Loc              string
}

func (Name) isExpr()    {}
func (Const) isExpr()   {}
func (Attr) isExpr()    {}
func (Index) isExpr()   {}
func (Call) isExpr()    {}
func (Format) isExpr()  {}
func (Seq) isExpr()     {}
func (Pair) isExpr()    {}
func (Lambda) isExpr()  {}
func (Thru) isExpr()    {}
func (BinOp) isExpr()   {}
func (Unary) isExpr()   {}
func (Ternary) isExpr() {}

// Stmt is the NIR statement interface (a closed set, switched on in lowering).
type Stmt interface{ isStmt() }

// Assign binds Value to each of Targets. Type is the DECLARED type name when the
// frontend knows it (e.g. Java `UserService svc = …` or an uninitialized field
// `UserService svc;`), enabling cross-file method resolution on the variable even
// without a constructor on the RHS; empty when unknown.
type Assign struct {
	Targets []string
	Value   Expr
	Type    string
	Decl    bool // true when this assignment came from a declaration (let/const/var, etc.)
	Loc     string
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
	Name       string
	Params     []string
	ParamTypes map[string]string
	Body       []Stmt
	Loc        string
	// ContextTokens records syntax-level evidence attached to the enclosing function
	// itself (for example its name or language-native annotations). Lowering preserves
	// these on generic function-return events; adapters decide what any token means.
	ContextTokens []string
	// Decorators records syntax-level annotation/decorator tokens attached to this function.
	// Lowering preserves them on generic function-return events; adapters decide what any
	// specific decorator means for a domain.
	Decorators []string
	// ParamEntries records syntax-level evidence that a parameter is populated by an
	// external caller or framework. Lowering emits generic parameter-entry events from this
	// data; adapters decide which events are source concepts.
	ParamEntries []ParamEntry
	// ResultEntries records syntax-level evidence attached to values returned by this
	// function. Lowering emits generic result events; adapters decide which events are
	// controls, sinks, or other domain concepts.
	ResultEntries []ResultEntry
	// Exported marks a function/method as part of the PUBLIC API surface (per the
	// language's visibility rules: Go capitalization, `pub`, `public`, `export`, no
	// leading underscore, …). The library/SDK archetype treats exported-function
	// parameters as an external-entry taint source; internal helpers are reached by
	// ordinary interprocedural propagation, so they must NOT be entry points.
	Exported bool
}

type ParamEntry struct {
	Param  string
	Tokens []string
}

type ResultEntry struct {
	Tokens []string
}

// ClassDef is a class definition.
type ClassDef struct {
	Name string
	Body []Stmt
	Loc  string
	// Bases are the base class / interface short names (generics stripped) — used for
	// inheritance-aware implicit-`this` member resolution.
	Bases []string
	// Members are the data-member names (fields + properties) declared on this class, so a
	// bare member reference inside a method can be resolved to `this.<member>`.
	Members []string
}

// Block is a flattened control-flow body, processed once in scope
// (flow-approximate, like the per-language extractors).
type Block struct{ Stmts []Stmt }

// Structured control-flow nodes (B1 / WS0). Frontends emit these instead of a flat
// Block when they preserve branch structure; the lowering builds a real CFG (CONTROL
// edges) from them under VYQL_CFG. With the flag off — or for a frontend that hasn't
// been converted — they are lowered like a Block (flatten), so they are fully additive
// and behaviour-preserving. Cond is retained for taint and (later) path feasibility.
type If struct {
	Cond Expr
	Then []Stmt
	Else []Stmt
	Loc  string
}

// Loop covers while/for/foreach. Cond may be nil for infinite/range loops.
// Iter/Vars are optional foreach/range metadata: values from Iter may bind to
// each variable in Vars before the loop body.
type Loop struct {
	Cond Expr
	Iter Expr
	Vars []string
	Body []Stmt
	Loc  string
}

// Switch is a multi-way branch: each Cases entry is one arm's body, Default the fallthrough.
// Labels[i] holds the case-label expressions for Cases[i] (parallel slice; empty when the
// frontend doesn't capture them) — used to prune to the matching arm when Subject is constant.
type Switch struct {
	Subject Expr
	Cases   [][]Stmt
	Labels  [][]Expr
	Default []Stmt
	Loc     string
}

// Try models exception control flow: Body, zero+ Handlers (catch/except bodies), Finally.
type Try struct {
	Body     []Stmt
	Handlers [][]Stmt
	Finally  []Stmt
	Loc      string
}

func (Assign) isStmt()    {}
func (AugAssign) isStmt() {}
func (Return) isStmt()    {}
func (ExprStmt) isStmt()  {}
func (FuncDef) isStmt()   {}
func (ClassDef) isStmt()  {}
func (Block) isStmt()     {}
func (If) isStmt()        {}
func (Loop) isStmt()      {}
func (Switch) isStmt()    {}
func (Try) isStmt()       {}

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
	// Hash is a content hash of the source file this module was parsed from (set by the
	// frontend). It identifies the module's parse result for the incremental lowering cache;
	// empty means "not content-addressed" (e.g. the native Go frontend) → always re-lowered.
	Hash string
	// CacheKey is TRANSIENT (excluded from gob via being set only post-decode): when a module is
	// returned as a stub (Body/Imports nil, to skip decoding an unchanged file), it carries the
	// parse cache's content key so the lowerer can decode the full NIR on demand if a signature
	// change elsewhere invalidates this module's cached body sub-graph.
	CacheKey string
}

// Program is a set of modules plus the receiver name used for self/this
// resolution (defaults to "self" when zero).
type Program struct {
	Modules  []Module
	SelfName string
	// Properties holds resolved key→value pairs from bundled config files
	// (.properties, etc.), so a config-read like `getProperty("featureMode")` can be
	// const-folded to its real value during lowering.
	Properties map[string]string
}

// Self returns the configured receiver name, defaulting to "self".
func (p Program) Self() string {
	if p.SelfName == "" {
		return "self"
	}
	return p.SelfName
}
