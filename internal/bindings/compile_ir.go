package bindings

// The compiled form of an authored v2 binding: what the graph labeler consumes.
//
// These types described the binding layer while living in internal/parser, which made the
// syntax package the owner of Layer-3's data model -- three extract frontends and the CLI
// imported the parser to reach them.

// Set is the compiled v2 binding set for one technology. Binding
// declarations in modules such as bindings.javascript.express compile into
// graph-labeling actions.
type Set struct {
	Name     string
	Meta     map[string]any
	Mappings []Action
}

// Action is one compiled action produced from a v2 binding.
type Action struct {
	Kind             string   // compiled v2 action family consumed by the graph labeler
	NodeType         string   // optional USG node type filter, e.g. code.Attr for memberAccess
	Pattern          string   // the callee path / method token (a string literal or dotted name)
	Concept          string   // the concept it maps to (qualified); for "type", the type name
	Constraint       string   // optional `on <type>` receiver-type constraint for sinks
	ArgIndex         int      // which argument position is targeted (default 0; `arg N`)
	ArgCountSet      bool     // true when ArgCountMin/ArgCountMax constrain call arity
	ArgCountMin      int      // minimum call arity when ArgCountSet is true; -1 = none
	ArgCountMax      int      // maximum call arity when ArgCountSet is true; -1 = none
	ValMatches       []string // required argument/option literal substrings (AND)
	ValAbsents       []string // forbidden argument/option literal substrings (AND)
	ScopePredicates  []PresencePredicate
	Packages         []string // dependency requirements required for the binding to fire
	Requirement      *Requirement
	Fidelity         string // authored binding evidence fidelity: syntactic, resolved, or semantic
	Confidence       string // authored binding evidence confidence: low, medium, or high
	Collection       bool   // also flag a Seq/collection-literal arg
	CollectionFirst  bool   // target element 0 of a Seq/collection arg when present
	CollectionIndex  int    // collection target index; defaults to 0 when CollectionFirst is set
	Exact            bool   // exact path match
	About            string // advisory/check target concept
	FlowDestArg      int    // value-propagation destination out-param argument index
	FlowSourceArg    int    // value-propagation source argument index; -1 when source is the call result
	FlowSourceResult bool   // call result flows into destination out-param
	FlowIdentity     bool   // destination aliases the source node instead of receiving a taint join
	FlowReceiver     bool   // receiver propagates to call result for fluent APIs
	Advisory         bool   // advisory check evidence; must not suppress findings
	Coverage         string // v2 coverage mode for advisory check evidence
	CoverageDetail   map[string]string
	Flag             *Presence
}

// Requirement is the compiled v2 project-prerequisite expression for a
// binding. It is evaluated once per binding application against indexed project
// evidence, not once per candidate node.
type Requirement struct {
	Op    string // dependency, import, language, file, framework, schema, all, any, not, soft
	Value string
	Range string
	Args  []Requirement
}

// Presence is an AST/graph-shaped presence annotation produced by v2
// presenceNode bindings.
type Presence struct {
	NodeKind   string
	Scope      string
	Predicates []PresencePredicate
	Operands   []PresenceOperand
}

type PresencePredicate struct {
	Subject  string
	Property string
	Op       string
	Values   []string
	Exact    bool
	Negative bool
}

type PresenceOperand struct {
	Predicates []PresencePredicate
}
