package parser

type V2Program struct {
	Module string
	Uses   []V2Use
	Decls  []V2Decl
}

type V2Use struct {
	Name  string
	Alias string
}

type V2Decl interface{ isV2Decl() }

type V2ConceptDecl struct {
	Name   string
	Module string
	Kind   string
	Fields map[string]any
}

func (*V2ConceptDecl) isV2Decl() {}

type V2ThreatDecl struct {
	Name   string
	Module string
	Fields map[string]any
}

func (*V2ThreatDecl) isV2Decl() {}

type V2PatternDecl struct {
	Name  string
	Alias string
	Items []V2PatternItem
}

func (*V2PatternDecl) isV2Decl() {}
func (*V2PatternDecl) isDecl()   {}

type V2PatternItem struct {
	Kind  string
	Name  string
	Alias string
	Expr  V2Expr
	Meta  map[string]any
}

type V2MatcherDecl struct {
	Name  string
	Items []V2MatcherItem
}

func (*V2MatcherDecl) isV2Decl() {}
func (*V2MatcherDecl) isDecl()   {}

type V2MatcherItem struct {
	Kind   string
	Values []string
}

type V2BindingDecl struct {
	Name         string
	Module       string
	Requirements []V2Requirement
	Unstable     map[string]any
	Query        V2BindingQuery
	Outputs      []V2BindingOutput
	Attrs        map[string]string
}

func (*V2BindingDecl) isV2Decl() {}
func (*V2BindingDecl) isDecl()   {}

type V2Requirement struct {
	Name string
	Args []any
}

type V2NamedArg struct {
	Name  string
	Value any
}

type V2BindingQuery struct {
	Pattern string
	Expr    *V2QueryExpr
	Where   V2Expr
}

type V2BindingOutput struct {
	Kind     string
	Concept  string
	Location string
	Covers   []V2Coverage
	Advisory *bool
	About    string
	From     string
	To       string
}

type V2Coverage struct {
	Mode  string
	Items map[string]any
}

type V2RuleDecl struct {
	Name    string
	Module  string
	Meta    map[string]any
	Body    V2RuleBody
	Clauses []V2RuleClause
}

func (*V2RuleDecl) isV2Decl() {}

type V2RuleBody struct {
	Verb   string
	From   V2Endpoint
	To     V2Endpoint
	Issue  V2Endpoint
	Query  *V2QueryExpr
	Select string
}

type V2Endpoint struct {
	Concept string
	Alias   string
}

type V2RuleClause struct {
	Kind     string
	Expr     V2Expr
	Target   string
	Coverage string
	Concept  string
	Value    string
}

type V2ReviewDecl struct {
	Concept string
	Fields  map[string]any
}

func (*V2ReviewDecl) isV2Decl() {}

type V2ProfileDecl struct {
	Name   string
	Fields map[string]any
}

func (*V2ProfileDecl) isV2Decl() {}

type V2PackDecl struct {
	Name   string
	Fields map[string]any
}

func (*V2PackDecl) isV2Decl() {}

type V2MechanicDecl struct {
	Kind   string
	Name   string
	Module string
	Items  []V2BlockItem
}

type V2BlockItem struct {
	Key   []string
	Value any
	Block []V2BlockItem
	Items []V2BlockItem
}

func (*V2MechanicDecl) isV2Decl() {}
func (*V2MechanicDecl) isDecl()   {}

func (m *V2MechanicDecl) QualifiedName() string {
	if m.Module == "" {
		return "mechanic:" + m.Kind + ":" + m.Name
	}
	return m.Module + ".mechanic:" + m.Kind + ":" + m.Name
}

type V2PolicyDecl struct {
	Kind   string
	Name   string
	Module string
	Items  []V2BlockItem
}

func (*V2PolicyDecl) isV2Decl() {}
func (*V2PolicyDecl) isDecl()   {}

func (p *V2PolicyDecl) QualifiedName() string {
	if p.Module == "" {
		return "policy:" + p.Kind + ":" + p.Name
	}
	return p.Module + ".policy:" + p.Kind + ":" + p.Name
}

type V2QueryExpr struct {
	Family string
	Alias  string
	Where  V2Expr
	Steps  []V2QueryStep
}

type V2QueryStep struct {
	Relation string
	Family   string
	Alias    string
	Where    V2Expr
}

type V2Expr interface{ isV2Expr() }

type V2RefExpr struct{ Name string }
type V2LiteralExpr struct{ Value any }
type V2UnaryExpr struct {
	Op string
	X  V2Expr
}
type V2BinaryExpr struct {
	Op          string
	Left, Right V2Expr
}
type V2CallExpr struct {
	Name      string
	Args      []V2Expr
	NamedArgs []V2NamedExprArg
}
type V2NamedExprArg struct {
	Name string
	Expr V2Expr
}
type V2SequenceExpr struct{ Items []V2Expr }

func (V2RefExpr) isV2Expr()      {}
func (V2LiteralExpr) isV2Expr()  {}
func (V2UnaryExpr) isV2Expr()    {}
func (V2BinaryExpr) isV2Expr()   {}
func (V2CallExpr) isV2Expr()     {}
func (V2SequenceExpr) isV2Expr() {}
