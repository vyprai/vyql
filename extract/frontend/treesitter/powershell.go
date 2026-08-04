package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	psl "github.com/vyprai/vyql/extract/frontend/treesitter/grammars/powershell"

	"github.com/vyprai/vyql/extract/nir"
)

// psConv walks a tree-sitter PowerShell CST into NIR. PowerShell wraps every
// expression in a deep precedence cascade (logical→bitwise→…→unary); psUnwrap
// peels those single-child wrappers to the meaningful node. A `command` is a Call
// (cmdlet name -> path, elements -> args); expandable strings ("ping $x")
// propagate taint.
type psConv struct {
	src        []byte
	file       string
	key        string
	childCache map[uintptr][]*tree_sitter.Node
}

func (c *psConv) namedChildren(n *tree_sitter.Node) []*tree_sitter.Node {
	if n == nil {
		return nil
	}
	if c.childCache == nil {
		c.childCache = make(map[uintptr][]*tree_sitter.Node)
	}
	key := uintptr(n.Id())
	if kids, ok := c.childCache[key]; ok {
		return kids
	}
	kids := namedChildren(n)
	c.childCache[key] = kids
	return kids
}

// psWrappers are single-child expression-precedence nodes to peel through.
// Only peeled when single-child (psUnwrap guards len==1), so a 2-operand
// additive_expression (string concat) is preserved and handled as Format.
var psWrappers = map[string]bool{
	"logical_expression": true, "bitwise_expression": true, "comparison_expression": true,
	"multiplicative_expression": true, "format_expression": true, "range_expression": true,
	"array_literal_expression": true, "unary_expression": true, "expression": true,
	"pipeline": true, "logical_expression_operand": true, "post_increment_expression": true,
	"additive_expression": true, "left_assignment_expression": true,
}

// ExtractPowerShell parses .ps1/.psm1 files into one NIR Program.
func ExtractPowerShell(files []string, root string) (nir.Program, error) {
	mods := parseModules(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(tree_sitter.NewLanguage(psl.Language()))
			return p
		},
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			c := &psConv{src: src, file: rel, key: moduleKey(root, abs, ".ps1")}
			return nir.Module{Key: c.key, File: rel, Body: c.program(tree.RootNode())}, true
		})
	return nir.Program{SelfName: "this", Modules: mods}, nil
}

func (c *psConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *psConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

// psUnwrap peels single-child precedence wrappers to the meaningful node.
func (c *psConv) psUnwrap(n *tree_sitter.Node) *tree_sitter.Node {
	for n != nil && psWrappers[n.Kind()] {
		k := c.namedChildren(n)
		if len(k) != 1 {
			break
		}
		n = k[0]
	}
	return n
}

func (c *psConv) program(root *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	// Top-level param() block entries are emitted as neutral parameter-entry events.
	for _, ch := range c.namedChildren(root) {
		if ch.Kind() == "param_block" {
			for _, p := range c.paramNames(ch) {
				out = append(out, nir.Assign{Targets: []string{p},
					Value: nir.Call{
						Callee: nir.Name{ID: "analysis.parameter.entry", Loc: c.loc(ch)},
						Args: []nir.Expr{
							nir.Const{Loc: c.loc(ch), Value: "entry_kind:script_param"},
							nir.Const{Loc: c.loc(ch), Value: "param_name:" + p},
						},
						Path:   "analysis.parameter.entry",
						Method: "entry",
						Loc:    c.loc(ch),
					}})
			}
		}
	}
	out = append(out, c.stmtList(root)...)
	return out
}

func (c *psConv) stmtList(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range c.namedChildren(m) {
			switch ch.Kind() {
			case "statement_list", "script_block", "script_block_body", "named_block":
				walk(ch)
			default:
				out = append(out, c.stmt(ch)...)
			}
		}
	}
	walk(n)
	return out
}

func (c *psConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	switch n.Kind() {
	case "function_statement":
		params, paramTypes := c.functionParams(n)
		return []nir.Stmt{nir.FuncDef{Name: c.functionName(n), Params: params, ParamTypes: paramTypes, Body: c.stmtList(n), Loc: c.loc(n)}}
	case "pipeline", "statement":
		inner := c.psUnwrap(n)
		if inner != n {
			return c.stmt(inner)
		}
		// a pipeline of commands
		var out []nir.Stmt
		for _, ch := range c.namedChildren(n) {
			out = append(out, c.stmt(ch)...)
		}
		return out
	case "assignment_expression":
		left := c.psUnwrap(field(n, "left"))
		if left == nil {
			if k := c.namedChildren(n); len(k) > 0 {
				left = c.psUnwrap(k[0])
			}
		}
		val := c.expr(field(n, "value"))
		if left != nil && left.Kind() == "variable" {
			return []nir.Stmt{nir.Assign{Targets: []string{c.varName(left)}, Value: val}}
		}
		return []nir.Stmt{nir.ExprStmt{Value: val}}
	case "command":
		return []nir.Stmt{nir.ExprStmt{Value: c.command(n)}}
	// branch-structured with predicate attached so constant-false arms are pruned.
	case "if_statement":
		return []nir.Stmt{c.psIf(n)}
	case "while_statement", "for_statement", "foreach_statement", "do_statement":
		return []nir.Stmt{nir.Loop{Body: c.collectBlocks(n)}}
	case "try_statement":
		return []nir.Stmt{nir.Try{Body: c.collectBlocks(n)}}
	case "switch_statement":
		return []nir.Stmt{c.psSwitch(n)}
	case "trap_statement":
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	}
	// unwrap & retry, else treat as an expression statement
	if u := c.psUnwrap(n); u != n {
		return c.stmt(u)
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.outputCall(n, c.expr(n))}}
}

func (c *psConv) outputCall(n *tree_sitter.Node, value nir.Expr) nir.Call {
	L := c.loc(n)
	raw := c.text(n)
	recovered := c.psRecoverGeneratedPayload([]nir.Expr{value}, raw, L)
	if len(recovered) > 1 {
		value = nir.Format{Parts: recovered, Loc: L}
	}
	return nir.Call{
		Callee: nir.Name{ID: "powershell.output", Loc: L},
		Args: []nir.Expr{
			value,
			nir.Const{Loc: L, Value: "expr:" + raw},
		},
		Path:   "powershell.output",
		Method: "output",
		Loc:    L,
	}
}

// psCmpMap maps PowerShell word-operators to C-style symbols const-eval understands.
var psCmpMap = map[string]string{
	"-gt": ">", "-lt": "<", "-ge": ">=", "-le": "<=", "-eq": "==", "-ne": "!=",
	"-and": "&&", "-or": "||",
}

// psCmpToken finds the operator of a comparison/logical node (a word-op token or a
// C-style symbol), normalising `-gt`→`>` etc.
func (c *psConv) psCmpToken(n *tree_sitter.Node) string {
	for i := uint(0); i < n.ChildCount(); i++ {
		t := strings.ToLower(c.text(n.Child(i)))
		if m, ok := psCmpMap[t]; ok {
			return m
		}
		switch t {
		case ">", "<", ">=", "<=", "==", "!=", "&&", "||":
			return t
		}
	}
	return "?"
}

// psIf lowers an if with its predicate so a constant-false arm is pruned, recursing into
// the then/else statement_block (which collectBlocks did not descend — a latent FN).
func (c *psConv) psIf(n *tree_sitter.Node) nir.Stmt {
	it := nir.If{Loc: c.loc(n)}
	if cond := field(n, "condition"); cond != nil {
		it.Cond = c.expr(cond)
	}
	for _, ch := range c.namedChildren(n) {
		switch ch.Kind() {
		case "statement_block":
			if it.Then == nil {
				it.Then = c.psBlock(ch)
			}
		case "else_clause":
			for _, e := range c.namedChildren(ch) {
				if e.Kind() == "statement_block" {
					it.Else = append(it.Else, c.psBlock(e)...)
				}
			}
		case "elseif_clause":
			it.Else = append(it.Else, c.stmt(ch)...)
		}
	}
	return it
}

// psSwitch lowers a switch to subject+labelled branches so a constant subject prunes
// the non-matching clauses (instead of flattening, which let a later clause mask a live
// one — and dropped the clause bodies' statement_block, an FN).
func (c *psConv) psSwitch(n *tree_sitter.Node) nir.Stmt {
	sw := nir.Switch{Loc: c.loc(n)}
	if cond := lastChildKind(n, "switch_condition"); cond != nil {
		if k := c.namedChildren(cond); len(k) > 0 {
			sw.Subject = c.expr(k[0])
		}
	}
	body := lastChildKind(n, "switch_body")
	if body == nil {
		return sw
	}
	clauses := lastChildKind(body, "switch_clauses")
	if clauses == nil {
		return sw
	}
	for _, cl := range c.namedChildren(clauses) {
		if cl.Kind() != "switch_clause" {
			continue
		}
		condN := lastChildKind(cl, "switch_clause_condition")
		stmts := c.psBlock(lastChildKind(cl, "statement_block"))
		if condN == nil || strings.EqualFold(c.text(condN), "default") {
			sw.Default = append(sw.Default, stmts...)
		} else {
			sw.Cases = append(sw.Cases, stmts)
			sw.Labels = append(sw.Labels, []nir.Expr{c.expr(condN)})
		}
	}
	return sw
}

// psBlock lowers the statements inside a statement_block.
func (c *psConv) psBlock(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range c.namedChildren(m) {
			switch ch.Kind() {
			case "statement_block", "statement_list", "named_block", "script_block", "script_block_body":
				walk(ch)
			default:
				out = append(out, c.stmt(ch)...)
			}
		}
	}
	walk(n)
	return out
}

func (c *psConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "statement_block", "script_block", "script_block_body", "statement_list", "named_block",
				"else_clause", "elseif_clause", "catch_clause", "finally_clause":
				walk(ch)
			case "command", "pipeline", "assignment_expression", "if_statement",
				"while_statement", "foreach_statement", "for_statement":
				out = append(out, c.stmt(ch)...)
			}
		}
	}
	walk(n)
	return out
}

func (c *psConv) paramNames(n *tree_sitter.Node) []string {
	var out []string
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range c.namedChildren(m) {
			if ch.Kind() == "variable" {
				out = append(out, c.varName(ch))
			} else {
				walk(ch)
			}
		}
	}
	walk(n)
	return out
}

func (c *psConv) functionParams(n *tree_sitter.Node) ([]string, map[string]string) {
	if pb := c.findParamBlock(n); pb != nil {
		return c.paramNames(pb), c.paramTypes(pb)
	}
	return nil, map[string]string{}
}

func (c *psConv) paramTypes(n *tree_sitter.Node) map[string]string {
	out := map[string]string{}
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		if name := c.directVarName(m); name != "" {
			typ := paramTypeFromField(c, m)
			if typ == "" {
				typ = psBracketType(c.text(m))
			}
			putParamType(out, name, typ)
		}
		for _, ch := range c.namedChildren(m) {
			if ch.Kind() == "parameter" || ch.Kind() == "parameter_declaration" || ch.Kind() == "variable" {
				name := ""
				if v := field(ch, "name"); v != nil {
					name = c.varName(v)
				}
				if name == "" {
					for _, cc := range c.namedChildren(ch) {
						if cc.Kind() == "variable" {
							name = c.varName(cc)
							break
						}
					}
				}
				if name == "" && ch.Kind() == "variable" {
					name = c.varName(ch)
				}
				putParamType(out, name, paramTypeFromField(c, ch))
				if name != "" {
					continue
				}
			}
			walk(ch)
		}
	}
	walk(n)
	return out
}

func (c *psConv) functionName(n *tree_sitter.Node) string {
	if name := c.text(field(n, "name")); name != "" {
		return name
	}
	for _, ch := range c.namedChildren(n) {
		switch ch.Kind() {
		case "command_name", "function_name", "identifier":
			return c.text(ch)
		case "script_block", "script_block_body", "statement_list":
			continue
		}
	}
	parts := strings.Fields(c.text(n))
	if len(parts) >= 2 && strings.EqualFold(parts[0], "function") {
		return strings.TrimSpace(parts[1])
	}
	return ""
}

func (c *psConv) findParamBlock(n *tree_sitter.Node) *tree_sitter.Node {
	if n == nil {
		return nil
	}
	for _, ch := range c.namedChildren(n) {
		if ch.Kind() == "param_block" {
			return ch
		}
		if got := c.findParamBlock(ch); got != nil {
			return got
		}
	}
	return nil
}

func (c *psConv) directVarName(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	if n.Kind() == "variable" {
		return c.varName(n)
	}
	for _, ch := range c.namedChildren(n) {
		if ch.Kind() == "variable" {
			return c.varName(ch)
		}
	}
	return ""
}

func psBracketType(s string) string {
	start := strings.Index(s, "[")
	end := strings.Index(s, "]")
	if start < 0 || end <= start {
		return ""
	}
	return s[start : end+1]
}

// command models a cmdlet/program call: command_name -> path, the
// array_literal_expression elements -> args (skipping separators).
func (c *psConv) command(n *tree_sitter.Node) nir.Expr {
	L := c.loc(n)
	name := lastSeg(strings.TrimPrefix(c.text(field(n, "command_name")), "&"))
	if name == "" {
		// `& "cmd"` invocation-operator form
		name = "&"
	}
	var args []nir.Expr
	if el := field(n, "command_elements"); el != nil {
		for _, ch := range c.namedChildren(el) {
			if ch.Kind() == "command_argument_sep" || ch.Kind() == "command_name" {
				continue
			}
			args = append(args, c.expr(ch))
		}
	}
	// Command binding applicators inspect arg0; collapse all command elements into one
	// taint-carrying Format so no argument position is dropped.
	var callArgs []nir.Expr
	if len(args) > 0 {
		callArgs = []nir.Expr{nir.Format{Parts: args, Loc: L}}
	}
	return nir.Call{Callee: nir.Name{ID: name, Loc: L}, Args: callArgs, Path: name, Method: name, Loc: L}
}

func (c *psConv) varName(n *tree_sitter.Node) string {
	return strings.TrimPrefix(c.text(n), "$")
}

func (c *psConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	n = c.psUnwrap(n)
	L := c.loc(n)
	switch n.Kind() {
	case "variable":
		if event, ok := sourceVarEvent("powershell", c.varName(n)); ok {
			return nir.Call{Callee: nir.Name{ID: event, Loc: L}, Path: event, Method: event, Loc: L}
		}
		return nir.Name{ID: c.varName(n), Loc: L}
	case "integer_literal", "decimal_integer_literal", "real_literal", "boolean":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "string_literal", "verbatim_string_characters", "expandable_string_literal", "literal_expression":
		if n.Kind() == "literal_expression" && strings.TrimSpace(c.text(n)) == "payload" {
			return nir.Name{ID: "payload", Loc: L}
		}
		var parts []nir.Expr
		var walk func(m *tree_sitter.Node)
		walk = func(m *tree_sitter.Node) {
			for _, ch := range c.namedChildren(m) {
				if ch.Kind() == "variable" || ch.Kind() == "sub_expression" {
					parts = append(parts, c.expr(ch))
				} else {
					walk(ch)
				}
			}
		}
		walk(n)
		if len(parts) > 0 {
			return nir.Format{Parts: parts, Loc: L}
		}
		return nir.Const{Loc: L, Value: psLiteralValue(c.text(n))}
	case "additive_expression":
		var parts []nir.Expr
		for _, ch := range c.namedChildren(n) {
			parts = append(parts, c.expr(ch))
		}
		parts = c.psRecoverGeneratedPayload(parts, c.text(n), L)
		return nir.Format{Parts: parts, Loc: L}
	case "comparison_expression", "logical_expression", "bitwise_expression":
		// reached only with 2 operands (single-child wrappers are peeled by psUnwrap);
		// map PowerShell's `-gt`/`-lt`/… to C-style operators so const-eval can fold.
		// The operator may itself be a named child, so take the first and last operands.
		k := c.namedChildren(n)
		if len(k) >= 2 {
			if op := c.psWordOperator(n); op == "-replace" || op == "-creplace" || op == "-ireplace" {
				return nir.Call{
					Callee: nir.Name{ID: "powershell.replace", Loc: L},
					Args:   []nir.Expr{c.expr(k[0]), c.expr(k[len(k)-1])},
					Path:   "powershell.replace",
					Method: "replace",
					Loc:    L,
				}
			}
			return nir.BinOp{Op: c.psCmpToken(n), Left: c.expr(k[0]), Right: c.expr(k[len(k)-1]), Loc: L}
		}
	case "unary_expression":
		k := c.namedChildren(n)
		if len(k) >= 1 {
			op := "?"
			for i := uint(0); i < n.ChildCount(); i++ {
				if ch := n.Child(i); !ch.IsNamed() {
					op = c.text(ch)
					break
				}
			}
			return nir.Unary{Op: op, Operand: c.expr(k[len(k)-1]), Loc: L}
		}
	case "command":
		return c.command(n)
	case "command_invokation_operator", "sub_expression", "parenthesized_expression":
		if k := c.namedChildren(n); len(k) > 0 {
			return c.expr(k[len(k)-1])
		}
	case "member_access":
		base := c.namedChildren(n)
		if len(base) > 0 {
			return nir.Attr{Base: c.expr(base[0]), Attr: c.psMemberName(n), Path: c.dotted(n), Loc: L}
		}
	case "invokation_expression":
		if k := c.namedChildren(n); len(k) > 0 {
			path := c.dotted(k[0])
			if invokePath := c.psInvokePathFromText(n); invokePath != "" {
				path = invokePath
			}
			if path == "?" {
				if staticPath := c.psStaticPath(n); staticPath != "" {
					path = staticPath
				}
			}
			return nir.Call{Callee: c.expr(k[0]), Args: c.psInvokeArgs(n), Path: path, Method: lastSeg(path), Loc: L}
		}
	}
	var parts []nir.Expr
	for _, ch := range c.namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return nir.Seq{Parts: parts, Loc: L}
}

func (c *psConv) psRecoverGeneratedPayload(parts []nir.Expr, raw, loc string) []nir.Expr {
	if !strings.Contains(raw, "payload") || psExprHasName(parts, "payload") {
		return parts
	}
	if strings.Contains(raw, "payload.replace") {
		return append(parts, nir.Call{
			Callee: nir.Name{ID: "powershell.replace", Loc: loc},
			Args: []nir.Expr{
				nir.Name{ID: "payload", Loc: loc},
				nir.Const{Loc: loc, Value: raw},
			},
			Path:   "powershell.replace",
			Method: "replace",
			Loc:    loc,
		})
	}
	return append(parts, nir.Name{ID: "payload", Loc: loc})
}

func psExprHasName(exprs []nir.Expr, name string) bool {
	for _, expr := range exprs {
		if psExprContainsName(expr, name) {
			return true
		}
	}
	return false
}

func psExprContainsName(expr nir.Expr, name string) bool {
	switch v := expr.(type) {
	case nir.Name:
		return v.ID == name
	case nir.Call:
		return psExprContainsName(v.Callee, name) || psExprHasName(v.Args, name)
	case nir.Format:
		return psExprHasName(v.Parts, name)
	case nir.Seq:
		return psExprHasName(v.Parts, name)
	case nir.BinOp:
		return psExprContainsName(v.Left, name) || psExprContainsName(v.Right, name)
	case nir.Unary:
		return psExprContainsName(v.Operand, name)
	case nir.Attr:
		return psExprContainsName(v.Base, name)
	case nir.Index:
		return psExprContainsName(v.Base, name) || psExprContainsName(v.Key, name)
	case nir.Thru:
		return psExprContainsName(v.Inner, name)
	case nir.Ternary:
		return psExprContainsName(v.Cond, name) || psExprContainsName(v.Then, name) || psExprContainsName(v.Else, name)
	default:
		return false
	}
}

func (c *psConv) psWordOperator(n *tree_sitter.Node) string {
	for i := uint(0); i < n.ChildCount(); i++ {
		t := strings.ToLower(strings.TrimSpace(c.text(n.Child(i))))
		if strings.HasPrefix(t, "-") {
			return t
		}
	}
	return ""
}

func psLiteralValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) >= 2 {
		if q := raw[0]; (q == '"' || q == '\'') && raw[len(raw)-1] == q {
			return raw[1 : len(raw)-1]
		}
	}
	return raw
}

func (c *psConv) psInvokeArgs(n *tree_sitter.Node) []nir.Expr {
	var out []nir.Expr
	if a := field(n, "arguments"); a != nil {
		for _, ch := range c.namedChildren(a) {
			out = append(out, c.expr(ch))
		}
		return out
	}
	if parsed := c.psInvokeArgsFromText(n); len(parsed) > 0 {
		return parsed
	}
	kids := c.namedChildren(n)
	for i, ch := range kids {
		if i == 0 {
			continue
		}
		if ch.Kind() == "argument_list" {
			for _, arg := range c.namedChildren(ch) {
				out = append(out, c.expr(arg))
			}
			continue
		}
		out = append(out, c.expr(ch))
	}
	return out
}

func (c *psConv) psInvokeArgsFromText(n *tree_sitter.Node) []nir.Expr {
	raw := strings.TrimSpace(c.text(n))
	open := strings.Index(raw, "(")
	close := strings.LastIndex(raw, ")")
	if open < 0 || close <= open {
		return nil
	}
	var out []nir.Expr
	for _, part := range psSplitArgs(raw[open+1 : close]) {
		if expr, ok := c.psExprFromText(part, c.loc(n)); ok {
			out = append(out, expr)
		}
	}
	return out
}

func psSplitArgs(raw string) []string {
	var out []string
	start := 0
	depth := 0
	quote := rune(0)
	for i, r := range raw {
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(raw[start:i]))
				start = i + len(string(r))
			}
		}
	}
	out = append(out, strings.TrimSpace(raw[start:]))
	return out
}

func (c *psConv) psExprFromText(raw, loc string) (nir.Expr, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, false
	}
	if strings.Contains(raw, "+") {
		var parts []nir.Expr
		for _, part := range strings.Split(raw, "+") {
			if expr, ok := c.psExprFromText(part, loc); ok {
				parts = append(parts, expr)
			}
		}
		if len(parts) > 0 {
			return nir.Format{Parts: parts, Loc: loc}, true
		}
	}
	if strings.HasPrefix(raw, "$") {
		name := strings.TrimPrefix(raw, "$")
		if strings.EqualFold(name, "true") || strings.EqualFold(name, "false") {
			return nir.Const{Loc: loc, Value: strings.ToLower(name)}, true
		}
		parts := strings.Split(name, ".")
		expr := nir.Expr(nir.Name{ID: parts[0], Loc: loc})
		path := parts[0]
		for _, attr := range parts[1:] {
			attr = strings.TrimSpace(attr)
			if attr == "" {
				continue
			}
			path += "." + attr
			expr = nir.Attr{Base: expr, Attr: attr, Path: path, Loc: loc}
		}
		return expr, true
	}
	if len(raw) >= 2 {
		if q := raw[0]; (q == '\'' || q == '"') && raw[len(raw)-1] == q {
			return nir.Const{Loc: loc, Value: raw[1 : len(raw)-1]}, true
		}
	}
	return nir.Const{Loc: loc, Value: raw}, true
}

func (c *psConv) psMemberName(n *tree_sitter.Node) string {
	if m := field(n, "member"); m != nil {
		return c.text(m)
	}
	raw := strings.TrimSpace(c.text(n))
	if i := strings.LastIndex(raw, "."); i >= 0 && i+1 < len(raw) {
		return strings.TrimSpace(raw[i+1:])
	}
	kids := c.namedChildren(n)
	if len(kids) > 1 {
		return strings.TrimSpace(c.text(kids[len(kids)-1]))
	}
	return ""
}

func (c *psConv) dotted(n *tree_sitter.Node) string {
	n = c.psUnwrap(n)
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "variable":
		return c.varName(n)
	case "member_access":
		base := c.namedChildren(n)
		if len(base) > 0 {
			return c.dotted(base[0]) + "." + c.psMemberName(n)
		}
	case "command":
		return lastSeg(c.text(field(n, "command_name")))
	}
	if path := c.psStaticPath(n); path != "" {
		return path
	}
	return "?"
}

func (c *psConv) psStaticPath(n *tree_sitter.Node) string {
	raw := strings.TrimSpace(c.text(n))
	if !strings.Contains(raw, "::") {
		return ""
	}
	if i := strings.Index(raw, "("); i >= 0 {
		raw = raw[:i]
	}
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.ReplaceAll(raw, "]::", ".")
	raw = strings.ReplaceAll(raw, "::", ".")
	raw = strings.ReplaceAll(raw, "[", "")
	raw = strings.ReplaceAll(raw, "]", "")
	raw = strings.Trim(raw, " \t\r\n")
	if raw == "" || strings.ContainsAny(raw, " \t\r\n") {
		return ""
	}
	return raw
}

func (c *psConv) psInvokePathFromText(n *tree_sitter.Node) string {
	raw := strings.TrimSpace(c.text(n))
	if !strings.Contains(raw, "(") {
		return ""
	}
	if staticPath := c.psStaticPath(n); staticPath != "" {
		return staticPath
	}
	raw = strings.TrimSpace(raw[:strings.Index(raw, "(")])
	raw = strings.TrimPrefix(raw, "$")
	if raw == "" || !strings.Contains(raw, ".") || strings.ContainsAny(raw, " \t\r\n") {
		return ""
	}
	return raw
}
