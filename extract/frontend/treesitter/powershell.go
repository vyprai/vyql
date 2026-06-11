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
// (cmdlet name → path, elements → args); $env:CGI vars and param() parameters are
// sources; expandable strings ("ping $x") propagate taint.
type psConv struct {
	src  []byte
	file string
	key  string
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
	parser := tree_sitter.NewParser()
	defer parser.Close()
	_ = parser.SetLanguage(tree_sitter.NewLanguage(psl.Language()))

	var prog nir.Program
	prog.SelfName = "this"
	for _, f := range files {
		src, err := readFile(f)
		if err != nil {
			continue
		}
		tree := parser.Parse(src, nil)
		if tree == nil {
			continue
		}
		rel := relPath(root, f)
		c := &psConv{src: src, file: rel, key: moduleKey(root, f, ".ps1")}
		prog.Modules = append(prog.Modules, nir.Module{Key: c.key, File: rel, Body: c.program(tree.RootNode())})
		tree.Close()
	}
	return prog, nil
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
		k := namedChildren(n)
		if len(k) != 1 {
			break
		}
		n = k[0]
	}
	return n
}

func (c *psConv) program(root *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	// top-level param() block → seed parameters as user input
	for _, ch := range namedChildren(root) {
		if ch.Kind() == "param_block" {
			for _, p := range c.paramNames(ch) {
				out = append(out, nir.Assign{Targets: []string{p},
					Value: nir.Call{Callee: nir.Name{ID: "http_input"}, Path: "http_input", Method: "http_input", Loc: c.loc(ch)}})
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
		for _, ch := range namedChildren(m) {
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
		return []nir.Stmt{nir.FuncDef{Name: c.text(field(n, "name")), Params: nil, Body: c.stmtList(n), Loc: c.loc(n)}}
	case "pipeline", "statement":
		inner := c.psUnwrap(n)
		if inner != n {
			return c.stmt(inner)
		}
		// a pipeline of commands
		var out []nir.Stmt
		for _, ch := range namedChildren(n) {
			out = append(out, c.stmt(ch)...)
		}
		return out
	case "assignment_expression":
		left := c.psUnwrap(field(n, "left"))
		if left == nil {
			if k := namedChildren(n); len(k) > 0 {
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
	// branch-structured (B1); Cond nil (PowerShell did not evaluate the predicate) -> byte-identical.
	case "if_statement":
		return []nir.Stmt{nir.If{Then: c.collectBlocks(n)}}
	case "while_statement", "for_statement", "foreach_statement", "do_statement":
		return []nir.Stmt{nir.Loop{Body: c.collectBlocks(n)}}
	case "try_statement":
		return []nir.Stmt{nir.Try{Body: c.collectBlocks(n)}}
	case "switch_statement", "trap_statement":
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	}
	// unwrap & retry, else treat as an expression statement
	if u := c.psUnwrap(n); u != n {
		return c.stmt(u)
	}
	if n.Kind() == "variable" || n.Kind() == "string_literal" {
		return nil
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
}

func (c *psConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "script_block", "script_block_body", "statement_list", "named_block",
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
		for _, ch := range namedChildren(m) {
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
		for _, ch := range namedChildren(el) {
			if ch.Kind() == "command_argument_sep" || ch.Kind() == "command_name" {
				continue
			}
			args = append(args, c.expr(ch))
		}
	}
	// A shell command's danger can be in ANY argument position (e.g.
	// Start-Process "cmd" $userArg), so collapse all args into one taint-carrying
	// Format that the sink (arg0) inspects.
	var callArgs []nir.Expr
	if len(args) > 0 {
		callArgs = []nir.Expr{nir.Format{Parts: args, Loc: L}}
	}
	return nir.Call{Callee: nir.Name{ID: name, Loc: L}, Args: callArgs, Path: name, Method: name, Loc: L}
}

// shSourcePSVar: $env:QUERY_STRING / $env:HTTP_* etc. are untrusted input.
func psSourceVar(name string) bool {
	n := strings.TrimPrefix(strings.ToUpper(name), "ENV:")
	for _, p := range []string{"QUERY_STRING", "HTTP_", "REQUEST_", "CONTENT_", "PATH_INFO", "REMOTE_"} {
		if n == p || strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
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
		if psSourceVar(c.varName(n)) {
			return nir.Call{Callee: nir.Name{ID: "shell_input", Loc: L}, Path: "shell_input", Method: "shell_input", Loc: L}
		}
		return nir.Name{ID: c.varName(n), Loc: L}
	case "integer_literal", "decimal_integer_literal", "real_literal", "boolean":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "string_literal", "verbatim_string_characters", "expandable_string_literal", "literal_expression":
		var parts []nir.Expr
		var walk func(m *tree_sitter.Node)
		walk = func(m *tree_sitter.Node) {
			for _, ch := range namedChildren(m) {
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
		return nir.Const{Loc: L}
	case "additive_expression":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			parts = append(parts, c.expr(ch))
		}
		return nir.Format{Parts: parts, Loc: L}
	case "command":
		return c.command(n)
	case "command_invokation_operator", "sub_expression", "parenthesized_expression":
		if k := namedChildren(n); len(k) > 0 {
			return c.expr(k[len(k)-1])
		}
	case "member_access":
		base := namedChildren(n)
		if len(base) > 0 {
			return nir.Attr{Base: c.expr(base[0]), Attr: c.text(field(n, "member")), Path: c.dotted(n), Loc: L}
		}
	case "invokation_expression":
		if k := namedChildren(n); len(k) > 0 {
			path := c.dotted(k[0])
			return nir.Call{Callee: c.expr(k[0]), Args: c.psInvokeArgs(n), Path: path, Method: lastSeg(path), Loc: L}
		}
	}
	var parts []nir.Expr
	for _, ch := range namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return nir.Seq{Parts: parts, Loc: L}
}

func (c *psConv) psInvokeArgs(n *tree_sitter.Node) []nir.Expr {
	var out []nir.Expr
	if a := field(n, "arguments"); a != nil {
		for _, ch := range namedChildren(a) {
			out = append(out, c.expr(ch))
		}
	}
	return out
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
		base := namedChildren(n)
		if len(base) > 0 {
			return c.dotted(base[0]) + "." + c.text(field(n, "member"))
		}
	case "command":
		return lastSeg(c.text(field(n, "command_name")))
	}
	return "?"
}
