package treesitter

import (
	"regexp"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsbash "github.com/tree-sitter/tree-sitter-bash/bindings/go"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// shConv walks a tree-sitter Bash CST into NIR. A `command` becomes a Call
// (program word = path/method, words/strings = args); configured variable
// expansions become synthetic event calls; a string with embedded expansions
// becomes a Format.
type shConv struct {
	nodeCache
	src  []byte
	file string
	key  string
}

var shCatInputAssignRE = regexp.MustCompile(`(?m)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\$\(\s*cat\s*\)`)

// ExtractBash parses shell scripts into one NIR Program (one module per file).
func ExtractBash(files []string, root string) (nir.Program, error) {
	mods := parseModules(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(tree_sitter.NewLanguage(tsbash.Language()))
			return p
		},
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			c := &shConv{src: src, file: rel, key: moduleKey(root, abs, ".sh")}
			body := append(c.shModuleContext(tree.RootNode()), c.block(tree.RootNode())...)
			return nir.Module{Key: c.key, File: rel, Body: body}, true
		})
	return nir.Program{SelfName: "self", Modules: mods}, nil
}

func (c *shConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *shConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

func (c *shConv) shModuleContext(root *tree_sitter.Node) []nir.Stmt {
	if root == nil {
		return nil
	}
	loc := c.file + ":1"
	text := c.text(root)
	args := []nir.Expr{
		nir.Const{Loc: loc, Value: "lang=bash"},
		nir.Const{Loc: loc, Value: text},
		nir.Const{Loc: loc, Value: strings.Join(strings.Fields(text), "")},
	}
	for _, tok := range c.shSemanticModuleTokens(text) {
		args = append(args, nir.Const{Loc: loc, Value: tok})
	}
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: "analysis.module.context", Loc: loc},
		Args:   args,
		Path:   "analysis.module.context",
		Method: "context",
		Loc:    loc,
	}}}
}

func (c *shConv) shSemanticModuleTokens(text string) []string {
	var out []string
	add := func(tok string) {
		for _, existing := range out {
			if existing == tok {
				return
			}
		}
		out = append(out, tok)
	}
	if shHasPythonTripleQuoteStdinInterpolation(text) {
		add("shell_bridge:python_triple_quote_stdin_interpolation")
	}
	return out
}

func shHasPythonTripleQuoteStdinInterpolation(text string) bool {
	if !strings.Contains(text, "python3") || !strings.Contains(text, "-c") ||
		!strings.Contains(text, "json.loads") || strings.Contains(text, "<<'PYEOF'") ||
		strings.Contains(text, "os.environ.get") {
		return false
	}
	for _, match := range shCatInputAssignRE.FindAllStringSubmatch(text, -1) {
		if len(match) < 2 {
			continue
		}
		name := match[1]
		if strings.Contains(text, "'''$"+name+"'''") ||
			strings.Contains(text, "'''${"+name+"}'''") ||
			strings.Contains(text, "'''$"+name) ||
			strings.Contains(text, "'''${"+name+"}") {
			return true
		}
	}
	return false
}

func (c *shConv) block(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, st := range c.namedChildren(n) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *shConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	switch c.kind(n) {
	case "function_definition":
		return []nir.Stmt{nir.FuncDef{Name: c.text(c.field(n, "name")), Body: c.block(c.field(n, "body")), Loc: c.loc(n)}}
	case "variable_assignment":
		name := c.text(c.field(n, "name"))
		if v := c.field(n, "value"); name != "" && v != nil {
			return []nir.Stmt{nir.Assign{Targets: []string{name}, Value: c.expr(v)}}
		}
		return nil
	case "declaration_command", "unset_command":
		var out []nir.Stmt
		for _, ch := range c.namedChildren(n) {
			if c.kind(ch) == "variable_assignment" {
				out = append(out, c.stmt(ch)...)
			}
		}
		return out
	case "command":
		return []nir.Stmt{nir.ExprStmt{Value: c.command(n)}}
	case "pipeline", "list", "subshell", "compound_statement", "negated_command":
		return c.block(n)
	// branch-structured with predicate attached so constant-false arms are pruned.
	case "if_statement":
		return []nir.Stmt{c.shIf(n)}
	case "for_statement", "while_statement", "c_style_for_statement":
		return []nir.Stmt{nir.Loop{Body: c.collectBlocks(n)}}
	case "case_statement":
		return []nir.Stmt{c.shCase(n)}
	case "redirected_statement":
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	}
	return nil
}

func (c *shConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch c.kind(ch) {
			case "command", "variable_assignment", "declaration_command", "pipeline",
				"list", "if_statement", "for_statement", "while_statement", "case_statement":
				out = append(out, c.stmt(ch)...)
			case "do_group", "compound_statement", "case_item", "elif_clause", "else_clause":
				walk(ch)
			}
		}
	}
	walk(n)
	return out
}

// command models a shell command as a Call: program word -> path/method, the
// remaining words/strings -> args. A leading directory in the program (/bin/sh)
// is stripped so sink patterns match the basename.
func (c *shConv) command(n *tree_sitter.Node) nir.Expr {
	L := c.loc(n)
	nameNode := c.field(n, "name")
	prog := c.text(nameNode)
	if i := strings.LastIndexByte(prog, '/'); i >= 0 {
		prog = prog[i+1:]
	}
	var args []nir.Expr
	for _, ch := range c.namedChildren(n) {
		switch c.kind(ch) {
		case "command_name":
			continue
		case "file_redirect", "heredoc_redirect", "herestring_redirect", "variable_assignment":
			continue
		default:
			args = append(args, c.expr(ch))
		}
	}
	return nir.Call{Callee: nir.Name{ID: prog, Loc: L}, Args: args, Path: prog, Method: prog, Loc: L}
}

func (c *shConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch c.kind(n) {
	case "word", "number", "raw_string", "test_operator":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "simple_expansion", "expansion":
		name := c.expansionVar(n)
		if event, ok := sourceVarEvent("bash", name); ok {
			return nir.Call{Callee: nir.Name{ID: event, Loc: L}, Path: event, Method: event, Loc: L}
		}
		if nested := c.shNestedSourceRefs(n, name); len(nested) > 0 {
			parts := []nir.Expr{nir.Name{ID: name, Loc: L}}
			parts = append(parts, nested...)
			return nir.Format{Parts: parts, Loc: L}
		}
		return nir.Name{ID: name, Loc: L}
	case "string", "concatenation":
		var parts []nir.Expr
		for _, ch := range c.namedChildren(n) {
			if k := c.kind(ch); k == "simple_expansion" || k == "expansion" ||
				k == "command_substitution" || k == "string" || k == "concatenation" {
				parts = append(parts, c.expr(ch))
			}
		}
		if event, ok := sourceVarEventInText("bash", c.text(n)); ok && !shExprsHaveCallPath(parts, event) {
			parts = append(parts, nir.Call{Callee: nir.Name{ID: event, Loc: L}, Path: event, Method: event, Loc: L})
		}
		if len(parts) > 0 {
			return nir.Format{Parts: parts, Loc: L}
		}
		return nir.Const{Loc: L, Value: shLiteralValue(c.text(n))}
	case "command_substitution":
		var parts []nir.Expr
		for _, ch := range c.namedChildren(n) {
			if c.kind(ch) == "command" {
				parts = append(parts, c.command(ch))
			} else {
				parts = append(parts, c.expr(ch))
			}
		}
		return nir.Seq{Parts: parts, Loc: L}
	case "command":
		return c.command(n)
	case "test_command":
		// `[ expr ]` / `[[ expr ]]` — unwrap to the inner comparison.
		if k := c.namedChildren(n); len(k) > 0 {
			return c.expr(k[0])
		}
	case "binary_expression":
		op := c.text(c.field(n, "operator"))
		if m, ok := shTestOp[op]; ok { // map `-gt`/`-eq`/… so const-eval can fold
			op = m
		}
		return nir.BinOp{Op: op, Left: c.expr(c.field(n, "left")), Right: c.expr(c.field(n, "right")), Loc: L}
	case "unary_expression":
		if k := c.namedChildren(n); len(k) > 0 {
			op := "?"
			for i := uint(0); i < n.ChildCount(); i++ {
				if ch := n.Child(i); !ch.IsNamed() {
					op = c.text(ch)
					break
				}
			}
			return nir.Unary{Op: op, Operand: c.expr(k[len(k)-1]), Loc: L}
		}
	}
	var parts []nir.Expr
	for _, ch := range c.namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
}

func (c *shConv) shNestedSourceRefs(root *tree_sitter.Node, outer string) []nir.Expr {
	var out []nir.Expr
	seen := map[string]bool{}
	add := func(event string, loc string) {
		if event == "" || seen[event] {
			return
		}
		seen[event] = true
		out = append(out, nir.Call{Callee: nir.Name{ID: event, Loc: loc}, Path: event, Method: event, Loc: loc})
	}
	if event, ok := sourceVarEventInText("bash", c.text(root)); ok {
		add(event, c.loc(root))
	}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		switch c.kind(n) {
		case "variable_name", "special_variable_name":
			name := c.text(n)
			if name != outer {
				if event, ok := sourceVarEvent("bash", name); ok {
					add(event, c.loc(n))
				}
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	for _, ch := range c.namedChildren(root) {
		walk(ch)
	}
	return out
}

func shExprsHaveCallPath(exprs []nir.Expr, path string) bool {
	for _, expr := range exprs {
		if shExprHasCallPath(expr, path) {
			return true
		}
	}
	return false
}

func shExprHasCallPath(expr nir.Expr, path string) bool {
	switch v := expr.(type) {
	case nir.Call:
		if v.Path == path {
			return true
		}
		return shExprsHaveCallPath(v.Args, path)
	case nir.Format:
		return shExprsHaveCallPath(v.Parts, path)
	case nir.Seq:
		return shExprsHaveCallPath(v.Parts, path)
	case nir.BinOp:
		return shExprHasCallPath(v.Left, path) || shExprHasCallPath(v.Right, path)
	case nir.Unary:
		return shExprHasCallPath(v.Operand, path)
	default:
		return false
	}
}

func shLiteralValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) >= 2 {
		if q := raw[0]; (q == '"' || q == '\'') && raw[len(raw)-1] == q {
			return raw[1 : len(raw)-1]
		}
	}
	return raw
}

// shTestOp maps bash test operators to C-style symbols const-eval understands.
var shTestOp = map[string]string{
	"-gt": ">", "-lt": "<", "-ge": ">=", "-le": "<=", "-eq": "==", "-ne": "!=",
}

// shIf lowers an if with its predicate so a constant-false arm is pruned. The then-body
// statements are direct children between the condition and the else/elif clauses.
func (c *shConv) shIf(n *tree_sitter.Node) nir.Stmt {
	it := nir.If{Loc: c.loc(n)}
	seenCond := false
	for i := uint(0); i < n.ChildCount(); i++ {
		ch := n.Child(i)
		if n.FieldNameForChild(uint32(i)) == "condition" {
			if it.Cond == nil {
				it.Cond = c.expr(ch)
			}
			seenCond = true
			continue
		}
		if !ch.IsNamed() {
			continue
		}
		switch c.kind(ch) {
		case "else_clause":
			for _, e := range c.namedChildren(ch) {
				it.Else = append(it.Else, c.stmt(e)...)
			}
		case "elif_clause":
			it.Else = append(it.Else, c.shIf(ch))
		default:
			if seenCond {
				it.Then = append(it.Then, c.stmt(ch)...)
			}
		}
	}
	return it
}

// shCase lowers a case to a subject+labelled Switch so a constant subject prunes arms.
func (c *shConv) shCase(n *tree_sitter.Node) nir.Stmt {
	sw := nir.Switch{Loc: c.loc(n)}
	if v := c.field(n, "value"); v != nil {
		sw.Subject = c.expr(v)
	}
	for _, ci := range c.namedChildren(n) {
		if c.kind(ci) != "case_item" {
			continue
		}
		var labs []nir.Expr
		var stmts []nir.Stmt
		isDefault := false
		for i := uint(0); i < ci.ChildCount(); i++ {
			ch := ci.Child(i)
			if !ch.IsNamed() {
				continue
			}
			if ci.FieldNameForChild(uint32(i)) == "value" {
				if c.text(ch) == "*" || c.kind(ch) == "extglob_pattern" {
					isDefault = true
				} else {
					labs = append(labs, c.expr(ch))
				}
				continue
			}
			if c.kind(ch) == "termination" {
				continue
			}
			stmts = append(stmts, c.stmt(ch)...)
		}
		if isDefault || len(labs) == 0 {
			sw.Default = append(sw.Default, stmts...)
		} else {
			sw.Cases = append(sw.Cases, stmts)
			sw.Labels = append(sw.Labels, labs)
		}
	}
	return sw
}

// expansionVar extracts the variable name from $x or ${x...}.
func (c *shConv) expansionVar(n *tree_sitter.Node) string {
	for _, ch := range c.namedChildren(n) {
		if c.kind(ch) == "variable_name" || c.kind(ch) == "special_variable_name" {
			return c.text(ch)
		}
		if c.kind(ch) == "subscript" {
			return c.text(c.field(ch, "name"))
		}
	}
	// ${x} sometimes exposes the name as the raw text between braces
	t := strings.TrimPrefix(c.text(n), "$")
	t = strings.TrimPrefix(t, "{")
	t = strings.TrimSuffix(t, "}")
	if i := strings.IndexAny(t, ":[}/#%"); i >= 0 {
		t = t[:i]
	}
	return t
}
