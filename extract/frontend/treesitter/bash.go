package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsbash "github.com/tree-sitter/tree-sitter-bash/bindings/go"

	"github.com/vyprai/vyql/extract/nir"
)

// shConv walks a tree-sitter Bash CST into NIR. A `command` becomes a Call
// (program word = path/method, words/strings = args); configured variable
// expansions become synthetic event calls; a string with embedded expansions
// becomes a Format.
type shConv struct {
	src  []byte
	file string
	key  string
}

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
			return nir.Module{Key: c.key, File: rel, Body: c.block(tree.RootNode())}, true
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

func (c *shConv) block(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, st := range namedChildren(n) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *shConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	switch n.Kind() {
	case "function_definition":
		return []nir.Stmt{nir.FuncDef{Name: c.text(field(n, "name")), Body: c.block(field(n, "body")), Loc: c.loc(n)}}
	case "variable_assignment":
		name := c.text(field(n, "name"))
		if v := field(n, "value"); name != "" && v != nil {
			return []nir.Stmt{nir.Assign{Targets: []string{name}, Value: c.expr(v)}}
		}
		return nil
	case "declaration_command", "unset_command":
		var out []nir.Stmt
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "variable_assignment" {
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
			switch ch.Kind() {
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
	nameNode := field(n, "name")
	prog := c.text(nameNode)
	if i := strings.LastIndexByte(prog, '/'); i >= 0 {
		prog = prog[i+1:]
	}
	var args []nir.Expr
	for _, ch := range namedChildren(n) {
		switch ch.Kind() {
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
	switch n.Kind() {
	case "word", "number", "raw_string", "test_operator":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "simple_expansion", "expansion":
		name := c.expansionVar(n)
		if event, ok := sourceVarEvent("bash", name); ok {
			return nir.Call{Callee: nir.Name{ID: event, Loc: L}, Path: event, Method: event, Loc: L}
		}
		return nir.Name{ID: name, Loc: L}
	case "string", "concatenation":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			if k := ch.Kind(); k == "simple_expansion" || k == "expansion" ||
				k == "command_substitution" || k == "string" || k == "concatenation" {
				parts = append(parts, c.expr(ch))
			}
		}
		if len(parts) > 0 {
			return nir.Format{Parts: parts, Loc: L}
		}
		return nir.Const{Loc: L, Value: shLiteralValue(c.text(n))}
	case "command_substitution":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "command" {
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
		if k := namedChildren(n); len(k) > 0 {
			return c.expr(k[0])
		}
	case "binary_expression":
		op := c.text(field(n, "operator"))
		if m, ok := shTestOp[op]; ok { // map `-gt`/`-eq`/… so const-eval can fold
			op = m
		}
		return nir.BinOp{Op: op, Left: c.expr(field(n, "left")), Right: c.expr(field(n, "right")), Loc: L}
	case "unary_expression":
		if k := namedChildren(n); len(k) > 0 {
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
	for _, ch := range namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
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
		switch ch.Kind() {
		case "else_clause":
			for _, e := range namedChildren(ch) {
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
	if v := field(n, "value"); v != nil {
		sw.Subject = c.expr(v)
	}
	for _, ci := range namedChildren(n) {
		if ci.Kind() != "case_item" {
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
				if c.text(ch) == "*" || ch.Kind() == "extglob_pattern" {
					isDefault = true
				} else {
					labs = append(labs, c.expr(ch))
				}
				continue
			}
			if ch.Kind() == "termination" {
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
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "variable_name" || ch.Kind() == "special_variable_name" {
			return c.text(ch)
		}
		if ch.Kind() == "subscript" {
			return c.text(field(ch, "name"))
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
