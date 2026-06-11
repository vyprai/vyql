package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsbash "github.com/tree-sitter/tree-sitter-bash/bindings/go"

	"github.com/vyprai/vyql/extract/nir"
)

// shConv walks a tree-sitter Bash CST into NIR. A `command` becomes a Call
// (program word = path/method, words/strings = args); a `$1`/`$QUERY_STRING`
// expansion becomes a synthetic source call (shell_input); a string with
// embedded expansions becomes a Format (taint-propagating).
type shConv struct {
	src  []byte
	file string
	key  string
}

// shSourceVars: positional/special params and CGI env vars are untrusted input.
func shSourceVar(name string) bool {
	if len(name) == 1 && (name[0] >= '1' && name[0] <= '9' || name == "@" || name == "*") {
		return true
	}
	for _, p := range []string{"QUERY_STRING", "HTTP_", "REQUEST_", "CONTENT_", "PATH_INFO", "REMOTE_", "REQUEST_URI", "REQUEST_METHOD"} {
		if name == p || strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// ExtractBash parses shell scripts into one NIR Program (one module per file).
func ExtractBash(files []string, root string) (nir.Program, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	_ = parser.SetLanguage(tree_sitter.NewLanguage(tsbash.Language()))

	var prog nir.Program
	prog.SelfName = "self"
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
		c := &shConv{src: src, file: rel, key: moduleKey(root, f, ".sh")}
		prog.Modules = append(prog.Modules, nir.Module{Key: c.key, File: rel, Body: c.block(tree.RootNode())})
		tree.Close()
	}
	return prog, nil
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
	// branch-structured (B1); Cond nil (bash did not evaluate the predicate) -> byte-identical.
	case "if_statement":
		return []nir.Stmt{nir.If{Then: c.collectBlocks(n)}}
	case "for_statement", "while_statement", "c_style_for_statement":
		return []nir.Stmt{nir.Loop{Body: c.collectBlocks(n)}}
	case "case_statement", "redirected_statement":
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
		return nir.Const{Loc: L}
	case "simple_expansion", "expansion":
		name := c.expansionVar(n)
		if shSourceVar(name) { // $1 / $QUERY_STRING / … → untrusted input
			return nir.Call{Callee: nir.Name{ID: "shell_input", Loc: L}, Path: "shell_input", Method: "shell_input", Loc: L}
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
		return nir.Const{Loc: L}
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
	}
	var parts []nir.Expr
	for _, ch := range namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
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
