package treesitter

import (
	"strings"
	"unicode"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsphp "github.com/tree-sitter/tree-sitter-php/bindings/go"

	"github.com/vyprai/vyql/extract/nir"
)

// phConv walks a tree-sitter PHP CST into NIR. PHP functions live in a global
// namespace (module key ""), like Ruby; `echo`/`print`/`include`/`require` are
// modeled as calls so they can be sinks.
type phConv struct {
	src      []byte
	root     string
	file     string
	funcName string
}

// ExtractPHP parses PHP files into one NIR Program (all modules keyed "").
func ExtractPHP(files []string, root string) (nir.Program, error) {
	mods := parseModules(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(tree_sitter.NewLanguage(tsphp.LanguagePHP()))
			return p
		},
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			c := &phConv{src: src, root: root, file: rel}
			body := c.block(tree.RootNode())
			body = append(body, c.phpIncompleteServerPortValidation(tree.RootNode())...)
			body = append(body, c.phpUnescapedSessionFlash(tree.RootNode())...)
			body = append(body, c.phpUnscannedPdfPreview(tree.RootNode())...)
			body = append(body, c.phpUnrestrictedVariableVariableAssignment(tree.RootNode())...)
			return nir.Module{Key: "", File: rel, Body: body}, true
		})
	return nir.Program{SelfName: "this", Modules: mods}, nil
}

func (c *phConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *phConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

func (c *phConv) block(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, st := range namedChildren(n) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *phConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "function_definition", "method_declaration":
		params := c.params(field(n, "parameters"))
		name := c.text(field(n, "name"))
		// top-level functions are public; methods are public unless private/protected.
		exported := true
		if n.Kind() == "method_declaration" {
			for _, ch := range children(n) {
				if ch.Kind() == "visibility_modifier" {
					t := c.text(ch)
					exported = !strings.Contains(t, "private") && !strings.Contains(t, "protected")
				}
			}
		}
		ptypes := c.paramTypes(field(n, "parameters"))
		prevFunc := c.funcName
		c.funcName = name
		body := c.block(field(n, "body"))
		c.funcName = prevFunc
		if n.Kind() == "method_declaration" && phpIsWPListTableColumn(name) && len(params) > 0 {
			body = append([]nir.Stmt{nir.Assign{Targets: []string{params[0]},
				Value: nir.Call{Callee: nir.Name{ID: "wp.list_table.row", Loc: L}, Path: "wp.list_table.row", Method: "row", Loc: L}}}, body...)
		}
		// MediaWiki parser hook: a method taking a `Parser`/`PPFrame` carries user wiki markup
		// in its OTHER params ($input, $args of `parse3DTag($input,$args,Parser $p,PPFrame $f)`),
		// which flow into Html::element/rawElement output (stored XSS). Seed those as input.
		if phpHasFrameworkParam(ptypes) {
			var seed []nir.Stmt
			for _, p := range params {
				if t := ptypes[p]; !phpFrameworkType(t) {
					seed = append(seed, nir.Assign{Targets: []string{p},
						Value: nir.Call{Callee: nir.Name{ID: "http_input", Loc: L}, Path: "http_input", Method: "http_input", Loc: L}})
				}
			}
			body = append(seed, body...)
		}
		return []nir.Stmt{nir.FuncDef{
			Name:       name,
			Params:     params,
			ParamTypes: ptypes,
			Body:       body,
			Loc:        L,
			Exported:   exported,
		}}
	case "class_declaration", "interface_declaration", "trait_declaration", "enum_declaration":
		return []nir.Stmt{nir.ClassDef{Name: c.text(field(n, "name")), Body: c.block(field(n, "body")), Loc: L}}
	case "expression_statement":
		kids := namedChildren(n)
		if len(kids) == 0 {
			return nil
		}
		return c.exprStmt(kids[0])
	case "echo_statement", "print_intrinsic", "unset_statement":
		// model echo/print as a sink-able call
		var args []nir.Expr
		for _, a := range namedChildren(n) {
			args = append(args, c.expr(a))
		}
		name := "echo"
		if n.Kind() == "print_intrinsic" {
			name = "print"
		}
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: nir.Name{ID: name, Loc: L}, Args: args, Path: name, Method: name, Loc: L}}}
	case "return_statement":
		kids := namedChildren(n)
		if len(kids) > 0 {
			value := c.expr(kids[0])
			if phpIsWPListTableColumn(c.funcName) {
				render := nir.ExprStmt{Value: nir.Call{Callee: nir.Name{ID: "wp.list_table.render", Loc: L},
					Args: []nir.Expr{value}, Path: "wp.list_table.render", Method: "render", Loc: L}}
				return []nir.Stmt{render, nir.Return{Value: value}}
			}
			return []nir.Stmt{nir.Return{Value: value}}
		}
		return []nir.Stmt{nir.Return{}}
	// branch-structured (B1). PHP did not evaluate the condition before → Cond stays nil,
	// byte-identical.
	case "if_statement":
		return []nir.Stmt{nir.If{Cond: c.expr(field(n, "condition")), Then: c.phpBranch(field(n, "body")), Else: c.phpElse(n)}}
	case "foreach_statement":
		// `foreach ($coll as $k => $v) {…}` — bind the loop key/value vars to the collection
		// (conservative whole-collection taint) so element taint flows into the body. Without
		// this $v/$k were unbound and all per-element taint was lost (e.g. building an HTML
		// attribute array `$par[$k]=$v` from user input). Binding $k too matters for
		// attribute-NAME injection. tree-sitter-php: `body` is a field; the non-body children
		// are [iterable, value-spec], where value-spec is variable_name | by_ref | list_literal
		// | pair($k => $v).
		body := c.collectBlocks(n)
		bodyNode := field(n, "body")
		var nonBody []*tree_sitter.Node
		for _, ch := range namedChildren(n) {
			if bodyNode != nil && ch.StartByte() == bodyNode.StartByte() {
				continue
			}
			nonBody = append(nonBody, ch)
		}
		if len(nonBody) >= 2 {
			coll := nonBody[0]
			var names []string
			c.foreachVarNames(nonBody[1], &names)
			var binds []nir.Stmt
			for _, vn := range names {
				binds = append(binds, nir.Assign{Targets: []string{vn},
					Value: nir.Format{Parts: []nir.Expr{c.expr(coll)}, Loc: L}})
			}
			body = append(binds, body...)
		}
		return []nir.Stmt{nir.Loop{Body: body}}
	case "while_statement", "for_statement", "do_statement":
		return []nir.Stmt{nir.Loop{Body: c.collectBlocks(n)}}
	case "try_statement":
		return []nir.Stmt{nir.Try{Body: c.collectBlocks(n)}}
	case "switch_statement":
		return []nir.Stmt{c.phpSwitch(n)}
	case "compound_statement":
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	}
	return nil
}

func (c *phConv) exprStmt(inner *tree_sitter.Node) []nir.Stmt {
	switch inner.Kind() {
	case "assignment_expression", "augmented_assignment_expression":
		left := field(inner, "left")
		right := c.expr(field(inner, "right"))
		if left != nil && left.Kind() == "variable_name" {
			if inner.Kind() == "augmented_assignment_expression" {
				return []nir.Stmt{nir.AugAssign{Target: c.text(left), Value: right, Loc: c.loc(inner)}}
			}
			return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: right}}
		}
		// member-property write ($obj->role = v) — model as a PATH-sink Call (Method empty so
		// it never collides with method-name sinks) so trust-context / DOM path sinks fire.
		if left != nil && left.Kind() == "member_access_expression" {
			return []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: c.expr(left), Args: []nir.Expr{right},
				Path: c.dotted(left), Method: "", Loc: c.loc(inner)}}}
		}
		// subscript write ($arr[$k] = v) — two effects: (1) a write to the base's path
		// ($_SESSION['role'] → "_SESSION") so the trust-boundary path sink fires (CWE-501);
		// (2) when the base is a plain variable, a taint-JOIN `$arr = combine($arr, v)` so a
		// later read of $arr carries v's taint (an array built element-by-element from user
		// input — e.g. `$par[$k]=$v; Html::element('canvas',$par)` — stays tainted). Without (2)
		// the value taint was dropped at the discarded write.
		if left != nil && left.Kind() == "subscript_expression" {
			if kids := namedChildren(left); len(kids) > 0 {
				base := kids[0]
				write := nir.ExprStmt{Value: nir.Call{Callee: c.expr(base), Args: []nir.Expr{right},
					Path: c.dotted(base), Method: "", Loc: c.loc(inner)}}
				if base.Kind() == "variable_name" {
					bn := c.text(base)
					join := nir.Assign{Targets: []string{bn},
						Value: nir.Format{Parts: []nir.Expr{nir.Name{ID: bn, Loc: c.loc(base)}, right}, Loc: c.loc(inner)}}
					return []nir.Stmt{write, join}
				}
				return []nir.Stmt{write}
			}
		}
		return []nir.Stmt{nir.ExprStmt{Value: right}}
	case "include_expression", "include_once_expression", "require_expression", "require_once_expression":
		// model include/require as a file-inclusion sink call
		kids := namedChildren(inner)
		var args []nir.Expr
		if len(kids) > 0 {
			args = append(args, c.expr(kids[0]))
		}
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: nir.Name{ID: "include", Loc: c.loc(inner)},
			Args: args, Path: "include", Method: "include", Loc: c.loc(inner)}}}
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(inner)}}
}

// phpBranch flattens one if-branch body: a `{}` compound_statement, or a brace-less
// single statement (PHP allows `if ($c) $x = 1;`).
func (c *phConv) phpBranch(b *tree_sitter.Node) []nir.Stmt {
	if b == nil {
		return nil
	}
	if b.Kind() == "compound_statement" {
		var out []nir.Stmt
		for _, st := range namedChildren(b) {
			out = append(out, c.stmt(st)...)
		}
		return out
	}
	return c.stmt(b)
}

// phpElse builds the Else branch from else_if_clause / else_clause children (elseif chains
// into a nested If), so the join-merge and constant-condition pruning work.
func (c *phConv) phpElse(n *tree_sitter.Node) []nir.Stmt {
	var alts []*tree_sitter.Node
	for _, ch := range children(n) {
		if ch.Kind() == "else_if_clause" || ch.Kind() == "else_clause" {
			alts = append(alts, ch)
		}
	}
	var els []nir.Stmt
	for i := len(alts) - 1; i >= 0; i-- {
		a := alts[i]
		if a.Kind() == "else_clause" {
			els = c.phpBranch(field(a, "body"))
			continue
		}
		els = []nir.Stmt{nir.If{Cond: c.expr(field(a, "condition")), Then: c.phpBranch(field(a, "body")), Else: els}}
	}
	return els
}

// phpSwitch lowers a switch into separate case branches with labels (consecutive
// fall-through labels merge into the next body) so a constant subject prunes to its arm.
func (c *phConv) phpSwitch(n *tree_sitter.Node) nir.Stmt {
	var cases [][]nir.Stmt
	var labels [][]nir.Expr
	var deflt []nir.Stmt
	var pending []nir.Expr
	if b := field(n, "body"); b != nil {
		for _, cs := range namedChildren(b) {
			switch cs.Kind() {
			case "case_statement":
				lv := field(cs, "value")
				var stmts []nir.Stmt
				for _, ch := range namedChildren(cs) {
					if lv != nil && ch.StartByte() == lv.StartByte() {
						continue
					}
					stmts = append(stmts, c.stmt(ch)...)
				}
				if lv != nil {
					pending = append(pending, c.expr(lv))
				}
				if len(stmts) > 0 {
					cases = append(cases, stmts)
					labels = append(labels, pending)
					pending = nil
				}
			case "default_statement":
				for _, ch := range namedChildren(cs) {
					deflt = append(deflt, c.stmt(ch)...)
				}
			}
		}
	}
	return nir.Switch{Subject: c.expr(field(n, "condition")), Cases: cases, Labels: labels, Default: deflt}
}

func (c *phConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "compound_statement":
				out = append(out, c.block(ch)...)
			case "else_clause", "else_if_clause", "catch_clause", "finally_clause",
				"switch_block", "case_statement", "default_statement":
				walk(ch)
			default:
				if ch.IsNamed() && ch.Kind() != "binary_expression" && ch.Kind() != "parenthesized_expression" {
					// nested statements directly in a clause body
					if isStmtKind(ch.Kind()) {
						out = append(out, c.stmt(ch)...)
					}
				}
			}
		}
	}
	walk(n)
	return out
}

func isStmtKind(k string) bool {
	switch k {
	case "expression_statement", "echo_statement", "return_statement", "if_statement",
		"while_statement", "for_statement", "foreach_statement", "compound_statement",
		"function_definition", "method_declaration", "class_declaration":
		return true
	}
	return false
}

func (c *phConv) params(params *tree_sitter.Node) []string {
	if params == nil {
		return nil
	}
	var out []string
	for _, ch := range namedChildren(params) {
		if ch.Kind() == "simple_parameter" || ch.Kind() == "variadic_parameter" || ch.Kind() == "property_promotion_parameter" {
			if nm := field(ch, "name"); nm != nil {
				out = append(out, c.text(nm))
			} else {
				for _, cc := range namedChildren(ch) {
					if cc.Kind() == "variable_name" {
						out = append(out, c.text(cc))
						break
					}
				}
			}
		}
	}
	return out
}

func (c *phConv) paramTypes(params *tree_sitter.Node) map[string]string {
	out := map[string]string{}
	if params == nil {
		return out
	}
	for _, ch := range namedChildren(params) {
		if ch.Kind() == "simple_parameter" || ch.Kind() == "variadic_parameter" || ch.Kind() == "property_promotion_parameter" {
			name := ""
			if nm := field(ch, "name"); nm != nil {
				name = c.text(nm)
			} else {
				for _, cc := range namedChildren(ch) {
					if cc.Kind() == "variable_name" {
						name = c.text(cc)
						break
					}
				}
			}
			putParamType(out, name, paramTypeFromField(c, ch))
		}
	}
	return out
}

func (c *phConv) callArgs(args *tree_sitter.Node) []nir.Expr {
	if args == nil {
		return nil
	}
	var out []nir.Expr
	for _, a := range namedChildren(args) {
		if a.Kind() == "argument" {
			if k := namedChildren(a); len(k) > 0 {
				out = append(out, c.expr(k[len(k)-1]))
			}
		} else {
			out = append(out, c.expr(a))
		}
	}
	return out
}

// phpFrameworkType reports whether a PHP param type is a MediaWiki framework object (NOT user
// data) — used to identify a parser hook and exclude these params from input seeding.
func phpFrameworkType(t string) bool {
	switch t {
	case "Parser", "PPFrame", "OutputPage", "Skin", "Title", "MimeAnalyzer":
		return true
	}
	return false
}

func phpHasFrameworkParam(ptypes map[string]string) bool {
	for _, t := range ptypes {
		if t == "Parser" || t == "PPFrame" {
			return true
		}
	}
	return false
}

func phpIsWPListTableColumn(name string) bool {
	return name == "column_default" || strings.HasPrefix(name, "column_")
}

func (c *phConv) phpIncompleteServerPortValidation(root *tree_sitter.Node) []nir.Stmt {
	full := c.text(root)
	compact := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, full)
	if !strings.Contains(compact, "connect(") ||
		!strings.Contains(compact, "is_numeric($port)") ||
		!(strings.Contains(compact, "explode(\":\",SERVER") || strings.Contains(compact, "explode(':',SERVER")) ||
		!(strings.Contains(compact, "$port<1024") || strings.Contains(compact, "1024>$port")) {
		return nil
	}
	var out []nir.Stmt
	seen := map[string]bool{}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		callText := strings.Map(func(r rune) rune {
			if unicode.IsSpace(r) {
				return -1
			}
			return r
		}, c.text(n))
		if n.Kind() == "function_call_expression" &&
			c.dotted(field(n, "function")) == "is_numeric" &&
			strings.Contains(callText, "is_numeric($port)") {
			loc := c.loc(n)
			if !seen[loc] {
				seen[loc] = true
				path := "security.php.server_port_validation.incomplete"
				out = append(out, nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: path, Loc: loc},
					Path:   path,
					Method: lastSeg(path),
					Loc:    loc,
				}})
			}
		}
		for _, ch := range namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
	return out
}

func (c *phConv) phpUnescapedSessionFlash(root *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	seen := map[string]bool{}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if n.Kind() == "assignment_expression" {
			left := c.text(field(n, "left"))
			right := c.text(field(n, "right"))
			if phpSessionFlashInfoWrite(left) &&
				strings.Contains(right, "$") &&
				!phpLooksHtmlEscaped(right) {
				loc := c.loc(n)
				if !seen[loc] {
					seen[loc] = true
					path := "security.php.session_flash.unescaped"
					out = append(out, nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: path, Loc: loc},
						Path:   path,
						Method: lastSeg(path),
						Loc:    loc,
					}})
				}
			}
		}
		for _, ch := range namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
	return out
}

func phpSessionFlashInfoWrite(left string) bool {
	compact := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, left)
	return strings.Contains(compact, "$_SESSION['info']") ||
		strings.Contains(compact, "$_SESSION[\"info\"]") ||
		strings.Contains(compact, "$_SESSION['message']") ||
		strings.Contains(compact, "$_SESSION[\"message\"]") ||
		strings.Contains(compact, "$_SESSION['flash']") ||
		strings.Contains(compact, "$_SESSION[\"flash\"]")
}

func phpLooksHtmlEscaped(s string) bool {
	lower := strings.ToLower(s)
	return strings.Contains(lower, "htmlspecialchars") ||
		strings.Contains(lower, "htmlentities") ||
		strings.Contains(lower, "esc_html") ||
		strings.Contains(lower, "strip_tags")
}

func (c *phConv) phpUnscannedPdfPreview(root *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	seen := map[string]bool{}
	var walk func(*tree_sitter.Node, string)
	walk = func(n *tree_sitter.Node, scope string) {
		if n == nil {
			return
		}
		if n.Kind() == "function_definition" || n.Kind() == "method_declaration" {
			scope = c.text(n)
		}
		if n.Kind() == "object_creation_expression" {
			text := c.text(n)
			if strings.Contains(text, "StreamedResponse") &&
				strings.Contains(strings.ToLower(text), "application/pdf") &&
				!phpPdfScanGateBefore(scope, text) {
				loc := c.loc(n)
				if !seen[loc] {
					seen[loc] = true
					path := "security.php.pdf_preview.unscanned"
					out = append(out, nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: path, Loc: loc},
						Path:   path,
						Method: lastSeg(path),
						Loc:    loc,
					}})
				}
			}
		}
		for _, ch := range namedChildren(n) {
			walk(ch, scope)
		}
	}
	walk(root, "")
	return out
}

func phpPdfScanGateBefore(scope, objectText string) bool {
	if scope == "" {
		return false
	}
	idx := strings.Index(scope, objectText)
	if idx < 0 {
		idx = len(scope)
	}
	prefix := strings.ToLower(scope[:idx])
	return strings.Contains(prefix, "getresponsebyscanstatus") ||
		strings.Contains(prefix, "getscanstatus") ||
		strings.Contains(prefix, "scan_pdf")
}

func (c *phConv) phpUnrestrictedVariableVariableAssignment(root *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	seen := map[string]bool{}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if n.Kind() == "foreach_statement" {
			text := c.text(n)
			if strings.Contains(text, "$_GET") &&
				strings.Contains(text, "$$") &&
				!phpVariableVariableKeyGuardBefore(text) {
				loc := c.phpVariableVariableAssignLoc(n)
				if !seen[loc] {
					seen[loc] = true
					path := "security.php.variable_variable.unrestricted"
					out = append(out, nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: path, Loc: loc},
						Path:   path,
						Method: lastSeg(path),
						Loc:    loc,
					}})
				}
			}
		}
		for _, ch := range namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
	return out
}

func phpVariableVariableKeyGuardBefore(foreachText string) bool {
	idx := strings.Index(foreachText, "$$")
	if idx < 0 {
		return false
	}
	prefix := strings.ToLower(foreachText[:idx])
	return strings.Contains(prefix, "preg_match") ||
		strings.Contains(prefix, "in_array") ||
		strings.Contains(prefix, "array_key_exists")
}

func (c *phConv) phpVariableVariableAssignLoc(n *tree_sitter.Node) string {
	loc := c.loc(n)
	var walk func(*tree_sitter.Node)
	walk = func(cur *tree_sitter.Node) {
		if cur == nil {
			return
		}
		if cur.Kind() == "assignment_expression" && strings.Contains(c.text(cur), "$$") {
			loc = c.loc(cur)
			return
		}
		for _, ch := range namedChildren(cur) {
			walk(ch)
		}
	}
	walk(n)
	return loc
}

// foreachVarNames collects the bare variable names bound by a foreach value-spec —
// `$v` (variable_name), `&$v` (by_ref), `[$a,$b]` (list_literal), or `$k => $v` (pair).
func (c *phConv) foreachVarNames(n *tree_sitter.Node, out *[]string) {
	if n == nil {
		return
	}
	switch n.Kind() {
	case "variable_name":
		*out = append(*out, c.text(n))
	case "by_ref", "list_literal", "pair":
		for _, ch := range namedChildren(n) {
			c.foreachVarNames(ch, out)
		}
	}
}

func (c *phConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "variable_name", "name":
		return nir.Name{ID: c.text(n), Loc: L}
	case "null", "shell_command_expression":
		return nir.Const{Loc: L}
	case "integer", "float":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "boolean":
		return nir.Const{Loc: L, Value: c.text(n)} // true/false value for `val` matching
	case "string":
		return nir.Const{Loc: L, Value: c.text(n)}
	case "encapsed_string", "heredoc", "string_value":
		// interpolated string: taint-propagating over the embedded variables
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "variable_name" || ch.Kind() == "member_access_expression" ||
				ch.Kind() == "subscript_expression" || ch.Kind() == "dynamic_variable_name" {
				parts = append(parts, c.expr(ch))
			}
		}
		if len(parts) > 0 {
			return nir.Format{Parts: parts, Loc: L}
		}
		return nir.Const{Loc: L, Value: c.text(n)} // non-interpolated → literal value
	case "member_access_expression":
		return nir.Attr{Base: c.expr(field(n, "object")), Attr: c.text(field(n, "name")), Path: c.dotted(n), Loc: L}
	case "subscript_expression":
		kids := namedChildren(n)
		var base, key nir.Expr = nir.Const{Loc: L}, nil
		if len(kids) > 0 {
			base = c.expr(kids[0])
		}
		if len(kids) > 1 {
			key = c.expr(kids[1])
		}
		return nir.Index{Base: base, Key: key, Path: c.dotted(n), Loc: L}
	case "function_call_expression":
		fn := field(n, "function")
		path := c.dotted(fn)
		return nir.Call{Callee: c.expr(fn), Args: c.callArgs(field(n, "arguments")), Path: path, Method: lastSeg(path), Loc: L}
	case "member_call_expression":
		name := c.text(field(n, "name"))
		path := c.dotted(n)
		return nir.Call{Callee: nir.Attr{Base: c.expr(field(n, "object")), Attr: name, Path: path, Loc: L},
			Args: c.callArgs(field(n, "arguments")), Path: path, Method: name, Loc: L}
	case "scoped_call_expression":
		name := c.text(field(n, "name"))
		path := c.dotted(n)
		return nir.Call{Callee: nir.Name{ID: path, Loc: L}, Args: c.callArgs(field(n, "arguments")), Path: path, Method: name, Loc: L}
	case "object_creation_expression":
		var typ string
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "name" || ch.Kind() == "qualified_name" {
				typ = c.text(ch)
				break
			}
		}
		return nir.Call{Callee: nir.Name{ID: typ, Loc: L}, Args: c.callArgs(field(n, "arguments")), Path: typ, Method: typ, Loc: L}
	case "binary_expression":
		op := c.text(field(n, "operator"))
		left, right := c.expr(field(n, "left")), c.expr(field(n, "right"))
		if op == "." || op == "+" {
			return nir.Format{Parts: []nir.Expr{left, right}, Loc: L} // string concat
		}
		return nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
	case "unary_op_expression":
		return nir.Unary{Op: c.text(field(n, "operator")), Operand: c.expr(field(n, "operand")), Loc: L}
	case "parenthesized_expression", "cast_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[len(kids)-1])}
		}
	case "array_creation_expression":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "array_element_initializer" {
				k := namedChildren(ch)
				switch {
				case len(k) >= 2: // key => value (named-value matching)
					parts = append(parts, nir.Pair{Key: c.keyName(k[0]), Value: c.expr(k[len(k)-1]), Loc: L})
				case len(k) == 1:
					parts = append(parts, c.expr(k[0]))
				}
			}
		}
		return nir.Seq{Parts: parts, Loc: L}
	case "conditional_expression":
		return nir.Ternary{Cond: c.expr(field(n, "condition")), Then: c.expr(field(n, "consequence")), Else: c.expr(field(n, "alternative")), Loc: L}
	case "anonymous_function", "anonymous_function_creation_expression":
		// `function ($req, $res) use ($x) { … }` — a closure (the dominant PHP route-handler
		// shape, e.g. Utopia/Slim `->action(function (...) { … })`). Without this it fell to the
		// Seq fallback below, which expr's the body instead of lowering its statements, so
		// variable reads never connected to their writes and all in-handler taint was lost.
		// Captured `use (...)` vars are free vars resolved from the enclosing scope by the
		// lambda closure-capture in lowering, so they need not be params.
		return nir.Lambda{Params: c.params(field(n, "parameters")), ParamTypes: c.paramTypes(field(n, "parameters")),
			Body: c.block(field(n, "body")), Loc: L}
	case "arrow_function":
		// `fn ($x) => expr` — single-expression closure; model the body as a return.
		return nir.Lambda{Params: c.params(field(n, "parameters")), ParamTypes: c.paramTypes(field(n, "parameters")),
			Body: []nir.Stmt{nir.Return{Value: c.expr(field(n, "body"))}}, Loc: L}
	}
	var parts []nir.Expr
	for _, ch := range namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
}

// keyName returns the bare name of an array key — a string literal with quotes
// stripped (e.g. 'httponly'), or a constant/name as-is (e.g. CURLOPT_SSL_VERIFYPEER).
func (c *phConv) keyName(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	t := c.text(n)
	if (n.Kind() == "string" || n.Kind() == "encapsed_string") && len(t) >= 2 {
		t = t[1 : len(t)-1]
	}
	return t
}

func (c *phConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "variable_name", "name", "qualified_name":
		// PHP global-namespace qualifier: `\file_get_contents` / `Foo\Bar\baz` — strip the
		// leading `\` and map namespace separators to the dotted form adapters match against,
		// else a fully-qualified builtin call (`\realpath`, `@\file_get_contents`) misses its sink.
		return strings.ReplaceAll(strings.TrimPrefix(c.text(n), `\`), `\`, ".")
	case "member_access_expression":
		return c.dotted(field(n, "object")) + "." + c.text(field(n, "name"))
	case "member_call_expression":
		return c.dotted(field(n, "object")) + "." + c.text(field(n, "name"))
	case "scoped_call_expression":
		return c.text(field(n, "scope")) + "." + c.text(field(n, "name"))
	case "function_call_expression":
		return c.dotted(field(n, "function"))
	case "subscript_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return c.dotted(kids[0])
		}
	}
	return "?"
}
