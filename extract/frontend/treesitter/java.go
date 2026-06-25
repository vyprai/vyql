package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsjava "github.com/tree-sitter/tree-sitter-java/bindings/go"

	"github.com/vyprai/vyql/extract/nir"
)

// jvConv walks a tree-sitter Java CST into NIR.
type jvConv struct {
	src                []byte
	root               string
	file               string
	key                string
	classParamTokens   []string
	classContextTokens []string
}

// javaPublic reports whether a method/constructor is part of the public API surface:
// it carries a `public` modifier (package-private/private/protected are not the API a
// library exposes to arbitrary callers). Used to scope the library param-source.
func (c *jvConv) javaPublic(n *tree_sitter.Node) bool {
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "modifiers" {
			t := c.text(ch)
			if strings.Contains(t, "private") || strings.Contains(t, "protected") {
				return false
			}
			return strings.Contains(t, "public")
		}
	}
	return false
}

// ExtractJava parses Java files into one NIR Program (one module per file, keyed
// by source-root-relative dotted path).
func ExtractJava(files []string, root string) (nir.Program, error) {
	mods := parseModules(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(tree_sitter.NewLanguage(tsjava.Language()))
			return p
		},
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			c := &jvConv{src: src, root: root, file: rel, key: moduleKey(root, abs, ".java")}
			r := tree.RootNode()
			return nir.Module{Key: c.key, File: rel, Imports: c.imports(r), Body: c.decls(r)}, true
		})
	return nir.Program{SelfName: "this", Modules: mods}, nil
}

func (c *jvConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *jvConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

// simpleTypeName returns a bare user-class type name from a declaration's `type`
// node — e.g. `UserService` (from `UserService`, `com.x.UserService`, or
// `List<UserService>` it returns the head). Primitives and `String`/`var` yield "".
func (c *jvConv) simpleTypeName(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	switch n.Kind() {
	case "type_identifier", "scoped_type_identifier":
		t := c.text(n)
		if i := strings.LastIndex(t, "."); i >= 0 {
			t = t[i+1:]
		}
		switch t {
		case "String", "Object", "Integer", "Long", "Boolean", "Double", "Float", "var":
			return ""
		}
		return t
	case "generic_type":
		if k := namedChildren(n); len(k) > 0 {
			return c.simpleTypeName(k[0])
		}
	}
	return ""
}

func (c *jvConv) imports(root *tree_sitter.Node) []nir.Import {
	var out []nir.Import
	var walk func(n *tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n.Kind() == "import_declaration" {
			for _, ch := range namedChildren(n) {
				if ch.Kind() == "scoped_identifier" || ch.Kind() == "identifier" {
					full := c.text(ch)
					out = append(out, nir.Import{Local: lastSeg(full), Module: full, IsModule: true})
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

// decls lowers top-level + class-member declarations.
func (c *jvConv) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range namedChildren(n) {
		out = append(out, c.stmt(ch)...)
	}
	return out
}

func (c *jvConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "class_declaration", "interface_declaration", "enum_declaration", "record_declaration":
		name := c.text(field(n, "name"))
		bases := c.jvClassBases(n)
		prevParams := c.classParamTokens
		prevContext := c.classContextTokens
		c.classParamTokens = append(append([]string{}, prevParams...), c.jvAnnotationTokens(n, "class_annotation:")...)
		c.classContextTokens = append(append([]string{}, prevContext...), javaClassContextTokens(name, bases)...)
		c.classContextTokens = append(c.classContextTokens, c.jvModifierTokens(n, "class_modifier:")...)
		cd := nir.ClassDef{Name: name, Body: c.decls(field(n, "body")), Loc: L, Bases: bases}
		c.classParamTokens = prevParams
		c.classContextTokens = prevContext
		return []nir.Stmt{cd}
	case "method_declaration", "constructor_declaration":
		name := c.text(field(n, "name"))
		paramsNode := field(n, "parameters")
		params := c.params(paramsNode)
		paramTypes := c.paramTypes(paramsNode)
		body := c.block(field(n, "body"))
		annotationTokens := c.jvAnnotationTokens(n, "annotation:")
		tokens := append([]string{}, c.classParamTokens...)
		tokens = append(tokens, annotationTokens...)
		contextTokens := append([]string{}, c.classContextTokens...)
		contextTokens = append(contextTokens, annotationTokens...)
		contextTokens = append(contextTokens, c.jvModifierTokens(n, "function_modifier:")...)
		contextTokens = append(contextTokens, c.jvSensitiveMetadataExportTokens(n)...)
		contextTokens = append(contextTokens, c.jvFunctionTokens(name, n, params, paramTypes)...)
		return []nir.Stmt{nir.FuncDef{Name: name, Params: params, ParamTypes: paramTypes, Body: body, Loc: L,
			ContextTokens: contextTokens,
			ParamEntries:  c.jvParamEntries(name, params, paramTypes, tokens, c.jvParamAnnotationTokens(paramsNode)), Exported: c.javaPublic(n)}}
	case "field_declaration", "local_variable_declaration":
		var out []nir.Stmt
		declType := c.simpleTypeName(field(n, "type")) // declared class type, for cross-file resolution
		for _, d := range namedChildren(n) {
			if d.Kind() == "variable_declarator" {
				name := field(d, "name")
				val := field(d, "value")
				var v nir.Expr = nir.Const{Loc: L}
				if val != nil {
					v = c.expr(val)
				}
				if name != nil {
					out = append(out, nir.Assign{Targets: []string{c.text(name)}, Value: v, Type: declType})
				}
			}
		}
		return out
	case "expression_statement":
		kids := namedChildren(n)
		if len(kids) == 0 {
			return nil
		}
		return c.exprStmt(kids[0])
	case "return_statement":
		kids := namedChildren(n)
		if len(kids) > 0 {
			return []nir.Stmt{nir.Return{Value: c.expr(kids[0])}}
		}
		return []nir.Stmt{nir.Return{}}
	// branch-structured (B1). Java did not evaluate the condition before, so Cond stays
	// nil → the flattened node set is byte-identical.
	case "if_statement":
		// Separate Then/Else branches (not a flattened single list) so the join-merge
		// keeps a value tainted on one path even when the other path overwrites it with a
		// constant (`if (c) x = src(); else x = "safe";`). A nested if/else in either
		// branch is structured by c.stmt (proper else-if chaining).
		return []nir.Stmt{nir.If{Cond: c.expr(field(n, "condition")), Then: c.branchBody(field(n, "consequence")), Else: c.branchBody(field(n, "alternative"))}}
	case "while_statement", "for_statement", "do_statement":
		return []nir.Stmt{nir.Loop{Body: c.collectBlocks(n)}}
	case "enhanced_for_statement":
		// `for (T x : coll)` — bind the loop variable to the iterable so a tainted
		// collection taints each element (flow-approximate element-of).
		body := c.collectBlocks(n)
		if nm, val := field(n, "name"), field(n, "value"); nm != nil && val != nil {
			body = append([]nir.Stmt{nir.Assign{Targets: []string{c.text(nm)}, Value: c.expr(val)}}, body...)
		}
		return []nir.Stmt{nir.Loop{Body: body}}
	case "try_statement", "try_with_resources_statement":
		return []nir.Stmt{c.tryStmt(n)}
	case "switch_expression":
		// each `case` group is a separate Switch branch so the join-merge keeps a value
		// tainted on one arm even when another arm overwrites it (`case 'A': bar = src();`
		// vs `case 'B': bar = "safe";`). Classic colon-form; arrow/yield form has no
		// statement groups and falls back to a flat Block.
		var cases [][]nir.Stmt
		var labels [][]nir.Expr
		var deflt []nir.Stmt
		var hasGroups bool
		var pending []nir.Expr // labels of empty (fall-through) case groups, merged into the next body
		for _, blk := range children(n) {
			if blk.Kind() != "switch_block" {
				continue
			}
			for _, grp := range children(blk) {
				if grp.Kind() != "switch_block_statement_group" {
					continue
				}
				hasGroups = true
				var stmts []nir.Stmt
				var labs []nir.Expr
				isDefault := false
				for _, ch := range children(grp) {
					if ch.Kind() == "switch_label" {
						if strings.Contains(c.text(ch), "default") {
							isDefault = true
						} else if lk := namedChildren(ch); len(lk) > 0 {
							labs = append(labs, c.expr(lk[0])) // the case's label value(s)
						}
						continue
					}
					stmts = append(stmts, c.stmt(ch)...)
				}
				if isDefault {
					deflt = append(deflt, stmts...)
					continue
				}
				pending = append(pending, labs...)
				if len(stmts) > 0 { // body present — flush the accumulated fall-through labels with it
					cases = append(cases, stmts)
					labels = append(labels, pending)
					pending = nil
				}
			}
		}
		if hasGroups {
			return []nir.Stmt{nir.Switch{Subject: c.expr(field(n, "condition")), Cases: cases, Labels: labels, Default: deflt}}
		}
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	case "block", "synchronized_statement":
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	case "static_initializer", "constructor_body":
		return []nir.Stmt{nir.Block{Stmts: c.block(n)}}
	}
	return nil
}

func (c *jvConv) exprStmt(inner *tree_sitter.Node) []nir.Stmt {
	switch inner.Kind() {
	case "assignment_expression":
		left := field(inner, "left")
		right := c.expr(field(inner, "right"))
		if left != nil && left.Kind() == "identifier" {
			return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: right}}
		}
		return []nir.Stmt{nir.ExprStmt{Value: right}}
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(inner)}}
}

// branchBody flattens a single if-branch body: a `{}` block, a brace-less single
// statement, or a nested control statement (structured by c.stmt).
func (c *jvConv) branchBody(b *tree_sitter.Node) []nir.Stmt {
	if b == nil {
		return nil
	}
	if b.Kind() == "block" {
		return c.block(b)
	}
	return c.stmt(b)
}

func (c *jvConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	// handled reports whether a body-position node was already collected/flattened by
	// the children walk below (a brace block, or a nested if/else flattened into this
	// same list). Used to avoid double-lowering when picking up brace-less bodies.
	handled := func(k string) bool {
		switch k {
		case "block", "constructor_body", "switch_block", "switch_block_statement_group",
			"catch_clause", "finally_clause", "resource_specification", "if_statement", "else":
			return true
		}
		return false
	}
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "block", "constructor_body":
				out = append(out, c.block(ch)...)
			case "switch_block", "switch_block_statement_group", "catch_clause", "finally_clause",
				"resource_specification", "if_statement", "else":
				walk(ch)
			case "resource":
				// try-with-resources `try (T x = new FileInputStream(path); …)` — lower the
				// resource initializer (often a file/stream sink) and bind its variable.
				if val := field(ch, "value"); val != nil {
					v := c.expr(val)
					if nm := field(ch, "name"); nm != nil {
						out = append(out, nir.Assign{Targets: []string{c.text(nm)}, Value: v})
					} else {
						out = append(out, nir.ExprStmt{Value: v})
					}
				}
			}
		}
		// brace-less single-statement bodies (`if (x) foo = y;` with no `{}`): the
		// consequence/alternative/body field points straight at the statement instead of a
		// block, so the children walk above skips it. Lower it here. A nested if/loop/try
		// body is structured by c.stmt; a block or already-flattened if is skipped.
		for _, f := range []string{"consequence", "alternative", "body"} {
			if b := field(m, f); b != nil && !handled(b.Kind()) {
				out = append(out, c.stmt(b)...)
			}
		}
	}
	if n.Kind() == "block" {
		return c.block(n)
	}
	walk(n)
	return out
}

func (c *jvConv) tryStmt(n *tree_sitter.Node) nir.Try {
	var body []nir.Stmt
	var resourceNames []string
	var handlers [][]nir.Stmt
	var handlerParams []string
	var finally []nir.Stmt
	bodySeen := false
	for _, ch := range namedChildren(n) {
		switch ch.Kind() {
		case "resource_specification":
			body = append(body, c.collectBlocks(ch)...)
			resourceNames = append(resourceNames, c.resourceNames(ch)...)
		case "block":
			if !bodySeen {
				body = append(body, c.block(ch)...)
				bodySeen = true
			}
		case "catch_clause":
			handlerParams = append(handlerParams, c.catchParam(ch))
			handlers = append(handlers, c.collectBlocks(ch))
		case "finally_clause":
			finally = append(finally, c.collectBlocks(ch)...)
		}
	}
	if !bodySeen && len(body) == 0 {
		body = c.collectBlocks(n)
	}
	for _, name := range resourceNames {
		body = append(body, c.implicitClose(name, c.loc(n)))
	}
	return nir.Try{Body: body, Handlers: handlers, HandlerParams: handlerParams, Finally: finally, Loc: c.loc(n)}
}

func (c *jvConv) resourceNames(n *tree_sitter.Node) []string {
	var names []string
	var walk func(*tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		if m == nil {
			return
		}
		if m.Kind() == "resource" {
			if nm := field(m, "name"); nm != nil {
				names = append(names, c.text(nm))
			}
			return
		}
		for _, ch := range namedChildren(m) {
			walk(ch)
		}
	}
	walk(n)
	return names
}

func (c *jvConv) implicitClose(name, loc string) nir.Stmt {
	return nir.ExprStmt{Value: nir.Call{
		Callee: nir.Attr{Base: nir.Name{ID: name, Loc: loc}, Attr: "close", Path: name + ".close", Loc: loc},
		Path:   name + ".close",
		Method: "close",
		Loc:    loc,
	}}
}

func (c *jvConv) catchParam(n *tree_sitter.Node) string {
	var found string
	var walk func(*tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		if m == nil || found != "" {
			return
		}
		if m.Kind() == "formal_parameter" || m.Kind() == "catch_formal_parameter" {
			if nm := field(m, "name"); nm != nil {
				found = c.text(nm)
				return
			}
		}
		for _, ch := range namedChildren(m) {
			walk(ch)
		}
	}
	walk(n)
	return found
}

func (c *jvConv) block(block *tree_sitter.Node) []nir.Stmt {
	if block == nil {
		return nil
	}
	var out []nir.Stmt
	for _, st := range namedChildren(block) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *jvConv) params(params *tree_sitter.Node) []string {
	if params == nil {
		return nil
	}
	var out []string
	for _, ch := range namedChildren(params) {
		if ch.Kind() == "formal_parameter" || ch.Kind() == "spread_parameter" {
			if nm := field(ch, "name"); nm != nil {
				out = append(out, c.text(nm))
			}
		}
	}
	return out
}

func (c *jvConv) paramTypes(params *tree_sitter.Node) map[string]string {
	out := map[string]string{}
	if params == nil {
		return out
	}
	for _, ch := range namedChildren(params) {
		if ch.Kind() == "formal_parameter" || ch.Kind() == "spread_parameter" {
			if nm := field(ch, "name"); nm != nil {
				putParamType(out, c.text(nm), paramTypeFromField(c, ch))
			}
		}
	}
	return out
}

func (c *jvConv) jvClassBases(n *tree_sitter.Node) []string {
	var out []string
	add := func(base string) {
		base = javaBaseTypeName(base)
		if base == "" {
			return
		}
		for _, seen := range out {
			if seen == base {
				return
			}
		}
		out = append(out, base)
	}
	var walkTypes func(*tree_sitter.Node)
	walkTypes = func(m *tree_sitter.Node) {
		if m == nil {
			return
		}
		switch m.Kind() {
		case "type_identifier", "scoped_type_identifier", "generic_type":
			add(c.text(m))
			return
		}
		for _, ch := range namedChildren(m) {
			walkTypes(ch)
		}
	}
	walkTypes(field(n, "superclass"))
	walkTypes(field(n, "interfaces"))
	return out
}

func javaBaseTypeName(s string) string {
	if i := strings.IndexByte(s, '<'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '.'); i >= 0 {
		s = s[i+1:]
	}
	return s
}

func javaClassContextTokens(name string, bases []string) []string {
	var out []string
	if name != "" {
		out = append(out, "class_name:"+name)
	}
	for _, base := range bases {
		if base != "" {
			out = append(out, "class_base:"+base)
		}
	}
	return out
}

// jvAnnotationTokens extracts syntax-level annotation names without interpreting
// framework/domain meaning. Adapters decide what each token means.
func (c *jvConv) jvAnnotationTokens(n *tree_sitter.Node, prefix string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, prefix+name)
	}
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		if m == nil {
			return
		}
		if m.Kind() == "marker_annotation" || m.Kind() == "annotation" {
			for _, k := range namedChildren(m) {
				if k.Kind() == "identifier" || k.Kind() == "scoped_identifier" {
					full := c.text(k)
					add(full)
					if short := lastSeg(full); short != "" && short != full {
						add(short)
					}
					break
				}
			}
			return
		}
		for _, ch := range namedChildren(m) {
			walk(ch)
		}
	}
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "modifiers" {
			walk(ch)
		}
	}
	return out
}

func (c *jvConv) jvModifierTokens(n *tree_sitter.Node, prefix string) []string {
	var mods string
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "modifiers" {
			mods = c.text(ch)
			break
		}
	}
	if mods == "" {
		return nil
	}
	var out []string
	for _, mod := range []string{"public", "protected", "private", "static", "final", "abstract", "synchronized", "native", "strictfp"} {
		if javaContainsWord(mods, mod) {
			out = append(out, prefix+mod)
		}
	}
	return out
}

func javaContainsWord(s, word string) bool {
	for {
		i := strings.Index(s, word)
		if i < 0 {
			return false
		}
		before := i == 0 || !javaIdentRune(rune(s[i-1]))
		afterIdx := i + len(word)
		after := afterIdx >= len(s) || !javaIdentRune(rune(s[afterIdx]))
		if before && after {
			return true
		}
		s = s[afterIdx:]
	}
}

func javaIdentRune(r rune) bool {
	return r == '_' || r == '$' || (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
}

func (c *jvConv) jvFunctionTokens(name string, n *tree_sitter.Node, params []string, paramTypes map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(tok string) {
		if tok == "" || seen[tok] || len(out) >= 512 {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	if name != "" {
		add("function_name:" + name)
	}
	text := c.text(n)
	add(text)
	add(javaCompactText(text))
	for i, param := range params {
		if param == "" {
			continue
		}
		add("param_name:" + param)
		add("param_index:" + itoa(i))
		if typ := paramTypes[param]; typ != "" {
			add("param_type:" + typ)
		}
	}
	prevCall := ""
	var walk func(*tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		if m == nil || len(out) >= 512 {
			return
		}
		switch m.Kind() {
		case "method_invocation":
			if p := c.dotted(m); p != "" && p != "?" {
				if prevCall != "" {
					add("call_order:" + prevCall + ">" + p)
				}
				prevCall = p
				add("call_path:" + p)
			}
			if nm := c.text(field(m, "name")); nm != "" {
				add("call:" + nm)
			}
		case "object_creation_expression":
			if typ := c.dotted(field(m, "type")); typ != "" && typ != "?" {
				if prevCall != "" {
					add("call_order:" + prevCall + ">" + typ)
				}
				prevCall = typ
				add("call_path:" + typ)
				add("call:" + lastSeg(typ))
			}
		case "field_access":
			if p := c.dotted(m); p != "" && p != "?" {
				add("selector:" + p)
			}
			if fld := c.text(field(m, "field")); fld != "" {
				add("selector:" + fld)
			}
		case "binary_expression":
			if expr := javaExprToken(c.text(m)); expr != "" {
				add("expr:" + expr)
			}
		case "string_literal":
			if lit := javaStringToken(c.text(m)); lit != "" {
				add("literal:" + lit)
			}
		case "decimal_integer_literal", "hex_integer_literal", "decimal_floating_point_literal",
			"character_literal":
			if lit := strings.TrimSpace(c.text(m)); lit != "" {
				add("literal:" + lit)
			}
		case "identifier":
			if ident := c.text(m); ident != "" {
				add("identifier:" + ident)
			}
		}
		for _, ch := range namedChildren(m) {
			walk(ch)
		}
	}
	walk(n)
	return out
}

func (c *jvConv) jvSensitiveMetadataExportTokens(n *tree_sitter.Node) []string {
	seen := map[string]bool{}
	added := map[string]map[string]bool{}
	var stack []string
	var out []string
	addToken := func(tok string) {
		if tok == "" || seen[tok] || len(out) >= 64 {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	addKey := func(obj, key string) {
		if obj == "" || key == "" || !javaSensitiveMetadataKey(key) {
			return
		}
		if added[obj] == nil {
			added[obj] = map[string]bool{}
		}
		added[obj][key] = true
	}
	var walk func(*tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		if m == nil || len(out) >= 64 {
			return
		}
		if m.Kind() == "enhanced_for_statement" {
			if base := c.jvPropertiesIterableBase(field(m, "value")); base != "" {
				stack = append(stack, base)
				for _, ch := range namedChildren(m) {
					if ch != field(m, "value") {
						walk(ch)
					}
				}
				stack = stack[:len(stack)-1]
				return
			}
		}
		if m.Kind() == "method_invocation" {
			path := c.dotted(m)
			method := lastSeg(path)
			base := javaPathBase(path)
			switch method {
			case "add", "put", "set":
				addKey(base, c.jvFirstStringArg(m))
			case "metadata", "putMetadata", "setMetadata", "writeMetadata":
				for _, obj := range stack {
					for key := range added[obj] {
						addToken("metadata_export_after_sensitive_key:" + key)
						addToken("metadata_export_after_sensitive_source:" + obj + "." + key)
						addToken("metadata_export_writer:" + path)
					}
				}
			}
		}
		for _, ch := range namedChildren(m) {
			walk(ch)
		}
	}
	walk(n)
	return out
}

func (c *jvConv) jvPropertiesIterableBase(n *tree_sitter.Node) string {
	if n == nil || n.Kind() != "method_invocation" {
		return ""
	}
	path := c.dotted(n)
	switch lastSeg(path) {
	case "getProperties", "entrySet", "propertySet":
		return javaPathBase(path)
	default:
		return ""
	}
}

func (c *jvConv) jvFirstStringArg(n *tree_sitter.Node) string {
	args := field(n, "arguments")
	if args == nil {
		return ""
	}
	for _, ch := range namedChildren(args) {
		if ch.Kind() == "string_literal" {
			return javaStringToken(c.text(ch))
		}
		return ""
	}
	return ""
}

func javaPathBase(path string) string {
	if i := strings.LastIndex(path, "."); i > 0 {
		return path[:i]
	}
	return ""
}

func javaSensitiveMetadataKey(key string) bool {
	k := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", ""), "_", ""))
	switch k {
	case "reposource", "repository", "repositoryurl", "gitsource", "gitremote", "originurl", "remoteurl":
		return true
	default:
		return strings.Contains(k, "repo") && (strings.Contains(k, "source") || strings.Contains(k, "url"))
	}
}

func javaExprToken(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		if r != ' ' && r != '\t' && r != '\n' && r != '\r' {
			b.WriteRune(r)
		}
		if b.Len() >= 256 {
			break
		}
	}
	return b.String()
}

func javaCompactText(s string) string {
	return strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "").Replace(s)
}

func javaStringToken(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	raw = strings.TrimPrefix(raw, "\"")
	raw = strings.TrimSuffix(raw, "\"")
	if raw == "" {
		return ""
	}
	if len(raw) > 256 {
		raw = raw[:256]
	}
	return raw
}

func (c *jvConv) jvParamAnnotationTokens(params *tree_sitter.Node) map[string][]string {
	out := map[string][]string{}
	if params == nil {
		return out
	}
	for _, ch := range namedChildren(params) {
		if ch.Kind() != "formal_parameter" && ch.Kind() != "spread_parameter" {
			continue
		}
		nm := field(ch, "name")
		if nm == nil {
			continue
		}
		toks := c.jvAnnotationTokens(ch, "annotation:")
		if len(toks) > 0 {
			out[c.text(nm)] = toks
		}
	}
	return out
}

func (c *jvConv) jvParamEntries(name string, params []string, paramTypes map[string]string, base []string, paramAnnotations map[string][]string) []nir.ParamEntry {
	funcTokens := append([]string{}, base...)
	for _, typ := range paramTypes {
		if typ == "" {
			continue
		}
		funcTokens = append(funcTokens, "has_param_type:"+typ)
		if short := lastSeg(typ); short != "" && short != typ {
			funcTokens = append(funcTokens, "has_param_type:"+short)
		}
	}
	out := make([]nir.ParamEntry, 0, len(params))
	for i, p := range params {
		if p == "" || p == "_" {
			continue
		}
		tokens := append([]string{}, funcTokens...)
		tokens = append(tokens, paramAnnotations[p]...)
		tokens = append(tokens, "function_name:"+name, "param_name:"+p, "param_index:"+itoa(i))
		if typ := paramTypes[p]; typ != "" {
			tokens = append(tokens, "param_type:"+typ)
			if short := lastSeg(typ); short != "" && short != typ {
				tokens = append(tokens, "param_type:"+short)
			}
		}
		out = append(out, nir.ParamEntry{Param: p, Tokens: tokens})
	}
	return out
}

func (c *jvConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "identifier", "this", "super":
		return nir.Name{ID: c.text(n), Loc: L}
	case "null_literal":
		return nir.Const{Loc: L}
	case "decimal_integer_literal", "hex_integer_literal", "decimal_floating_point_literal",
		"character_literal":
		// carry the literal text so constant-folding (opaque branch conditions) and numeric
		// value-matching (e.g. chmod modes) can read it.
		return nir.Const{Loc: L, Value: c.text(n)}
	case "true", "false":
		return nir.Const{Loc: L, Value: c.text(n)} // boolean value for `val` matching
	case "string_literal":
		// pick up interpolation in text blocks if any; otherwise constant
		return nir.Const{Loc: L, Value: c.text(n)}
	case "field_access":
		return nir.Attr{Base: c.expr(field(n, "object")), Attr: c.text(field(n, "field")), Path: c.dotted(n), Loc: L}
	case "array_access":
		return nir.Index{Base: c.expr(field(n, "array")), Key: c.expr(field(n, "index")), Path: c.dotted(field(n, "array")), Loc: L}
	case "method_invocation":
		obj := field(n, "object")
		name := c.text(field(n, "name"))
		path := c.dotted(n)
		var arglist []nir.Expr
		if args := field(n, "arguments"); args != nil {
			for _, a := range namedChildren(args) {
				arglist = append(arglist, c.expr(a))
			}
		}
		var callee nir.Expr
		if obj != nil {
			callee = nir.Attr{Base: c.expr(obj), Attr: name, Path: path, Loc: L}
		} else {
			callee = nir.Name{ID: name, Loc: L}
		}
		return nir.Call{Callee: callee, Args: arglist, Path: path, Method: name, Loc: L}
	case "object_creation_expression":
		typ := c.text(field(n, "type"))
		var arglist []nir.Expr
		if args := field(n, "arguments"); args != nil {
			for _, a := range namedChildren(args) {
				arglist = append(arglist, c.expr(a))
			}
		}
		// model `new T(args)` as a constructor call with callee path "T", so
		// adapters can match constructor and type information.
		return nir.Call{Callee: nir.Name{ID: typ, Loc: L}, Args: arglist, Path: typ, Method: typ, Loc: L}
	case "binary_expression":
		op := c.text(field(n, "operator"))
		left, right := c.expr(field(n, "left")), c.expr(field(n, "right"))
		if op == "+" {
			// `+` is overloaded (string concat / arithmetic); keep it a taint-propagating
			// Format so string-building flows are preserved.
			return nir.Format{Parts: []nir.Expr{left, right}, Loc: L}
		}
		// other operators (-, *, /, %, >, <, ==, &&, …) preserve the operator for constant
		// evaluation of opaque branch conditions; BinOp also flows taint through both sides.
		return nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
	case "unary_expression":
		return nir.Unary{Op: c.text(field(n, "operator")), Operand: c.expr(field(n, "operand")), Loc: L}
	case "parenthesized_expression", "cast_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[len(kids)-1])}
		}
	case "ternary_expression":
		return nir.Ternary{Cond: c.expr(field(n, "condition")), Then: c.expr(field(n, "consequence")), Else: c.expr(field(n, "alternative")), Loc: L}
	case "array_initializer":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			parts = append(parts, c.expr(ch))
		}
		return nir.Seq{Parts: parts, Loc: L}
	}
	var parts []nir.Expr
	for _, ch := range namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
}

func (c *jvConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "identifier", "this", "super", "type_identifier", "scoped_identifier":
		return c.text(n)
	case "field_access":
		return c.dotted(field(n, "object")) + "." + c.text(field(n, "field"))
	case "method_invocation":
		obj := field(n, "object")
		name := c.text(field(n, "name"))
		if obj == nil {
			return name
		}
		return c.dotted(obj) + "." + name
	case "array_access":
		return c.dotted(field(n, "array")) + "[]"
	case "object_creation_expression":
		return c.text(field(n, "type"))
	case "parenthesized_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return c.dotted(kids[0])
		}
	}
	if strings.Contains(c.text(n), ".") {
		return c.text(n)
	}
	return "?"
}
