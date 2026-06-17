package treesitter

import (
	"regexp"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsc "github.com/tree-sitter/tree-sitter-c/bindings/go"
	tscpp "github.com/tree-sitter/tree-sitter-cpp/bindings/go"

	objc "github.com/vyprai/vyql/extract/frontend/treesitter/grammars/objc"

	"github.com/vyprai/vyql/extract/nir"
)

// ccConv walks a tree-sitter C CST into NIR. C has no string-concat operator:
// untrusted data reaches a buffer through writer functions (sprintf/strcpy/…),
// so those are modeled as an ASSIGNMENT to their destination argument, and
// reader functions (fgets/gets/…) seed their destination buffer as a source.
type ccConv struct {
	src  []byte
	file string
	key  string
}

// cPropagators taint their dest (arg0) from the remaining (source) arguments.
var cPropagators = map[string]bool{
	"sprintf": true, "snprintf": true, "vsprintf": true, "vsnprintf": true,
	"strcpy": true, "strncpy": true, "strcat": true, "strncat": true,
	"memcpy": true, "memmove": true, "stpcpy": true,
}

// cReaders read external input into a destination BUFFER argument; the value is the
// arg index of that buffer (recv/read take the buffer at arg1, not arg0).
var cReaders = map[string]int{
	"fgets": 0, "gets": 0, "fread": 0, "fscanf": 0,
	"read": 1, "recv": 1, "recvfrom": 1, "pread": 1,
}

// ExtractC parses C files into one NIR Program (one module per file).
func ExtractC(files []string, root string) (nir.Program, error) {
	return extractCLike(files, root, ".c", tree_sitter.NewLanguage(tsc.Language()))
}

// ExtractCPP parses C++ files. The C/C++ grammars share the ccConv walker; the
// extra C++ node kinds (qualified_identifier, namespace/class, new_expression)
// are handled there and are inert for C.
func ExtractCPP(files []string, root string) (nir.Program, error) {
	return extractCLike(files, root, ".cpp", tree_sitter.NewLanguage(tscpp.Language()))
}

// ExtractObjC parses Objective-C (.m) files. ObjC is a C superset; ccConv reuses
// the C handling and adds message_expression + @implementation method nodes.
func ExtractObjC(files []string, root string) (nir.Program, error) {
	return extractCLike(files, root, ".m", tree_sitter.NewLanguage(objc.Language()))
}

func extractCLike(files []string, root, ext string, lang *tree_sitter.Language) (nir.Program, error) {
	// the *Language is immutable grammar data; each worker gets its own parser referencing it.
	mods := parseModules(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(lang)
			return p
		},
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			c := &ccConv{src: src, file: rel, key: moduleKey(root, abs, ext)}
			body := c.decls(tree.RootNode())
			body = append(body, c.ccLifetimeReleaseReturnObservations(tree.RootNode())...)
			return nir.Module{Key: c.key, File: rel, Body: body}, true
		})
	return nir.Program{SelfName: "this", Modules: mods}, nil
}

func (c *ccConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *ccConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

var (
	ccNewAssignRe = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\b`)
	ccDeleteRe    = regexp.MustCompile(`delete\s*(?:\[\]\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*;`)
)

func (c *ccConv) ccLifetimeReleaseReturnObservations(root *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	seen := map[string]bool{}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if n.Kind() == "function_definition" {
			text := c.text(n)
			allocated := map[string]bool{}
			for _, m := range ccNewAssignRe.FindAllStringSubmatch(text, -1) {
				if len(m) == 2 && !ccFunctionDeclaresLocal(text, m[1]) {
					allocated[m[1]] = true
				}
			}
			for _, m := range ccDeleteRe.FindAllStringSubmatchIndex(text, -1) {
				if len(m) < 4 {
					continue
				}
				name := text[m[2]:m[3]]
				if !allocated[name] {
					continue
				}
				after := strings.ToLower(text[m[1]:minInt(len(text), m[1]+160)])
				if !strings.Contains(after, "return(false)") && !strings.Contains(after, "return false") {
					continue
				}
				loc := c.locAt(n, text, m[0])
				if seen[loc] {
					continue
				}
				seen[loc] = true
				path := "analysis.lifetime.release_then_return"
				out = append(out, nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: path, Loc: loc},
					Args: []nir.Expr{
						nir.Const{Loc: loc, Value: "release=delete"},
						nir.Const{Loc: loc, Value: "return=false"},
						nir.Const{Loc: loc, Value: "storage=nonlocal"},
					},
					Path:   path,
					Method: "release_then_return",
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

func ccFunctionDeclaresLocal(fnText, name string) bool {
	for _, line := range strings.Split(fnText, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, name) || !strings.Contains(line, "=") {
			continue
		}
		if strings.Contains(line, "* "+name) || strings.Contains(line, "*"+name) ||
			strings.Contains(line, "& "+name) || strings.Contains(line, "&"+name) {
			return true
		}
	}
	return false
}

func (c *ccConv) locAt(fn *tree_sitter.Node, fnText string, offset int) string {
	line := int(fn.StartPosition().Row) + 1 + strings.Count(fnText[:offset], "\n")
	return c.file + ":" + itoa(line)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (c *ccConv) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range namedChildren(n) {
		out = append(out, c.stmt(ch)...)
	}
	return out
}

// objcMethod extracts an ObjC method's selector name, parameter names, and body.
func (c *ccConv) objcMethod(n *tree_sitter.Node) (string, []string, *tree_sitter.Node) {
	var name string
	var params []string
	var body *tree_sitter.Node
	for _, ch := range namedChildren(n) {
		switch ch.Kind() {
		case "identifier":
			if name == "" {
				name = c.text(ch)
			} else {
				name += ":" + c.text(ch)
			}
		case "method_parameter":
			for _, p := range namedChildren(ch) {
				if p.Kind() == "identifier" {
					params = append(params, c.text(p))
				}
			}
		case "compound_statement":
			body = ch
		}
	}
	return name, params, body
}

func sameCNode(a, b *tree_sitter.Node) bool {
	return a != nil && b != nil && a.StartByte() == b.StartByte() && a.EndByte() == b.EndByte()
}

func isCExprArg(k string) bool {
	switch k {
	case "identifier", "call_expression", "message_expression", "string_literal",
		"binary_expression", "field_expression", "subscript_expression", "cast_expression",
		"unary_expression", "number_literal", "concatenated_string":
		return true
	}
	return false
}

// declName unwraps pointer/array/function/parenthesized declarators to the
// underlying identifier name.
func (c *ccConv) declName(d *tree_sitter.Node) string {
	for d != nil {
		switch d.Kind() {
		case "identifier", "field_identifier", "type_identifier":
			return c.text(d)
		case "pointer_declarator", "array_declarator", "parenthesized_declarator",
			"init_declarator", "function_declarator":
			d = field(d, "declarator")
		default:
			if inner := field(d, "declarator"); inner != nil {
				d = inner
			} else {
				return ""
			}
		}
	}
	return ""
}

func (c *ccConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "function_definition":
		decl := field(n, "declarator")
		params := c.params(decl)
		if len(params) == 0 {
			params = c.params(n)
		}
		paramTypes := c.paramTypes(decl)
		if len(paramTypes) == 0 {
			paramTypes = c.paramTypes(n)
		}
		if len(params) == 0 {
			params, paramTypes = c.paramsFromSignatureText(c.text(n))
		}
		return []nir.Stmt{nir.FuncDef{
			Name:       c.declName(decl),
			Params:     params,
			ParamTypes: paramTypes,
			Body:       append(c.block(field(n, "body")), c.ccIndexAccessObservations(n)...),
			Loc:        L,
		}}
	case "struct_specifier", "union_specifier", "enum_specifier":
		return nil
	case "class_implementation", "class_interface", "category_implementation", // ObjC
		"category_interface", "protocol_declaration", "implementation_definition",
		"interface_declaration_list", "protocol_declaration_list":
		var out []nir.Stmt
		for _, ch := range namedChildren(n) {
			out = append(out, c.stmt(ch)...)
		}
		return out
	case "method_definition", "method_declaration": // ObjC method
		name, params, body := c.objcMethod(n)
		return []nir.Stmt{nir.FuncDef{Name: name, Params: params, ParamTypes: c.objcParamTypes(n, params), Body: c.block(body), Loc: L}}
	case "namespace_definition", "linkage_specification", "declaration_list": // C++
		if b := field(n, "body"); b != nil {
			return c.decls(b)
		}
		return c.decls(n)
	case "template_declaration": // C++ — process the templated decl
		return c.decls(n)
	case "class_specifier": // C++
		return []nir.Stmt{nir.ClassDef{Name: c.text(field(n, "name")), Body: c.decls(field(n, "body")), Loc: L}}
	case "field_declaration_list":
		return c.decls(n)
	case "declaration":
		var out []nir.Stmt
		// the constructed/declared type (e.g. `File` in `File f(p)` / `File g = File(p)`).
		// C++ qualified types (std::ifstream) come through the declaration's `type`
		// field as a qualified_identifier; use its last dotted segment.
		typeName := c.text(lastChildKind(n, "type_identifier"))
		if typeName == "" {
			if t := field(n, "type"); t != nil {
				typeName = lastSeg(c.dotted(t))
			}
		}
		for _, d := range namedChildren(n) {
			switch d.Kind() {
			case "init_declarator":
				name := c.declName(field(d, "declarator"))
				if val := field(d, "value"); name != "" && val != nil {
					out = append(out, nir.Assign{Targets: []string{name}, Value: c.expr(val)})
				}
			case "function_declarator":
				// C++ "most vexing parse": `File f(p)` parses as a function declaration,
				// but when the args are bare value identifiers (not typed parameters) it is
				// really a stack-allocated constructor call. Lower it so type/arg sinks match.
				if args, ok := c.vexingCtorArgs(field(d, "parameters")); ok && typeName != "" {
					out = append(out, nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: typeName, Loc: L}, Args: args,
						Path: typeName, Method: typeName, Loc: L,
					}})
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
	// branch-structured (B1); Cond nil (C did not evaluate the predicate) -> byte-identical.
	case "if_statement":
		return []nir.Stmt{nir.If{Cond: c.expr(field(n, "condition")), Then: c.cBranch(field(n, "consequence")), Else: c.cBranch(field(n, "alternative"))}}
	case "while_statement", "for_statement", "do_statement":
		return []nir.Stmt{nir.Loop{Body: c.collectBlocks(n)}}
	case "switch_statement":
		return []nir.Stmt{c.cSwitch(n)}
	case "compound_statement":
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	}
	return nil
}

// vexingCtorArgs decides whether a function_declarator's parameter_list is really a
// constructor argument list (most-vexing-parse). It returns the arguments as value
// references only when EVERY parameter is a bare identifier/expression with no parameter
// name — a genuine prototype like `File f(int x)` or `File f(Foo x)` has a typed,
// named parameter and is left as a declaration (returns ok=false).
func (c *ccConv) vexingCtorArgs(params *tree_sitter.Node) ([]nir.Expr, bool) {
	if params == nil || params.Kind() != "parameter_list" {
		return nil, false
	}
	var args []nir.Expr
	for _, p := range namedChildren(params) {
		if p.Kind() != "parameter_declaration" {
			return nil, false // variadic, optional, etc. — not a clear ctor
		}
		kids := namedChildren(p)
		// a real parameter has a type plus a declarator (name); a vexing arg is a single
		// bare identifier/type_identifier standing in for a value reference.
		if len(kids) != 1 {
			return nil, false
		}
		switch kids[0].Kind() {
		case "identifier", "type_identifier":
			args = append(args, nir.Name{ID: c.text(kids[0]), Loc: c.loc(kids[0])})
		case "number_literal", "string_literal", "char_literal":
			args = append(args, nir.Const{Loc: c.loc(kids[0]), Value: c.text(kids[0])})
		default:
			return nil, false
		}
	}
	if len(args) == 0 {
		return nil, false
	}
	return args, true
}

func (c *ccConv) exprStmt(inner *tree_sitter.Node) []nir.Stmt {
	switch inner.Kind() {
	case "assignment_expression":
		left := field(inner, "left")
		right := c.expr(field(inner, "right"))
		if left != nil && left.Kind() == "identifier" {
			return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: right}}
		}
		if left != nil {
			return []nir.Stmt{nir.ExprStmt{Value: c.expr(left)}, nir.ExprStmt{Value: right}}
		}
		return []nir.Stmt{nir.ExprStmt{Value: right}}
	case "call_expression":
		name := lastSeg(c.dotted(field(inner, "function")))
		args := namedChildren(field(inner, "arguments"))
		// buffer writers: the destination buffer is tainted from the source args / the read.
		if len(args) > 0 {
			if cPropagators[name] {
				if dst := c.destName(args[0]); dst != "" { // dest is arg0 for str/mem copy
					var parts []nir.Expr
					for _, a := range args[1:] {
						parts = append(parts, c.expr(a))
					}
					return []nir.Stmt{
						nir.Assign{Targets: []string{dst}, Value: nir.Format{Parts: parts, Loc: c.loc(inner)}},
						nir.ExprStmt{Value: c.expr(inner)},
					}
				}
			}
			if idx, ok := cReaders[name]; ok && idx < len(args) {
				if dst := c.destName(args[idx]); dst != "" { // read into the BUFFER arg (recv/read = arg1)
					return []nir.Stmt{nir.Assign{Targets: []string{dst}, Value: c.expr(inner)}}
				}
			}
		}
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(inner)}}
}

// destName returns the buffer variable name of a writer's destination argument,
// unwrapping a leading `&`.
func (c *ccConv) destName(a *tree_sitter.Node) string {
	if a.Kind() == "pointer_expression" || a.Kind() == "unary_expression" {
		if arg := field(a, "argument"); arg != nil {
			a = arg
		}
	}
	if a.Kind() == "identifier" {
		return c.text(a)
	}
	return ""
}

// cBranch flattens one if-branch body: a `{}` compound_statement, an else_clause wrapper,
// or a brace-less single statement.
func (c *ccConv) cBranch(b *tree_sitter.Node) []nir.Stmt {
	if b == nil {
		return nil
	}
	switch b.Kind() {
	case "compound_statement":
		var out []nir.Stmt
		for _, st := range namedChildren(b) {
			out = append(out, c.stmt(st)...)
		}
		return out
	case "else_clause":
		var out []nir.Stmt
		for _, ch := range namedChildren(b) {
			out = append(out, c.cBranch(ch)...)
		}
		return out
	default:
		return c.stmt(b)
	}
}

// cSwitch lowers a switch into separate case branches with labels (consecutive
// fall-through-empty cases merge into the next body) so a constant subject prunes.
func (c *ccConv) cSwitch(n *tree_sitter.Node) nir.Stmt {
	var cases [][]nir.Stmt
	var labels [][]nir.Expr
	var deflt []nir.Stmt
	var pending []nir.Expr
	if b := field(n, "body"); b != nil {
		for _, cs := range namedChildren(b) {
			if cs.Kind() != "case_statement" {
				continue
			}
			lv := field(cs, "value")
			var stmts []nir.Stmt
			for _, ch := range namedChildren(cs) {
				if lv != nil && ch.StartByte() == lv.StartByte() {
					continue
				}
				stmts = append(stmts, c.stmt(ch)...)
			}
			if lv == nil { // default:
				deflt = append(deflt, stmts...)
				continue
			}
			pending = append(pending, c.expr(lv))
			if len(stmts) > 0 {
				cases = append(cases, stmts)
				labels = append(labels, pending)
				pending = nil
			}
		}
	}
	return nir.Switch{Subject: c.expr(field(n, "condition")), Cases: cases, Labels: labels, Default: deflt}
}

func (c *ccConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "compound_statement":
				out = append(out, c.block(ch)...)
			case "else_clause", "case_statement":
				walk(ch)
			case "expression_statement", "declaration", "return_statement", "if_statement":
				out = append(out, c.stmt(ch)...)
			}
		}
	}
	if n.Kind() == "compound_statement" {
		return c.block(n)
	}
	walk(n)
	return out
}

func (c *ccConv) block(block *tree_sitter.Node) []nir.Stmt {
	if block == nil {
		return nil
	}
	var out []nir.Stmt
	for _, st := range namedChildren(block) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *ccConv) params(decl *tree_sitter.Node) []string {
	pl := c.paramList(decl)
	if pl == nil {
		return nil
	}
	var out []string
	for _, ch := range namedChildren(pl) {
		if isCParamDecl(ch.Kind()) {
			if nm := c.declName(field(ch, "declarator")); nm != "" {
				out = append(out, nm)
			}
		}
	}
	return out
}

func (c *ccConv) paramTypes(decl *tree_sitter.Node) map[string]string {
	out := map[string]string{}
	pl := c.paramList(decl)
	if pl == nil {
		return out
	}
	for _, ch := range namedChildren(pl) {
		if isCParamDecl(ch.Kind()) {
			if nm := c.declName(field(ch, "declarator")); nm != "" {
				putParamType(out, nm, paramTypeFromField(c, ch))
			}
		}
	}
	return out
}

func (c *ccConv) paramList(decl *tree_sitter.Node) *tree_sitter.Node {
	if pl := field(decl, "parameters"); pl != nil {
		return pl
	}
	for _, ch := range namedChildren(decl) {
		if ch.Kind() == "parameter_list" {
			return ch
		}
		if pl := c.paramList(ch); pl != nil {
			return pl
		}
	}
	return nil
}

func (c *ccConv) paramsFromSignatureText(s string) ([]string, map[string]string) {
	out := map[string]string{}
	body := strings.Index(s, "{")
	if body >= 0 {
		s = s[:body]
	}
	start := strings.LastIndex(s, "(")
	end := strings.LastIndex(s, ")")
	if start < 0 || end <= start {
		return nil, out
	}
	var params []string
	for _, part := range strings.Split(s[start+1:end], ",") {
		part = strings.TrimSpace(part)
		if part == "" || part == "void" {
			continue
		}
		if eq := strings.Index(part, "="); eq >= 0 {
			part = strings.TrimSpace(part[:eq])
		}
		spaced := strings.NewReplacer("*", " * ", "&", " & ").Replace(part)
		fields := strings.Fields(spaced)
		if len(fields) == 0 {
			continue
		}
		name := fields[len(fields)-1]
		typeFields := fields[:len(fields)-1]
		for len(typeFields) > 0 && (typeFields[len(typeFields)-1] == "*" || typeFields[len(typeFields)-1] == "&") {
			typeFields = typeFields[:len(typeFields)-1]
		}
		typ := strings.Join(typeFields, " ")
		params = append(params, name)
		putParamType(out, name, typ)
	}
	return params, out
}

func isCParamDecl(kind string) bool {
	switch kind {
	case "parameter_declaration", "optional_parameter_declaration":
		return true
	}
	return false
}

func (c *ccConv) objcParamTypes(n *tree_sitter.Node, params []string) map[string]string {
	out := map[string]string{}
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "method_parameter" {
			name := ""
			if nm := field(ch, "name"); nm != nil {
				name = c.text(nm)
			}
			typ := paramTypeFromField(c, ch)
			if typ == "" {
				typ = objcMethodParamType(c.text(ch))
			}
			putParamType(out, name, typ)
		}
	}
	for _, name := range params {
		if _, ok := out[name]; ok {
			continue
		}
		putParamType(out, name, objcMethodParamTypeForName(c.text(n), name))
	}
	return out
}

func objcMethodParamType(s string) string {
	start := strings.Index(s, "(")
	end := strings.Index(s, ")")
	if start < 0 || end <= start {
		return ""
	}
	return s[start+1 : end]
}

func objcMethodParamTypeForName(s, name string) string {
	idx := strings.Index(s, name)
	if idx < 0 {
		return ""
	}
	prefix := s[:idx]
	start := strings.LastIndex(prefix, "(")
	end := strings.LastIndex(prefix, ")")
	if start < 0 || end <= start {
		return ""
	}
	return prefix[start+1 : end]
}

func (c *ccConv) callArgs(args *tree_sitter.Node) []nir.Expr {
	if args == nil {
		return nil
	}
	var out []nir.Expr
	for _, a := range namedChildren(args) {
		out = append(out, c.expr(a))
	}
	return out
}

func (c *ccConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "identifier", "field_identifier", "qualified_identifier", "namespace_identifier", "type_identifier":
		if v, ok := cBoolValue(c.text(n)); ok {
			return nir.Const{Loc: L, Value: v}
		}
		return nir.Name{ID: c.text(n), Loc: L}
	case "true", "false", "null", "nullptr":
		if v, ok := cBoolValue(c.text(n)); ok {
			return nir.Const{Loc: L, Value: v}
		}
		return nir.Const{Loc: L}
	case "number_literal", "char_literal":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "string_literal", "concatenated_string", "raw_string_literal":
		// carry the quote-stripped literal text so val-matched marks/sinks
		// (Cipher "DES", setSecure "false", algorithm strings) can value-match;
		// unquoteLit in lowering strips the surrounding delimiters.
		return nir.Const{Loc: L, Value: cStringText(c.text(n))}
	case "new_expression": // C++
		typ := c.text(field(n, "type"))
		return nir.Call{Callee: nir.Name{ID: typ, Loc: L}, Args: c.callArgs(field(n, "arguments")), Path: typ, Method: typ, Loc: L}
	case "field_expression":
		return nir.Attr{Base: c.expr(field(n, "argument")), Attr: c.text(field(n, "field")), Path: c.dotted(n), Loc: L}
	case "subscript_expression":
		return nir.Index{Base: c.expr(field(n, "argument")), Key: c.expr(field(n, "index")), Path: c.dotted(field(n, "argument")), Loc: L}
	case "call_expression":
		fn := field(n, "function")
		path := c.dotted(fn)
		return nir.Call{Callee: c.expr(fn), Args: c.callArgs(field(n, "arguments")), Path: path, Method: lastSeg(path), Loc: L}
	case "message_expression": // ObjC [receiver method:arg ...]
		recv := field(n, "receiver")
		methN := field(n, "method")
		method := c.text(methN)
		path := c.dotted(recv) + "." + method
		var args []nir.Expr
		// every named child except the receiver and the method selector is an arg
		for _, ch := range namedChildren(n) {
			if sameCNode(ch, recv) || sameCNode(ch, methN) || ch.Kind() == "selector" {
				continue
			}
			args = append(args, c.expr(ch))
		}
		return nir.Call{Callee: nir.Attr{Base: c.expr(recv), Attr: method, Path: path, Loc: L}, Args: args, Path: path, Method: method, Loc: L}
	case "binary_expression":
		op := c.text(field(n, "operator"))
		left, right := c.expr(field(n, "left")), c.expr(field(n, "right"))
		return nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
	case "parenthesized_expression", "cast_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[len(kids)-1])}
		}
	case "pointer_expression":
		if arg := field(n, "argument"); arg != nil {
			if c.unaryOp(n) == "*" {
				return nir.Call{Callee: nir.Name{ID: "__deref", Loc: L}, Args: []nir.Expr{c.expr(arg)}, Path: "__deref", Method: "__deref", Loc: L}
			}
			return nir.Thru{Inner: c.expr(arg)}
		}
	case "unary_expression":
		if arg := field(n, "argument"); arg != nil {
			op := c.unaryOp(n)
			if op == "*" {
				return nir.Call{Callee: nir.Name{ID: "__deref", Loc: L}, Args: []nir.Expr{c.expr(arg)}, Path: "__deref", Method: "__deref", Loc: L}
			}
			return nir.Unary{Op: op, Operand: c.expr(arg), Loc: L}
		}
	case "assignment_expression":
		return c.expr(field(n, "right"))
	case "conditional_expression":
		return nir.Ternary{Cond: c.expr(field(n, "condition")), Then: c.expr(field(n, "consequence")), Else: c.expr(field(n, "alternative")), Loc: L}
	}
	var parts []nir.Expr
	for _, ch := range namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
}

func (c *ccConv) ccIndexAccessObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	bodyText := compactCExprText(c.text(body))
	seen := map[string]bool{}
	var out []nir.Stmt
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if n.Kind() == "subscript_expression" {
			idx := field(n, "index")
			idxText := c.text(idx)
			compactIdx := compactCExprText(idxText)
			if ccStructuredIndex(idxText) && compactIdx != "" {
				loc := c.loc(n)
				if !seen[loc] {
					seen[loc] = true
					guard := "guard=missing_upper_bound"
					if ccHasUpperBoundGuard(bodyText, compactIdx) {
						guard = "guard=upper_bound"
					}
					path := "analysis.index.access"
					out = append(out, nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: path, Loc: loc},
						Args: []nir.Expr{
							nir.Const{Loc: loc, Value: "index_kind=field_derived"},
							nir.Const{Loc: loc, Value: guard},
							nir.Const{Loc: loc, Value: "index=" + compactIdx},
						},
						Path:   path,
						Method: "access",
						Loc:    loc,
					}})
				}
			}
		}
		for _, ch := range namedChildren(n) {
			walk(ch)
		}
	}
	walk(body)
	return out
}

func ccStructuredIndex(s string) bool {
	return strings.Contains(s, "->") || strings.Contains(s, ".")
}

func ccHasUpperBoundGuard(bodyText, idx string) bool {
	return strings.Contains(bodyText, idx+"<") ||
		strings.Contains(bodyText, idx+"<=") ||
		strings.Contains(bodyText, ">"+idx) ||
		strings.Contains(bodyText, ">="+idx)
}

func compactCExprText(s string) string {
	return strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "").Replace(s)
}

func (c *ccConv) unaryOp(n *tree_sitter.Node) string {
	if op := field(n, "operator"); op != nil {
		return c.text(op)
	}
	raw := c.text(n)
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case ' ', '\t', '\r', '\n':
			continue
		case '*', '&', '!', '+', '-':
			return string(raw[i])
		}
		break
	}
	return ""
}

func cBoolValue(s string) (string, bool) {
	switch s {
	case "YES", "TRUE", "true":
		return "true", true
	case "NO", "FALSE", "false":
		return "false", true
	}
	return "", false
}

// cStringText returns a quoted string literal whose surrounding delimiters wrap only
// the de-prefixed content, so downstream unquoteLit yields the inner text. It strips
// C/C++/ObjC literal prefixes (L, u, U, u8, @) and joins adjacent quoted runs
// (concatenated_string / "a" "b"), keeping a single pair of double quotes so the
// value still reads as a string literal for val-matching.
func cStringText(raw string) string {
	var b []byte
	i := 0
	for i < len(raw) {
		ch := raw[i]
		if ch == '"' || ch == '\'' {
			q := ch
			i++
			for i < len(raw) && raw[i] != q {
				if raw[i] == '\\' && i+1 < len(raw) {
					b = append(b, raw[i+1])
					i += 2
					continue
				}
				b = append(b, raw[i])
				i++
			}
			if i < len(raw) {
				i++ // closing quote
			}
			continue
		}
		// skip prefix chars / whitespace between adjacent literals (L, u, U, 8, @, space)
		i++
	}
	return "\"" + string(b) + "\""
}

func (c *ccConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "identifier", "field_identifier", "type_identifier", "namespace_identifier":
		return c.text(n)
	case "qualified_identifier": // C++ std::system -> std.system (dotted boundary)
		scope := field(n, "scope")
		name := field(n, "name")
		if scope == nil {
			return c.dotted(name)
		}
		return c.dotted(scope) + "." + c.dotted(name)
	case "field_expression":
		return c.dotted(field(n, "argument")) + "." + c.text(field(n, "field"))
	case "message_expression": // ObjC
		return c.dotted(field(n, "receiver")) + "." + c.text(field(n, "method"))
	case "call_expression":
		return c.dotted(field(n, "function"))
	case "subscript_expression":
		return c.dotted(field(n, "argument")) + "[]"
	case "parenthesized_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return c.dotted(kids[0])
		}
	}
	return "?"
}
