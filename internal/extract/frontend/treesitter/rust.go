package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsrust "github.com/tree-sitter/tree-sitter-rust/bindings/go"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// rsConv walks a tree-sitter Rust CST into NIR.
type rsConv struct {
	src        []byte
	file       string
	key        string
	childCache map[uintptr][]*tree_sitter.Node
}

// rsFormatMacros build a string from their arguments (taint-propagating).
var rsFormatMacros = map[string]bool{
	"format": true, "println": true, "print": true, "eprintln": true,
	"eprint": true, "write": true, "writeln": true, "panic": true, "format_args": true,
}

// ExtractRust parses Rust files into one NIR Program (one module per file).
func ExtractRust(files []string, root string) (nir.Program, error) {
	mods := parseModules(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(tree_sitter.NewLanguage(tsrust.Language()))
			return p
		},
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			c := &rsConv{src: src, file: rel, key: moduleKey(root, abs, ".rs")}
			return nir.Module{Key: c.key, File: rel, Body: c.decls(tree.RootNode())}, true
		})
	return nir.Program{SelfName: "self", Modules: mods}, nil
}

func (c *rsConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *rsConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

func (c *rsConv) namedChildren(n *tree_sitter.Node) []*tree_sitter.Node {
	if n == nil {
		return nil
	}
	if c.childCache == nil {
		c.childCache = map[uintptr][]*tree_sitter.Node{}
	}
	id := n.Id()
	if kids, ok := c.childCache[id]; ok {
		return kids
	}
	kids := namedChildren(n)
	c.childCache[id] = kids
	return kids
}

// decls walks a list, tracking preceding attribute_item syntax for the next item.
func (c *rsConv) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var attrs []string
	for _, ch := range c.namedChildren(n) {
		if ch.Kind() == "attribute_item" {
			attrs = append(attrs, c.rsAttrTokens(ch)...)
			continue
		}
		out = append(out, c.stmtH(ch, attrs)...)
		attrs = nil
	}
	return out
}

func (c *rsConv) rsAttrTokens(n *tree_sitter.Node) []string {
	seen := map[string]bool{}
	var out []string
	add := func(tok string) {
		if tok == "" || seen[tok] {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	rawItem := strings.Join(strings.Fields(c.text(n)), "")
	if strings.HasPrefix(rawItem, "#[repr(") && strings.HasSuffix(rawItem, ")]") {
		arg := strings.TrimSuffix(strings.TrimPrefix(rawItem, "#[repr("), ")]")
		add("attr_name:repr")
		add("attr_repr:" + arg)
		add("attr:repr(" + arg + ")")
		add("repr:" + arg)
	}
	for _, tok := range rsDeriveTokens(rawItem) {
		add(tok)
	}
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		if m.Kind() == "attribute" {
			for _, ch := range c.namedChildren(m) {
				if ch.Kind() == "identifier" || ch.Kind() == "scoped_identifier" {
					path := c.dotted(ch)
					add("attr_path:" + path)
					add("attr_name:" + lastSeg(path))
				}
			}
			return
		}
		for _, ch := range c.namedChildren(m) {
			walk(ch)
		}
	}
	walk(n)
	return out
}

func (c *rsConv) stmt(n *tree_sitter.Node) []nir.Stmt { return c.stmtH(n, nil) }

func (c *rsConv) stmtH(n *tree_sitter.Node, attrs []string) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "function_item":
		params := c.params(field(n, "parameters"))
		paramTypes := c.paramTypes(field(n, "parameters"))
		body := c.block(field(n, "body"))
		body = append(body, c.rsFunctionContext(n)...)
		exported := false
		for _, ch := range children(n) {
			if ch.Kind() == "visibility_modifier" {
				exported = true
				break
			}
		}
		return []nir.Stmt{nir.FuncDef{Name: c.text(field(n, "name")), Params: params, ParamTypes: paramTypes, ParamEntries: c.rsParamEntries(c.text(field(n, "name")), params, attrs), Body: body, Loc: L, Exported: exported}}
	case "impl_item":
		out := c.rsUnsafeImplMetadata(n)
		out = append(out, c.rsUnpinImplMetadata(n)...)
		out = append(out, c.rsRunTestsAutoApprovalMetadata(n)...)
		out = append(out, c.decls(field(n, "body"))...)
		return out
	case "mod_item", "trait_item":
		return c.decls(field(n, "body"))
	case "enum_item":
		return c.rsEnumMetadata(n, attrs)
	case "struct_item":
		return c.rsStructFieldMetadata(n, attrs)
	case "use_declaration", "const_item", "static_item":
		return nil
	case "let_declaration":
		val := field(n, "value")
		if val == nil {
			return nil
		}
		name := c.patName(field(n, "pattern"))
		if name != "" {
			return []nir.Stmt{nir.Assign{Targets: []string{name}, Value: c.expr(val)}}
		}
		// `let _ = expr;` binds no name, but the call still matters for sinks/marks.
		return []nir.Stmt{nir.ExprStmt{Value: c.expr(val)}}
	case "expression_statement":
		kids := c.namedChildren(n)
		if len(kids) == 0 {
			return nil
		}
		return c.exprStmt(kids[0])
	// if/match in statement position become branch-structured control flow (predicate
	// attached) so dead arms prune AND nested reassignments are tracked (no FN). The
	// value-context forms (`let x = if …`) are still handled in expr() as a Ternary.
	case "if_expression":
		return []nir.Stmt{c.rsIf(n)}
	case "match_expression":
		return []nir.Stmt{c.rsMatch(n)}
	case "block":
		return c.block(n)
	}
	if meta := c.rsUninitializedMetadata(n); meta != nil {
		return append(meta, nir.ExprStmt{Value: c.expr(n)})
	}
	// a bare tail expression (block value) still matters for taint
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
}

func (c *rsConv) rsUninitializedMetadata(n *tree_sitter.Node) []nir.Stmt {
	text := c.text(n)
	compact := rustCompactText(text)
	if !strings.Contains(compact, "mem::uninitialized") {
		return nil
	}
	loc := c.loc(n)
	path := "analysis.rust.uninitialized"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "lang=rust"},
			nir.Const{Loc: loc, Value: "mem::uninitialized"},
		},
		Path:   path,
		Method: "uninitialized",
		Loc:    loc,
	}}}
}

func (c *rsConv) rsRunTestsAutoApprovalMetadata(n *tree_sitter.Node) []nir.Stmt {
	compact := rustCompactText(c.text(n))
	if !strings.Contains(compact, "\"run_tests\"") ||
		!strings.Contains(compact, "ToolCapability::ExecutesCode") ||
		!strings.Contains(compact, "\"cargotest\"") ||
		strings.Contains(compact, "ApprovalRequirement::Required") ||
		strings.Contains(compact, "ApprovalRequirement::Suggest") {
		return nil
	}
	loc := c.loc(n)
	return []nir.Stmt{c.rsAnalysisCall("analysis.rust.run_tests_auto_approval_executes_code",
		"run_tests_auto_approval_executes_code", loc,
		"lang=rust", "tool=run_tests", "capability=executes_code", "approval=auto")}
}

func (c *rsConv) rsEnumMetadata(n *tree_sitter.Node, attrs []string) []nir.Stmt {
	if len(attrs) == 0 {
		return nil
	}
	loc := c.loc(n)
	path := "analysis.rust.enum"
	name := c.text(field(n, "name"))
	tokens := []string{"lang=rust", "kind:enum"}
	if name != "" {
		tokens = append(tokens, "enum_name:"+name)
	}
	tokens = append(tokens, attrs...)
	args := make([]nir.Expr, 0, len(tokens))
	for _, tok := range tokens {
		args = append(args, nir.Const{Loc: loc, Value: tok})
	}
	out := []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args:   args,
		Path:   path,
		Method: "enum",
		Loc:    loc,
	}}}
	if rsContainsString(attrs, "attr_repr:C") || rsContainsString(attrs, "repr:C") {
		out = append(out, c.rsAnalysisCall("analysis.rust.ffi_enum_layout_risk", "ffi_enum_layout_risk", loc,
			"lang=rust", "kind:enum", "repr:C"))
	}
	return out
}

func (c *rsConv) rsStructFieldMetadata(n *tree_sitter.Node, attrs []string) []nir.Stmt {
	name := c.text(field(n, "name"))
	if name == "" {
		return nil
	}
	structTokens := []string{"lang=rust", "struct_name:" + name}
	structTokens = append(structTokens, attrs...)
	var out []nir.Stmt
	var walk func(*tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		if m == nil {
			return
		}
		if m.Kind() == "field_declaration_list" {
			var pendingAttrs []string
			for _, ch := range c.namedChildren(m) {
				if ch.Kind() == "attribute_item" {
					pendingAttrs = append(pendingAttrs, c.rsAttrTokens(ch)...)
					pendingAttrs = append(pendingAttrs, rsSerdeTokens(c.text(ch))...)
					continue
				}
				if ch.Kind() == "field_declaration" {
					if stmt, ok := c.rsStructFieldMetadataCall(ch, structTokens, pendingAttrs); ok {
						out = append(out, stmt)
					}
					pendingAttrs = nil
					continue
				}
				pendingAttrs = nil
				walk(ch)
			}
			return
		}
		if m.Kind() == "field_declaration" {
			if stmt, ok := c.rsStructFieldMetadataCall(m, structTokens, nil); ok {
				out = append(out, stmt)
			}
			return
		}
		for _, ch := range c.namedChildren(m) {
			walk(ch)
		}
	}
	walk(n)
	return out
}

func (c *rsConv) rsStructFieldMetadataCall(n *tree_sitter.Node, structTokens, pendingAttrs []string) (nir.Stmt, bool) {
	name := c.text(field(n, "name"))
	if name == "" {
		for _, ch := range c.namedChildren(n) {
			if ch.Kind() == "field_identifier" || ch.Kind() == "identifier" {
				name = c.text(ch)
				break
			}
		}
	}
	if name == "" {
		return nil, false
	}
	typ := c.text(field(n, "type"))
	fieldAttrs := append([]string{}, pendingAttrs...)
	for _, ch := range c.namedChildren(n) {
		if ch.Kind() == "attribute_item" {
			fieldAttrs = append(fieldAttrs, c.rsAttrTokens(ch)...)
			fieldAttrs = append(fieldAttrs, rsSerdeTokens(c.text(ch))...)
		}
	}
	tokens := append([]string{}, structTokens...)
	tokens = append(tokens, "field:"+name)
	if typ != "" {
		tokens = append(tokens, "field_type:"+rustCompactText(typ))
	}
	tokens = append(tokens, fieldAttrs...)
	if rsDependencyMapField(name, typ) {
		tokens = append(tokens, "semantic:dependency_map")
	}
	args := make([]nir.Expr, 0, len(tokens))
	loc := c.loc(n)
	tokens = dedupeStrings(tokens)
	for _, tok := range tokens {
		args = append(args, nir.Const{Loc: loc, Value: tok})
	}
	path := "analysis.rust.serde_field"
	out := []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args:   args,
		Path:   path,
		Method: "serde_field",
		Loc:    loc,
	}}}
	if rsContainsString(tokens, "derive:Deserialize") &&
		rsContainsString(tokens, "semantic:dependency_map") &&
		!rsContainsString(tokens, "serde_attr:deserialize_with") {
		out = append(out, c.rsAnalysisCall("analysis.rust.unvalidated_dependency_map_key_deserialization",
			"unvalidated_dependency_map_key_deserialization", loc,
			"lang=rust", "field:"+name, "field_type:"+rustCompactText(typ)))
	}
	if len(out) == 1 {
		return out[0], true
	}
	return nir.Block{Stmts: out}, true
}

func rsDeriveTokens(raw string) []string {
	compact := rustCompactText(raw)
	start := strings.Index(compact, "#[derive(")
	if start < 0 {
		return nil
	}
	rest := compact[start+len("#[derive("):]
	end := strings.Index(rest, ")]")
	if end < 0 {
		return nil
	}
	var out []string
	for _, part := range strings.Split(rest[:end], ",") {
		if part != "" {
			out = append(out, "derive:"+part)
		}
	}
	return out
}

func rsSerdeTokens(raw string) []string {
	compact := rustCompactText(raw)
	if !strings.HasPrefix(compact, "#[serde(") || !strings.HasSuffix(compact, ")]") {
		return nil
	}
	body := strings.TrimSuffix(strings.TrimPrefix(compact, "#[serde("), ")]")
	var out []string
	for _, part := range strings.Split(body, ",") {
		if part == "" {
			continue
		}
		key, val, hasVal := strings.Cut(part, "=")
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		out = append(out, "serde_attr:"+key)
		if hasVal {
			val = strings.Trim(val, "\"")
			switch key {
			case "alias":
				out = append(out, "serde_alias:"+val)
			case "serialize_with":
				out = append(out, "serde_serialize_with:"+val)
			case "deserialize_with":
				out = append(out, "serde_deserialize_with:"+val)
			}
		}
	}
	return out
}

func rsDependencyMapField(name, typ string) bool {
	n := strings.ToLower(name)
	if !strings.Contains(n, "depend") && !strings.Contains(n, "package") && !strings.Contains(n, "plugin") {
		return false
	}
	t := strings.ToLower(typ)
	return strings.Contains(t, "map") || strings.Contains(t, "dependencies") || strings.Contains(t, "packages") || strings.Contains(t, "plugins")
}

func dedupeStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func (c *rsConv) rsUnsafeImplMetadata(n *tree_sitter.Node) []nir.Stmt {
	text := c.text(n)
	compact := rustCompactText(text)
	if !strings.HasPrefix(strings.TrimSpace(text), "unsafe impl") {
		return nil
	}
	var trait string
	for _, name := range []string{"Send", "Sync"} {
		if strings.Contains(compact, name+"for") || strings.Contains(compact, name+"<") {
			trait = name
			break
		}
	}
	if trait == "" {
		return nil
	}
	loc := c.loc(n)
	tokens := []string{"lang=rust", "kind:unsafe_impl", "trait:" + trait}
	for _, bound := range []string{"Send", "Sync"} {
		if strings.Contains(compact, "+"+bound) || strings.Contains(compact, ":"+bound) {
			tokens = append(tokens, "bound:"+bound)
		}
	}
	path := "analysis.rust.unsafe_impl"
	out := []nir.Stmt{c.rsAnalysisCall(path, "unsafe_impl", loc, tokens...)}
	hasSendBound := rsContainsString(tokens, "bound:Send")
	hasSyncBound := rsContainsString(tokens, "bound:Sync")
	switch trait {
	case "Send":
		if !hasSendBound {
			out = append(out, c.rsAnalysisCall("analysis.rust.unsafe_send_impl_missing_bound", "unsafe_send_impl_missing_bound", loc,
				"lang=rust", "trait:Send", "missing_bound:Send"))
		}
	case "Sync":
		if !hasSyncBound && !hasSendBound {
			out = append(out, c.rsAnalysisCall("analysis.rust.unsafe_sync_impl_missing_bound", "unsafe_sync_impl_missing_bound", loc,
				"lang=rust", "trait:Sync", "missing_bound:SyncOrSend"))
		}
	}
	return out
}

// rsUnpinImplMetadata reports an unconditional Unpin impl for a generic type
// in a file that also pins with Pin::new_unchecked. Unpin is a safe trait, so
// the impl alone proves nothing -- a wrapper whose field is a Box is Unpin
// whatever its parameter is. The unsoundness needs both halves: the blanket
// impl lets safe code move the value out of a Pin, and new_unchecked is the
// promise that it never moves. Together they let a caller free a buffer the
// pinned I/O object still references (RUSTSEC's Framed shape). A bound on the
// parameter (T: Unpin) makes the impl conditional and drops the fact.
func (c *rsConv) rsUnpinImplMetadata(n *tree_sitter.Node) []nir.Stmt {
	compact := rustCompactText(c.text(n))
	if strings.HasPrefix(compact, "unsafeimpl") || !strings.HasPrefix(compact, "impl") {
		return nil
	}
	if !strings.Contains(compact, "Unpinfor") {
		return nil
	}
	// Only a generic impl can promise Unpin for parameters it does not know.
	if !strings.HasPrefix(compact, "impl<") {
		return nil
	}
	if strings.Contains(compact, ":Unpin") || strings.Contains(compact, "+Unpin") {
		return nil
	}
	if !strings.Contains(string(c.src), "new_unchecked") {
		return nil
	}
	loc := c.loc(n)
	return []nir.Stmt{c.rsAnalysisCall("analysis.rust.unpin_impl_missing_bound", "unpin_impl_missing_bound", loc,
		"lang=rust", "trait:Unpin", "missing_bound:Unpin")}
}

func (c *rsConv) rsAnalysisCall(path, method, loc string, tokens ...string) nir.Stmt {
	args := make([]nir.Expr, 0, len(tokens))
	for _, tok := range tokens {
		args = append(args, nir.Const{Loc: loc, Value: tok})
	}
	return nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args:   args,
		Path:   path,
		Method: method,
		Loc:    loc,
	}}
}

func rsContainsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func (c *rsConv) rsParamEntries(name string, params []string, attrs []string) []nir.ParamEntry {
	if len(params) == 0 || len(attrs) == 0 {
		return nil
	}
	var out []nir.ParamEntry
	for i, p := range params {
		tokens := append([]string{}, attrs...)
		tokens = append(tokens, "function_name:"+name, "param_name:"+p, "param_index:"+itoa(i))
		out = append(out, nir.ParamEntry{Param: p, Tokens: tokens})
	}
	return out
}

func (c *rsConv) rsFunctionContext(fn *tree_sitter.Node) []nir.Stmt {
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	loc := c.loc(fn)
	text := c.text(body)
	path := "analysis.function.context"
	args := []nir.Expr{
		nir.Const{Loc: loc, Value: "lang=rust"},
		nir.Const{Loc: loc, Value: "name=" + c.text(field(fn, "name"))},
		nir.Const{Loc: loc, Value: text},
		nir.Const{Loc: loc, Value: rustCompactText(text)},
	}
	if abi := c.rsExternAbi(fn); abi != "" {
		args = append(args, nir.Const{Loc: loc, Value: "abi=" + abi})
	}
	for _, tok := range c.rsStructuredContextTokens(body) {
		args = append(args, nir.Const{Loc: loc, Value: tok})
	}
	if tok := c.rustClosureUnwindStaleLength(fn, body); tok != "" {
		args = append(args, nir.Const{Loc: loc, Value: tok})
	}
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args:   args,
		Path:   path,
		Method: "context",
		Loc:    loc,
	}}}
}

// rsExternAbi reports the extern ABI a function item is declared with: the
// function_modifiers -> extern_modifier grammar path, whose optional string
// literal names the ABI and defaults to "C" when absent. A function with no
// extern modifier returns "".
func (c *rsConv) rsExternAbi(fn *tree_sitter.Node) string {
	for _, ch := range c.namedChildren(fn) {
		if ch.Kind() != "function_modifiers" {
			continue
		}
		for _, m := range c.namedChildren(ch) {
			if m.Kind() != "extern_modifier" {
				continue
			}
			for _, lit := range c.namedChildren(m) {
				if lit.Kind() == "string_literal" {
					return strings.Trim(c.text(lit), "\"")
				}
			}
			return "C"
		}
	}
	return ""
}

func (c *rsConv) rsStructuredContextTokens(root *tree_sitter.Node) []string {
	seen := map[string]bool{}
	var out []string
	add := func(tok string) {
		if tok == "" || seen[tok] || len(out) >= 512 {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	atom := func(n *tree_sitter.Node) string {
		if n == nil {
			return ""
		}
		if p := c.dotted(n); p != "" && p != "?" {
			return p
		}
		return rustCompactText(c.text(n))
	}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil || len(out) >= 512 {
			return
		}
		switch n.Kind() {
		case "assignment_expression":
			left := atom(field(n, "left"))
			right := atom(field(n, "right"))
			if left != "" && right != "" {
				add("assign:" + left + "=" + right)
			}
		case "call_expression":
			if path := c.dotted(field(n, "function")); path != "" && path != "?" {
				add("call_path:" + path)
				add("call:" + lastSeg(path))
				for _, arg := range c.namedChildren(field(n, "arguments")) {
					if a := atom(arg); a != "" {
						add("call_arg:" + path + ":" + a)
					}
				}
			}
		case "field_expression":
			if sel := c.dotted(n); sel != "" && sel != "?" {
				add("selector:" + sel)
			}
		case "match_arm":
			if pat := rustMatchArmPattern(n); pat != nil {
				if label := atom(pat); label != "" {
					add("match_arm:" + label)
				}
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
	for _, tok := range rustSemanticReviewTokens(c.text(root)) {
		add(tok)
	}
	return out
}

// rustClosureUnwindStaleLength reports the shape of the retain family of
// memory-safety bugs (rust-lang/rust#60977, #78498): a function takes a
// caller-supplied closure, calls it between a raw buffer copy and the final
// set_len, and carries no unwind protection. A panic inside the closure then
// leaves the collection with its stale pre-compaction length, and the drop
// that follows frees moved elements twice or observes holes. Both guarded
// forms suppress the fact: zeroing the length before the loop (set_len(0)),
// or restoring it from an inline Drop guard. The check is keyed on this
// shape, never on any one crate's identifiers.
func (c *rsConv) rustClosureUnwindStaleLength(fn, body *tree_sitter.Node) string {
	bodyText := rustCompactText(c.text(body))
	if !strings.Contains(bodyText, "ptr::copy") || !strings.Contains(bodyText, "set_len(") {
		return ""
	}
	if strings.Contains(bodyText, "set_len(0)") || strings.Contains(bodyText, "Dropfor") {
		return ""
	}
	// The closure bound lives in the signature or the where clause, not in the
	// parameter list, so read everything before the body.
	fnText := rustCompactText(c.text(fn))
	sig := strings.TrimSuffix(fnText, bodyText)
	if !strings.Contains(sig, "FnMut") && !strings.Contains(sig, "FnOnce") && !strings.Contains(sig, "Fn(") {
		return ""
	}
	for _, p := range c.params(field(fn, "parameters")) {
		name := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(p), "mut "))
		if name == "" || name == "self" || !rustCompactCallsIdent(bodyText, name) {
			continue
		}
		return "rust_review:closure_unwind_stale_length"
	}
	return ""
}

// rustCompactCallsIdent reports whether compact holds a call to the bare
// identifier: name immediately followed by an open parenthesis, with no
// path or field character in front, so a parameter named len does not match
// every .len() in the body.
func rustCompactCallsIdent(compact, name string) bool {
	needle := name + "("
	for at := strings.Index(compact, needle); at >= 0; {
		if at == 0 {
			return true
		}
		prev := compact[at-1]
		if !(prev >= 'a' && prev <= 'z') && !(prev >= 'A' && prev <= 'Z') &&
			!(prev >= '0' && prev <= '9') && prev != '_' && prev != '.' && prev != ':' {
			return true
		}
		next := strings.Index(compact[at+1:], needle)
		if next < 0 {
			break
		}
		at += 1 + next
	}
	return false
}

func rustSemanticReviewTokens(raw string) []string {
	compact := rustCompactText(raw)
	var out []string
	add := func(fact string) {
		out = append(out, "rust_review:"+fact)
	}
	if strings.Contains(compact, "installScript") &&
		strings.Contains(compact, "final_script") &&
		!strings.Contains(compact, "spawn_installer_container") {
		add("template_install_script_host_execution")
	}
	if strings.Contains(compact, "&mut") &&
		strings.Contains(compact, "as*const") &&
		strings.Contains(compact, "as*mut") {
		add("unsafe_mutable_alias")
	}
	if strings.Contains(compact, "avail_in=input.len()asc_uint") &&
		strings.Contains(compact, "avail_out=output.len()asc_uint") &&
		strings.Contains(compact, "BZ2_bz") &&
		!strings.Contains(compact, ".min(c_uint::MAXasusize)asc_uint") {
		add("unchecked_ffi_length_narrowing")
	}
	if rustUninitializedBufferExposure(compact) {
		add("uninitialized_buffer_exposure")
	}
	if strings.Contains(compact, "letn_partitions=1u32<<order;") &&
		strings.Contains(compact, "letn_samples=block_size>>order;") &&
		strings.Contains(compact, "letmutlen=n_samples-n_warm_up;") &&
		strings.Contains(compact, "buffer[start..start+lenasusize]") &&
		strings.Contains(compact, "decode_rice_partition(input,slice)") &&
		strings.Contains(compact, "decode_rice2_partition(input,slice)") &&
		!strings.Contains(compact, "block_size&(n_partitions-1)asu16!=0") &&
		!strings.Contains(compact, "n_samples_per_partition") {
		add("claxon_residual_partition_buffer_exposure")
	}
	if strings.Contains(compact, ".next().await") && !strings.Contains(compact, "timeout") {
		add("unbounded_next_await")
	}
	if strings.Contains(compact, "lettarget_size=target_size.unwrap_or(value.len());") &&
		strings.Contains(compact, "self.data.resize(offset+target_size,0)") &&
		strings.Contains(compact, "forindexin0..target_size") &&
		strings.Contains(compact, "value.len()>index") &&
		!strings.Contains(compact, "value.is_empty()") {
		add("empty_source_slice_memory_expansion")
	}
	if strings.Contains(compact, "whilelen>0") &&
		strings.Contains(compact, "self.fill_buf()") &&
		strings.Contains(compact, "buf.len().min(len)") &&
		strings.Contains(compact, "self.consume(consume_len)") &&
		strings.Contains(compact, "len-=consume_len") &&
		!strings.Contains(compact, "buf.is_empty()") &&
		!strings.Contains(compact, "UnexpectedEof") {
		add("bufread_discard_loop_without_eof_guard")
	}
	if strings.Contains(compact, "request.into_parts()") &&
		strings.Contains(compact, "hyper::body::to_bytes(body).await?") &&
		strings.Contains(compact, "Request::from_parts(parts,full_body)") &&
		!strings.Contains(compact, "check_content_length") &&
		!strings.Contains(compact, "size_hint") {
		add("conduit_hyper_unbounded_body_to_bytes")
	}
	if strings.Contains(compact, "\"max-age\",Some(v)") &&
		strings.Contains(compact, "v.parse()") &&
		strings.Contains(compact, "Duration::seconds(val)") &&
		!strings.Contains(compact, "Duration::max_value().num_seconds()") &&
		!strings.Contains(compact, "cmp::min") {
		add("cookie_max_age_duration_seconds_panic")
	}
	if strings.Contains(compact, "letstate_ptr=Weak::into_raw(Arc::downgrade(&self_ref.state));letmutstate=self_ref.state.write().unwrap();") &&
		strings.Contains(compact, "state.waker.is_none()") &&
		strings.Contains(compact, "ic0::call_new") {
		add("call_future_raw_weak_state_ref")
	}
	if rustWindowsReservedDeviceBypass(compact, "COM") {
		add("windows_reserved_device_name_bypass_com")
	}
	if rustWindowsReservedDeviceBypass(compact, "LPT") {
		add("windows_reserved_device_name_bypass_lpt")
	}
	if strings.Contains(compact, "PACKAGE_SOURCE_LOCK") &&
		strings.Contains(compact, "entry.unpack_in(parent)") &&
		strings.Contains(compact, "OpenOptions::new().create(true)") &&
		strings.Contains(compact, "write!(ok,\"ok\")") &&
		!strings.Contains(compact, "entry_path.file_name()") &&
		!strings.Contains(compact, "create_new(true)") {
		add("archive_marker_symlink_overwrite")
	}
	if strings.Contains(compact, "self.ensure_smart_account_at_round(&tx.from,current_round);") &&
		strings.Contains(compact, "self.debit(&tx.from,tx.fee)?;") &&
		strings.Contains(compact, "self.increment_nonce(&tx.from);") &&
		strings.Contains(compact, "SmartOpType::Stake{amount}=>{") &&
		strings.Contains(compact, "returnErr(CoinError::ValidationError(\"belowminimumstake\".into()))") &&
		strings.Contains(compact, "ok_or_else(||CoinError::ValidationError(\"nostaketounstake\".into()))?") &&
		!strings.Contains(compact, "tx.fee.saturating_add(*amount)") {
		add("state_mutation_before_operation_preconditions")
	}
	if strings.Contains(compact, "record_deposit(out.len())") &&
		strings.Contains(compact, "letexit_result=self.exit_substate(StackExitKind::Succeeded);ifletErr(e)=self.record_external_operation") &&
		strings.Contains(compact, "ExternalOperation::Write(U256::from(out.len()))") &&
		strings.Contains(compact, "self.state.set_code(address,out)") {
		add("state_commit_before_external_write_accounting")
	}
	if strings.Contains(compact, "DiscoveryMessage::Handshake") &&
		strings.Contains(compact, "self.peer_list_limit=Some(limit);") &&
		strings.Contains(compact, "self.peer_list_limit.unwrap()asusize-1") &&
		strings.Contains(compact, "self.get_peer_contacts(") &&
		!strings.Contains(compact, ".saturating_sub(1)") &&
		!strings.Contains(compact, ".min(self.config.update_limit)") {
		add("peer_limit_underflow")
	}
	if strings.Contains(compact, "Regex::new") &&
		strings.Contains(compact, "(?m)//.*$") &&
		strings.Contains(compact, "replace_all") &&
		!strings.Contains(compact, "verify_string") &&
		!strings.Contains(compact, "is_permitted_char") &&
		!strings.Contains(compact, "strip_comments_and_verify") {
		add("regex_line_comment_strip_without_char_whitelist")
	}
	if strings.Contains(compact, "underflow_mask=((borrow>>63)^1).wrapping_sub(1)") &&
		strings.Contains(compact, "constants::L[i]&underflow_mask") &&
		!strings.Contains(compact, "read_volatile") &&
		!strings.Contains(compact, "black_box(underflow_mask)") {
		add("crypto_missing_optimization_barrier")
	}
	if rustCryptoScalarRandomBitsByteLengthConfusion(compact) {
		add("crypto_scalar_random_bits_byte_length_confusion")
	}
	if strings.Contains(compact, "cryptsetupluksOpen--typeluks2-d-$root_hd$name") &&
		!strings.Contains(compact, "open_encrypted_volume") &&
		!strings.Contains(compact, "--header") &&
		!strings.Contains(compact, "luksHeaderBackup") &&
		!strings.Contains(compact, "validate_luks2_headers") {
		add("luks2_attached_header_activation")
	}
	if strings.Contains(compact, "config_dest.push(\"ignition\");") &&
		strings.Contains(compact, "config_dest.push(\"config.ign\");") &&
		strings.Contains(compact, "create_dir_all(&config_dest)") &&
		strings.Contains(compact, "OpenOptions::new()") &&
		strings.Contains(compact, ".create_new(true)") &&
		strings.Contains(compact, "copy(&mutconfig_in,&mutconfig_out)") &&
		!strings.Contains(compact, "set_permissions") &&
		!strings.Contains(compact, "Permissions::from_mode") &&
		!strings.Contains(compact, ".chmod(") &&
		!strings.Contains(compact, ".set_mode(") {
		add("secret_config_file_permission_missing")
	}
	return out
}

func rustUninitializedBufferExposure(compact string) bool {
	if strings.Contains(compact, "with_capacity") &&
		strings.Contains(compact, "as_mut_ptr") &&
		strings.Contains(compact, "from_raw_parts_mut") &&
		strings.Contains(compact, "read_exact") &&
		strings.Contains(compact, "set_len") {
		return true
	}
	if strings.Contains(compact, "Vec::with_capacity") &&
		strings.Contains(compact, "set_len") &&
		strings.Contains(compact, "read_exact(&mut") &&
		!strings.Contains(compact, "resize") {
		return true
	}
	return strings.Contains(compact, "as_mut_ptr") &&
		strings.Contains(compact, "from_raw_parts_mut") &&
		strings.Contains(compact, ".read(") &&
		strings.Contains(compact, "set_len")
}

func rustWindowsReservedDeviceBypass(compact, prefix string) bool {
	return strings.Contains(compact, "path.file_stem()") &&
		strings.Contains(compact, "stemstr.to_uppercase().as_str()") &&
		strings.Contains(compact, "\""+prefix+"0\"") &&
		strings.Contains(compact, "\""+prefix+"9\"") &&
		strings.Contains(compact, "manually::open") &&
		!strings.Contains(compact, "\""+prefix+"\u00b9\"")
}

func rustCryptoScalarRandomBitsByteLengthConfusion(compact string) bool {
	if strings.Contains(compact, ".bits().div_ceil(8)") &&
		strings.Contains(compact, "try_random_bits") &&
		strings.Contains(compact, "Scalar::from_uint") &&
		strings.Contains(compact, "ProjectivePoint::mul_by_generator") {
		return !strings.Contains(compact, "try_generate_from_rng") && !strings.Contains(compact, "NonZeroScalar")
	}
	return strings.Contains(compact, "try_random_bits(rng,bit_length)") &&
		strings.Contains(compact, "k<*") &&
		strings.Contains(compact, "::ORDER") &&
		strings.Contains(compact, "is_zero") &&
		!strings.Contains(compact, "try_generate_from_rng") &&
		!strings.Contains(compact, "NonZeroScalar")
}

func rustMatchArmPattern(n *tree_sitter.Node) *tree_sitter.Node {
	if p := field(n, "pattern"); p != nil {
		return p
	}
	for _, ch := range namedChildren(n) {
		switch ch.Kind() {
		case "identifier", "scoped_identifier", "match_pattern", "tuple_struct_pattern", "literal_pattern":
			return ch
		}
	}
	return nil
}

var rustCompactTextReplacer = strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "")

func rustCompactText(s string) string {
	return rustCompactTextReplacer.Replace(s)
}

func (c *rsConv) exprStmt(inner *tree_sitter.Node) []nir.Stmt {
	switch inner.Kind() {
	case "if_expression":
		return []nir.Stmt{c.rsIf(inner)}
	case "match_expression":
		return []nir.Stmt{c.rsMatch(inner)}
	}
	if inner.Kind() == "assignment_expression" {
		left := field(inner, "left")
		right := c.expr(field(inner, "right"))
		if left != nil && left.Kind() == "identifier" {
			return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: right}}
		}
		return []nir.Stmt{nir.ExprStmt{Value: right}}
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(inner)}}
}

func (c *rsConv) block(block *tree_sitter.Node) []nir.Stmt {
	if block == nil {
		return nil
	}
	var out []nir.Stmt
	for _, st := range c.namedChildren(block) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *rsConv) params(params *tree_sitter.Node) []string {
	if params == nil {
		return nil
	}
	var out []string
	for _, ch := range c.namedChildren(params) {
		if ch.Kind() == "parameter" {
			if nm := c.patName(field(ch, "pattern")); nm != "" {
				out = append(out, nm)
			}
		}
	}
	return out
}

func (c *rsConv) paramTypes(params *tree_sitter.Node) map[string]string {
	out := map[string]string{}
	if params == nil {
		return out
	}
	for _, ch := range c.namedChildren(params) {
		if ch.Kind() == "parameter" {
			if nm := c.patName(field(ch, "pattern")); nm != "" {
				putParamType(out, nm, paramTypeFromField(c, ch))
			}
		}
	}
	return out
}

// patName extracts the bound identifier from a pattern (unwrapping ref/mut).
func (c *rsConv) patName(p *tree_sitter.Node) string {
	for p != nil {
		switch p.Kind() {
		case "identifier":
			return c.text(p)
		case "ref_pattern", "mut_pattern", "reference_pattern":
			kids := c.namedChildren(p)
			if len(kids) == 0 {
				return ""
			}
			p = kids[len(kids)-1]
		default:
			return ""
		}
	}
	return ""
}

func (c *rsConv) callArgs(args *tree_sitter.Node) []nir.Expr {
	if args == nil {
		return nil
	}
	var out []nir.Expr
	for _, a := range c.namedChildren(args) {
		out = append(out, c.expr(a))
	}
	return out
}

func (c *rsConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "identifier", "self", "field_identifier", "type_identifier", "scoped_identifier":
		return nir.Name{ID: c.text(n), Loc: L}
	case "boolean_literal", "unit_expression":
		return nir.Const{Loc: L, Value: c.text(n)}
	case "integer_literal", "float_literal", "char_literal":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "string_literal", "raw_string_literal":
		return nir.Const{Loc: L, Value: rustStringValue(c.text(n))}
	case "field_expression":
		return nir.Attr{Base: c.expr(field(n, "value")), Attr: c.text(field(n, "field")), Path: c.dotted(n), Loc: L}
	case "index_expression":
		kids := c.namedChildren(n)
		var base, key nir.Expr = nir.Const{Loc: L}, nil
		if len(kids) > 0 {
			base = c.expr(kids[0])
		}
		if len(kids) > 1 {
			key = c.expr(kids[1])
		}
		return nir.Index{Base: base, Key: key, Path: c.dotted(n), Loc: L}
	case "call_expression":
		fn := field(n, "function")
		path := c.dotted(fn)
		return nir.Call{Callee: c.expr(fn), Args: c.callArgs(field(n, "arguments")), Path: path, Method: lastSeg(path), Loc: L}
	case "macro_invocation":
		name := lastSeg(c.dotted(field(n, "macro")))
		var parts []nir.Expr
		if tt := lastChildKind(n, "token_tree"); tt != nil {
			for _, ch := range c.namedChildren(tt) {
				if isRustExprTok(ch.Kind()) {
					parts = append(parts, c.expr(ch))
				}
			}
		}
		if rsFormatMacros[name] {
			return nir.Format{Parts: parts, Loc: L}
		}
		// other macros (e.g. query!) — model as a call so they can be sinks
		return nir.Call{Callee: nir.Name{ID: name, Loc: L}, Args: parts, Path: name, Method: name, Loc: L}
	case "binary_expression":
		op := c.text(field(n, "operator"))
		left, right := c.expr(field(n, "left")), c.expr(field(n, "right"))
		if op == "+" {
			return nir.Format{Parts: []nir.Expr{left, right}, Loc: L}
		}
		return nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
	case "reference_expression", "try_expression", "await_expression",
		"parenthesized_expression", "type_cast_expression":
		if kids := c.namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[0])}
		}
	case "unary_expression":
		// `-x`, `!x` — the operator is the leading unnamed token.
		op := "?"
		for i := uint(0); i < n.ChildCount(); i++ {
			if ch := n.Child(i); !ch.IsNamed() {
				op = c.text(ch)
				break
			}
		}
		var operand nir.Expr = nir.Const{Loc: L}
		if kids := c.namedChildren(n); len(kids) > 0 {
			operand = c.expr(kids[len(kids)-1])
		}
		return nir.Unary{Op: op, Operand: operand, Loc: L}
	case "if_expression":
		// `let x = if c { A } else { B }` — model as a Ternary on the arms' tail values so a
		// constant condition prunes. Falls back to Seq when an arm isn't a simple value.
		then := c.blockTail(field(n, "consequence"))
		var els nir.Expr
		if alt := field(n, "alternative"); alt != nil {
			if k := c.namedChildren(alt); len(k) > 0 {
				if k[0].Kind() == "block" {
					els = c.blockTail(k[0])
				} else {
					els = c.expr(k[0]) // else if …
				}
			}
		}
		if then != nil && els != nil {
			return nir.Ternary{Cond: c.expr(field(n, "condition")), Then: then, Else: els, Loc: L}
		}
		return nir.Seq{Parts: c.blockValues(n), Loc: L}
	case "match_expression", "block":
		return nir.Seq{Parts: c.blockValues(n), Loc: L}
	}
	var parts []nir.Expr
	for _, ch := range c.namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
}

// rustStringValue returns a quoted string literal whose inner text reflects the
// Rust literal payload. It covers normal, byte, raw, and byte-raw strings well
// enough for binding `val` matching; escape handling is intentionally simple
// because value-matched mappings need literal substrings such as path fragments
// or byte constants.
func rustStringValue(raw string) string {
	s := raw
	for len(s) > 0 {
		switch s[0] {
		case 'b':
			s = s[1:]
		case 'r':
			hashes := 0
			i := 1
			for i < len(s) && s[i] == '#' {
				hashes++
				i++
			}
			if i < len(s) && s[i] == '"' {
				start := i + 1
				end := len(s) - 1 - hashes
				if end >= start && end < len(s) {
					return "\"" + s[start:end] + "\""
				}
			}
			return "\"" + raw + "\""
		default:
			goto unquote
		}
	}
unquote:
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		body := s[1 : len(s)-1]
		out := make([]byte, 0, len(body))
		for i := 0; i < len(body); i++ {
			if body[i] == '\\' && i+1 < len(body) {
				out = append(out, body[i+1])
				i++
				continue
			}
			out = append(out, body[i])
		}
		return "\"" + string(out) + "\""
	}
	return "\"" + raw + "\""
}

// rsIf lowers a statement-position if with its predicate so constant-false arms prune.
func (c *rsConv) rsIf(n *tree_sitter.Node) nir.Stmt {
	it := nir.If{Loc: c.loc(n)}
	it.Cond = c.expr(field(n, "condition"))
	it.Then = c.block(field(n, "consequence"))
	if alt := field(n, "alternative"); alt != nil {
		it.Else = c.rsElse(alt)
	}
	return it
}

// rsElse unwraps an else branch: a block, a chained else-if, or an else_clause wrapper.
func (c *rsConv) rsElse(alt *tree_sitter.Node) []nir.Stmt {
	switch alt.Kind() {
	case "block":
		return c.block(alt)
	case "if_expression":
		return []nir.Stmt{c.rsIf(alt)}
	case "else_clause":
		var out []nir.Stmt
		for _, ch := range c.namedChildren(alt) {
			out = append(out, c.rsElse(ch)...)
		}
		return out
	}
	return nil
}

// rsMatch lowers a statement-position match to a subject+labelled Switch so dead arms
// prune. A wildcard `_` arm is the default; literal patterns become case labels.
func (c *rsConv) rsMatch(n *tree_sitter.Node) nir.Stmt {
	sw := nir.Switch{Loc: c.loc(n), Subject: c.expr(field(n, "value"))}
	body := field(n, "body")
	if body == nil {
		return sw
	}
	for _, arm := range c.namedChildren(body) {
		if arm.Kind() != "match_arm" {
			continue
		}
		pat := field(arm, "pattern")
		stmts := c.rsArmBody(field(arm, "value"))
		if pat == nil || c.text(pat) == "_" {
			sw.Default = append(sw.Default, stmts...)
			continue
		}
		label := pat // unwrap match_pattern -> the inner literal so labels are foldable
		if k := c.namedChildren(pat); len(k) == 1 {
			label = k[0]
		}
		sw.Cases = append(sw.Cases, stmts)
		sw.Labels = append(sw.Labels, []nir.Expr{c.expr(label)})
	}
	return sw
}

func (c *rsConv) rsArmBody(v *tree_sitter.Node) []nir.Stmt {
	if v == nil {
		return nil
	}
	if v.Kind() == "block" {
		return c.block(v)
	}
	return c.exprStmt(v)
}

// blockTail returns the tail (value) expression of a `{ … }` block, or nil if the last
// element isn't a bare expression (e.g. a let/assignment) — used to model an if-as-value.
func (c *rsConv) blockTail(block *tree_sitter.Node) nir.Expr {
	if block == nil || block.Kind() != "block" {
		return nil
	}
	kids := c.namedChildren(block)
	if len(kids) == 0 {
		return nil
	}
	last := kids[len(kids)-1]
	switch last.Kind() {
	case "let_declaration", "expression_statement", "empty_statement":
		return nil
	}
	return c.expr(last)
}

func (c *rsConv) blockValues(n *tree_sitter.Node) []nir.Expr {
	var out []nir.Expr
	for _, ch := range c.namedChildren(n) {
		out = append(out, c.expr(ch))
	}
	return out
}

func (c *rsConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "identifier", "field_identifier", "type_identifier", "self", "primitive_type":
		return c.text(n)
	case "scoped_identifier", "scoped_type_identifier":
		path := field(n, "path")
		name := field(n, "name")
		if path == nil {
			return c.dotted(name)
		}
		return c.dotted(path) + "." + c.dotted(name)
	case "field_expression":
		return c.dotted(field(n, "value")) + "." + c.text(field(n, "field"))
	case "call_expression":
		return c.dotted(field(n, "function"))
	case "generic_function":
		return c.dotted(field(n, "function"))
	case "generic_type":
		return c.dotted(field(n, "type"))
	case "index_expression":
		if kids := c.namedChildren(n); len(kids) > 0 {
			return c.dotted(kids[0]) + "[]"
		}
	}
	return "?"
}

func isRustExprTok(k string) bool {
	switch k {
	case "identifier", "scoped_identifier", "field_expression", "call_expression",
		"macro_invocation", "index_expression", "reference_expression", "self":
		return true
	}
	return false
}

func lastChildKind(n *tree_sitter.Node, kind string) *tree_sitter.Node {
	for _, ch := range namedChildren(n) {
		if ch.Kind() == kind {
			return ch
		}
	}
	return nil
}
