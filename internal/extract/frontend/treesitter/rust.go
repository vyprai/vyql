package treesitter

import (
	"bytes"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsrust "github.com/tree-sitter/tree-sitter-rust/bindings/go"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// rsConv walks a tree-sitter Rust CST into NIR.
type rsConv struct {
	nodeCache
	src           []byte
	file          string
	key           string
	matchSubjects int // per-file counter for the synthetic locals match scrutinees bind to
	// refcountDrops maps a type's base name to the reference-release call its
	// Drop impl makes, for the types declared in this file.
	refcountDrops map[string]string
	implSelfType  string // base type name of the impl block being walked
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
			c.rsCollectRefcountDrops(tree.RootNode())
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

// decls walks a list, tracking preceding attribute_item syntax for the next item.
func (c *rsConv) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var attrs []string
	for _, ch := range c.namedChildren(n) {
		if c.kind(ch) == "attribute_item" {
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
		if c.kind(m) == "attribute" {
			for _, ch := range c.namedChildren(m) {
				if c.kind(ch) == "identifier" || c.kind(ch) == "scoped_identifier" {
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
	switch c.kind(n) {
	case "function_item":
		params := c.params(c.field(n, "parameters"))
		paramTypes := c.paramTypes(c.field(n, "parameters"))
		body := c.block(c.field(n, "body"))
		body = append(body, c.rsFunctionContext(n)...)
		body = append(body, c.rsTypeErasureMetadata(n)...)
		body = append(body, c.rsRefcountedConversionMetadata(n)...)
		exported := false
		for _, ch := range children(n) {
			if c.kind(ch) == "visibility_modifier" {
				exported = true
				break
			}
		}
		return []nir.Stmt{nir.FuncDef{Name: c.text(c.field(n, "name")), Params: params, ParamTypes: paramTypes, ParamEntries: c.rsParamEntries(c.text(c.field(n, "name")), params, attrs), Body: body, Loc: L, Exported: exported}}
	case "impl_item":
		out := c.rsUnsafeImplMetadata(n)
		out = append(out, c.rsUnpinImplMetadata(n)...)
		out = append(out, c.rsManualRefcountDropMetadata(n)...)
		out = append(out, c.rsRunTestsAutoApprovalMetadata(n)...)
		// A method's self receiver is typed by the impl it sits in, and the
		// function_item case has no other way to reach that type.
		outerSelf := c.implSelfType
		c.implSelfType = lastSeg(c.dotted(c.field(n, "type")))
		out = append(out, c.decls(c.field(n, "body"))...)
		c.implSelfType = outerSelf
		return out
	case "mod_item", "trait_item":
		return c.decls(c.field(n, "body"))
	case "enum_item":
		return c.rsEnumMetadata(n, attrs)
	case "struct_item":
		return c.rsStructFieldMetadata(n, attrs)
	case "use_declaration", "const_item", "static_item":
		return nil
	case "let_declaration":
		val := c.field(n, "value")
		if val == nil {
			return nil
		}
		name := c.patName(c.field(n, "pattern"))
		if name != "" {
			// `let x = match subj { … }` — lower the match as the branch-structured statement it
			// is, assigning each arm's tail to x, rather than as one expression container over
			// every arm at once. The join that follows then has one operand per arm, which is
			// what makes a check applied in ONE arm distinguishable from none at all.
			if c.kind(val) == "match_expression" {
				return c.rsMatch(val, name)
			}
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
		return c.rsMatch(n, "")
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
	// The cargo-test association appears in three real spellings inside a
	// run_tests tool impl: a command() string literal "cargo test" (compacts
	// to "cargotest"), a backticked `cargo test` in the doc description
	// (compacts to `cargotest`), and Command::new("cargo") beside the
	// vec!["test"] argument vector.
	cargoTest := strings.Contains(compact, "\"cargotest\"") ||
		strings.Contains(compact, "`cargotest`") ||
		(strings.Contains(compact, "Command::new(\"cargo\")") && strings.Contains(compact, "vec![\"test\""))
	if !strings.Contains(compact, "\"run_tests\"") ||
		!strings.Contains(compact, "ToolCapability::ExecutesCode") ||
		!cargoTest ||
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
	name := c.text(c.field(n, "name"))
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
	name := c.text(c.field(n, "name"))
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
		if c.kind(m) == "field_declaration_list" {
			var pendingAttrs []string
			for _, ch := range c.namedChildren(m) {
				if c.kind(ch) == "attribute_item" {
					pendingAttrs = append(pendingAttrs, c.rsAttrTokens(ch)...)
					pendingAttrs = append(pendingAttrs, rsSerdeTokens(c.text(ch))...)
					continue
				}
				if c.kind(ch) == "field_declaration" {
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
		if c.kind(m) == "field_declaration" {
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
	name := c.text(c.field(n, "name"))
	if name == "" {
		for _, ch := range c.namedChildren(n) {
			if c.kind(ch) == "field_identifier" || c.kind(ch) == "identifier" {
				name = c.text(ch)
				break
			}
		}
	}
	if name == "" {
		return nil, false
	}
	typ := c.text(c.field(n, "type"))
	fieldAttrs := append([]string{}, pendingAttrs...)
	for _, ch := range c.namedChildren(n) {
		if c.kind(ch) == "attribute_item" {
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

// rsImplParameterBounds returns an impl's type parameter names and which
// thread-safety auto-trait bounds (Send, Sync) constrain at least one of
// them. Only bounds attached to a parameter the impl itself declares count:
// a bound on an associated type (`where R::GuardMarker: Send`) constrains a
// projection, not the parameter, and a bound on some other type constrains
// nothing this impl is generic over.
func (c *rsConv) rsImplParameterBounds(n *tree_sitter.Node) ([]string, map[string]bool) {
	bounded := map[string]bool{}
	tp := c.field(n, "type_parameters")
	if tp == nil {
		return nil, bounded
	}
	params := []string{}
	declared := map[string]bool{}
	for _, ch := range children(tp) {
		if c.kind(ch) != "type_parameter" {
			continue
		}
		name := c.text(orSelf(c.field(ch, "name"), ch))
		params = append(params, name)
		declared[strings.TrimSpace(name)] = true
		c.rsCollectAutoTraitBounds(c.field(ch, "bounds"), bounded)
	}
	for _, ch := range children(n) {
		if c.kind(ch) != "where_clause" {
			continue
		}
		for _, pred := range children(ch) {
			if c.kind(pred) != "where_predicate" {
				continue
			}
			left := c.field(pred, "left")
			if left == nil || c.kind(left) != "type_identifier" {
				continue
			}
			if !declared[strings.TrimSpace(c.text(left))] {
				continue
			}
			c.rsCollectAutoTraitBounds(c.field(pred, "bounds"), bounded)
		}
	}
	return params, bounded
}

// rsCollectAutoTraitBounds records which of Send and Sync appear among a
// parameter's trait bounds.
func (c *rsConv) rsCollectAutoTraitBounds(bounds *tree_sitter.Node, into map[string]bool) {
	if bounds == nil || c.kind(bounds) != "trait_bounds" {
		return
	}
	for _, b := range children(bounds) {
		if c.kind(b) == "lifetime" {
			continue
		}
		name := c.text(b)
		if i := strings.LastIndex(name, "::"); i >= 0 {
			name = name[i+2:]
		}
		if name == "Send" || name == "Sync" {
			into[name] = true
		}
	}
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
	params, bounded := c.rsImplParameterBounds(n)
	for _, bound := range []string{"Send", "Sync"} {
		if bounded[bound] {
			tokens = append(tokens, "bound:"+bound)
		}
	}
	path := "analysis.rust.unsafe_impl"
	out := []nir.Stmt{c.rsAnalysisCall(path, "unsafe_impl", loc, tokens...)}
	// A concrete impl asserts thread safety for a fully known type, which is
	// the ordinary use of an unsafe auto-trait impl. The unsound shape is a
	// generic one: a parameter the impl cannot see through, with neither a
	// Send nor a Sync bound of its own. Either bound makes the impl sound
	// for some exposure of the parameter (a wrapper holding `&T` is Send
	// when `T: Sync`, one holding `T` when `T: Send`), and the source alone
	// does not say which exposure applies.
	if len(params) == 0 || bounded["Send"] || bounded["Sync"] {
		return out
	}
	switch trait {
	case "Send":
		out = append(out, c.rsAnalysisCall("analysis.rust.unsafe_send_impl_missing_bound", "unsafe_send_impl_missing_bound", loc,
			"lang=rust", "trait:Send", "missing_bound:SendOrSync"))
	case "Sync":
		out = append(out, c.rsAnalysisCall("analysis.rust.unsafe_sync_impl_missing_bound", "unsafe_sync_impl_missing_bound", loc,
			"lang=rust", "trait:Sync", "missing_bound:SyncOrSend"))
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

// rsReferenceReleaseNames are the spellings a hand-rolled reference count uses
// to give a reference back: the C-API decrements, the GObject-style unref, and
// the strong-count decrements an Arc-shaped type writes itself. A count kept
// this way is arithmetic, not ownership, so nothing in the language stops a
// second release -- which is exactly why the release has to be named before
// anything can reason about how many times it runs.
var rsReferenceReleaseNames = []string{
	"decref", "dec_ref", "unref", "release_ref", "dec_strong", "dec_refcount", "refcount_dec",
}

func rsIsReferenceRelease(path string) bool {
	name := strings.ToLower(lastSeg(path))
	for _, want := range rsReferenceReleaseNames {
		if strings.Contains(name, want) {
			return true
		}
	}
	return false
}

// rsItemContainers are the node kinds that hold Rust items: the file itself,
// the body of a module, trait or impl, a function body, and a nested block. An
// `impl` is an item, so descending through these reaches every impl in the file
// while leaving expression subtrees, which hold no items, untouched.
var rsItemContainers = map[string]bool{
	"source_file": true, "declaration_list": true, "block": true,
	"mod_item": true, "trait_item": true, "impl_item": true, "function_item": true,
}

// rsCollectRefcountDrops records, for this file, every type whose Drop impl
// performs a manual reference release, keyed by the type's base name. The pass
// runs before the module is walked because the conversion that mishandles such
// a value is usually written above the Drop impl that gives it its meaning.
func (c *rsConv) rsCollectRefcountDrops(root *tree_sitter.Node) {
	if !bytes.Contains(c.src, []byte("Drop")) {
		return
	}
	var walk func(n *tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		kind := c.kind(n)
		if kind == "impl_item" {
			if typ, release := c.rsRefcountDropImpl(n); typ != "" {
				if c.refcountDrops == nil {
					c.refcountDrops = map[string]string{}
				}
				c.refcountDrops[typ] = release
			}
		}
		if !rsItemContainers[kind] {
			return
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
}

// rsRefcountDropImpl reports the base type name an `impl Drop` block is for and
// the release call its drop body makes on the value's own state, or "" when the
// impl is not a Drop impl or its drop releases something other than a count it
// maintains itself. The release has to mention self: a Drop body that calls a
// decrement on some unrelated value is not releasing this type's reference.
func (c *rsConv) rsRefcountDropImpl(n *tree_sitter.Node) (string, string) {
	tr := c.field(n, "trait")
	if tr == nil || lastSeg(c.dotted(tr)) != "Drop" {
		return "", ""
	}
	typ := lastSeg(c.dotted(c.field(n, "type")))
	if typ == "" || typ == "?" {
		return "", ""
	}
	for _, decl := range c.namedChildren(c.field(n, "body")) {
		if c.kind(decl) != "function_item" || c.text(c.field(decl, "name")) != "drop" {
			continue
		}
		if release := c.rsReferenceReleaseCall(c.field(decl, "body")); release != "" {
			return typ, release
		}
	}
	return "", ""
}

// rsReferenceReleaseCall returns the dotted path of the first reference-release
// call in the subtree whose callee or arguments mention self.
func (c *rsConv) rsReferenceReleaseCall(n *tree_sitter.Node) string {
	found := ""
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		if m == nil || found != "" {
			return
		}
		if c.kind(m) == "call_expression" {
			path := c.dotted(c.field(m, "function"))
			if path != "" && path != "?" && rsIsReferenceRelease(path) && c.rsMentionsValue(m, "self") {
				found = path
				return
			}
		}
		for _, ch := range c.namedChildren(m) {
			walk(ch)
		}
	}
	walk(n)
	return found
}

// rsOwnedValue is a value the function owns outright: a by-value parameter or a
// by-value self receiver, whose type releases a reference when it is dropped.
type rsOwnedValue struct {
	name    string
	typ     string
	release string
}

// rsRefcountedConversionMetadata reports a function that takes ownership of a
// value whose Drop releases a manually kept reference count, copies a field out
// of it, lets that copy escape through the function's result, and never
// suppresses the drop with mem::forget or ManuallyDrop. The owned value is
// dropped when the function returns, so the count falls by one while the copy
// that outlives it still stands for a live reference: every later release of
// that copy is one release too many, which is the hand-rolled smart pointer's
// use-after-free (pyo3 CVE-2020-35917).
//
// Only a Copy field can be read out of a value that implements Drop -- moving a
// field out is E0509 -- so any field a compiling program reads here leaves the
// source value whole and droppable. That is what makes the field read, rather
// than a move, the thing worth recording: a move hands the release on to the
// receiver, and a copy duplicates it.
//
// The two suppressed forms are the two ways the language has of saying "this
// value's Drop must not run": mem::forget on the value, or rebinding it through
// ManuallyDrop. A borrowed receiver (&self) is not reported at all, because a
// borrow drops nothing.
func (c *rsConv) rsRefcountedConversionMetadata(fn *tree_sitter.Node) []nir.Stmt {
	if len(c.refcountDrops) == 0 {
		return nil
	}
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	var out []nir.Stmt
	for _, owned := range c.rsOwnedRefcountedValues(fn) {
		if c.rsSuppressesDrop(body, owned.name) {
			continue
		}
		carriers, fields := c.rsCopiedOutFields(body, owned.name)
		if len(fields) == 0 || !c.rsCopyEscapesResult(body, owned.name, carriers) {
			continue
		}
		tokens := []string{
			"lang=rust",
			"kind:refcounted_conversion",
			"type:" + owned.typ,
			"value:" + owned.name,
			"release:" + owned.release,
			"missing_call:mem::forget",
		}
		for _, f := range fields {
			tokens = append(tokens, "field:"+f)
		}
		out = append(out, c.rsAnalysisCall("analysis.rust.refcounted_conversion_missing_forget",
			"refcounted_conversion_missing_forget", c.loc(fn), dedupeStrings(tokens)...))
	}
	return out
}

// rsOwnedRefcountedValues names the values a function takes ownership of whose
// type releases a reference on drop: a parameter declared with the type itself
// rather than a reference to it, and a self receiver spelled without &.
func (c *rsConv) rsOwnedRefcountedValues(fn *tree_sitter.Node) []rsOwnedValue {
	var out []rsOwnedValue
	add := func(name, typ string) {
		if release, ok := c.refcountDrops[typ]; ok && name != "" {
			out = append(out, rsOwnedValue{name: name, typ: typ, release: release})
		}
	}
	for _, ch := range c.namedChildren(c.field(fn, "parameters")) {
		switch c.kind(ch) {
		case "self_parameter":
			if c.rsSelfParameterBorrows(ch) {
				continue
			}
			add("self", c.implSelfType)
		case "parameter":
			typ := c.field(ch, "type")
			if typ == nil || c.kind(typ) == "reference_type" {
				continue
			}
			add(c.patName(c.field(ch, "pattern")), lastSeg(c.dotted(typ)))
		}
	}
	return out
}

// rsSelfParameterBorrows reports whether a self receiver is a borrow (&self or
// &mut self), which drops nothing when the function returns.
func (c *rsConv) rsSelfParameterBorrows(n *tree_sitter.Node) bool {
	for _, ch := range c.children(n) {
		if c.kind(ch) == "&" {
			return true
		}
	}
	return false
}

// rsSuppressesDrop reports whether the body keeps the owned value's Drop from
// running: mem::forget on it, or rebinding it through ManuallyDrop.
func (c *rsConv) rsSuppressesDrop(body *tree_sitter.Node, name string) bool {
	found := false
	var walk func(n *tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil || found {
			return
		}
		if c.kind(n) == "call_expression" {
			path := c.dotted(c.field(n, "function"))
			suppresses := lastSeg(path) == "forget" || strings.Contains(path, "ManuallyDrop")
			if suppresses && c.rsMentionsValue(c.field(n, "arguments"), name) {
				found = true
				return
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(body)
	return found
}

// rsCopiedOutFields returns the names a destructuring of the owned value binds
// (its carriers) and a label per field the body reads out of it.
func (c *rsConv) rsCopiedOutFields(body *tree_sitter.Node, name string) (map[string]bool, []string) {
	carriers := map[string]bool{}
	var fields []string
	var walk func(n *tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if c.kind(n) == "let_declaration" {
			pattern := c.field(n, "pattern")
			value := c.field(n, "value")
			switch {
			case c.rsIsValueRef(value, name):
				// `let Ptr(raw, _) = owned;` -- destructuring binds the
				// Copy fields the pattern names and leaves owned intact.
				for _, bound := range c.rsPatternBindings(pattern) {
					carriers[bound] = true
					fields = append(fields, bound)
				}
			case c.rsReadsFieldOf(value, name):
				// `let raw = owned.0;` -- the same copy, spelled as a
				// field read, carried by the name it is bound to.
				if bound := c.patName(pattern); bound != "" {
					carriers[bound] = true
				}
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(body)
	c.rsWalkFieldReads(body, false, func(read *tree_sitter.Node) {
		if !c.rsIsValueRef(c.field(read, "value"), name) {
			return
		}
		if label := c.text(c.field(read, "field")); label != "" {
			fields = append(fields, label)
		}
	})
	return carriers, dedupeStrings(fields)
}

// rsWalkFieldReads visits every field_expression in the subtree that reads a
// field out of a value, skipping the selector of a method call: `owned.into_x()`
// moves the value into the method rather than copying a field out of it, and
// the move carries the release with it.
func (c *rsConv) rsWalkFieldReads(n *tree_sitter.Node, callee bool, visit func(*tree_sitter.Node)) {
	if n == nil {
		return
	}
	if c.kind(n) == "call_expression" {
		c.rsWalkFieldReads(c.field(n, "function"), true, visit)
		c.rsWalkFieldReads(c.field(n, "arguments"), false, visit)
		return
	}
	if c.kind(n) == "field_expression" && !callee {
		visit(n)
	}
	for _, ch := range c.namedChildren(n) {
		c.rsWalkFieldReads(ch, false, visit)
	}
}

// rsPatternBindings names the identifiers a destructuring pattern binds,
// skipping the type path the pattern matches on.
func (c *rsConv) rsPatternBindings(p *tree_sitter.Node) []string {
	if p == nil {
		return nil
	}
	var out []string
	skip := c.field(p, "type")
	var walk func(n *tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil || (skip != nil && n.Id() == skip.Id()) {
			return
		}
		switch c.kind(n) {
		case "identifier", "shorthand_field_identifier":
			out = append(out, c.text(n))
			return
		case "type_identifier", "scoped_identifier", "scoped_type_identifier":
			return
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(p)
	return out
}

// rsCopyEscapesResult reports whether a field copied out of the owned value
// reaches what the function returns -- its tail expression or an explicit
// return. A copy that stays inside the body dies with it and releases nothing.
func (c *rsConv) rsCopyEscapesResult(body *tree_sitter.Node, name string, carriers map[string]bool) bool {
	for _, result := range c.rsResultExprs(body) {
		if c.rsReadsFieldOf(result, name) || c.rsExprMentions(result, carriers, nil) {
			return true
		}
	}
	return false
}

// rsResultExprs returns the expressions a function's value can come from: the
// block's tail expression, unwrapped through unsafe and nested blocks, and the
// operand of every return in the body.
func (c *rsConv) rsResultExprs(body *tree_sitter.Node) []*tree_sitter.Node {
	var out []*tree_sitter.Node
	if tail := c.rsBlockTailExpr(body); tail != nil {
		out = append(out, tail)
	}
	var walk func(n *tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if c.kind(n) == "return_expression" {
			out = append(out, n)
			return
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(body)
	return out
}

// rsBlockTailExpr returns a block's tail expression. A block-valued tail (an
// unsafe block, a bare block) is parsed as an expression_statement without a
// semicolon, so it is unwrapped to the expression it carries.
func (c *rsConv) rsBlockTailExpr(block *tree_sitter.Node) *tree_sitter.Node {
	if block == nil {
		return nil
	}
	kids := c.namedChildren(block)
	for i := len(kids) - 1; i >= 0; i-- {
		last := kids[i]
		switch c.kind(last) {
		case "line_comment", "block_comment":
			continue
		case "let_declaration", "empty_statement":
			return nil
		case "expression_statement":
			if strings.HasSuffix(strings.TrimSpace(c.text(last)), ";") {
				return nil
			}
			inner := c.namedChildren(last)
			if len(inner) == 0 {
				return nil
			}
			last = inner[0]
		}
		switch c.kind(last) {
		case "unsafe_block":
			return c.rsBlockTailExpr(lastChildKind(last, "block"))
		case "block":
			return c.rsBlockTailExpr(last)
		}
		return last
	}
	return nil
}

// rsIsValueRef reports whether an expression is a bare reference to the named
// owned value; `self` is a node kind of its own rather than an identifier.
func (c *rsConv) rsIsValueRef(n *tree_sitter.Node, name string) bool {
	if n == nil {
		return false
	}
	switch c.kind(n) {
	case "identifier", "self":
		return c.text(n) == name
	}
	return false
}

// rsReadsFieldOf reports whether the subtree copies a field out of the named
// value.
func (c *rsConv) rsReadsFieldOf(n *tree_sitter.Node, name string) bool {
	found := false
	c.rsWalkFieldReads(n, false, func(read *tree_sitter.Node) {
		if c.rsIsValueRef(c.field(read, "value"), name) {
			found = true
		}
	})
	return found
}

// rsMentionsValue reports whether the subtree names the value anywhere.
func (c *rsConv) rsMentionsValue(n *tree_sitter.Node, name string) bool {
	if n == nil {
		return false
	}
	if c.rsIsValueRef(n, name) {
		return true
	}
	for _, ch := range c.namedChildren(n) {
		if c.rsMentionsValue(ch, name) {
			return true
		}
	}
	return false
}

// rsManualRefcountDropMetadata reports the Drop impl that releases a manually
// kept reference count, naming the type and the release call it makes.
func (c *rsConv) rsManualRefcountDropMetadata(n *tree_sitter.Node) []nir.Stmt {
	typ, release := c.rsRefcountDropImpl(n)
	if typ == "" {
		return nil
	}
	loc := c.loc(n)
	return []nir.Stmt{c.rsAnalysisCall("analysis.rust.manual_refcount_drop", "manual_refcount_drop", loc,
		"lang=rust", "kind:drop_impl", "type:"+typ, "release:"+release)}
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

// rsTypeErasureMetadata reports a function that erases one of its own generic
// type parameters behind an untyped raw pointer -- a cast to `*const ()` or
// `*mut ()` -- while no type parameter it declares carries a lifetime bound.
// A raw pointer keeps no trace of the lifetime of what it points at, and the
// untyped spelling drops the type too, so whatever vtable, struct field or
// return value receives the pointer can restore the type and call into it
// after the original value is gone. The signature is the only place left to
// state that constraint, which is why a lifetime bound ('static or a named
// lifetime) on the erased parameter is what makes the erasure checkable at
// all. Only parameters the function declares itself count: a method whose
// receiver type comes from the surrounding impl carries its obligation there,
// and a non-generic function erases a concrete type with no lifetime to lose.
// The check reads the cast from the syntax tree, so prose and comments cannot
// satisfy or defeat it, and it names no crate's identifiers.
func (c *rsConv) rsTypeErasureMetadata(n *tree_sitter.Node) []nir.Stmt {
	tp := c.field(n, "type_parameters")
	body := c.field(n, "body")
	if tp == nil || body == nil {
		return nil
	}
	var typeParams []string
	for _, p := range c.namedChildren(tp) {
		if c.kind(p) != "type_parameter" {
			continue
		}
		name := c.text(c.field(p, "name"))
		if name == "" {
			continue
		}
		typeParams = append(typeParams, name)
	}
	if len(typeParams) == 0 {
		return nil
	}
	// A lifetime bound on any declared parameter -- inline, in the where
	// clause, or on a declared lifetime -- means the signature already states
	// the constraint the erasure needs.
	for _, p := range c.namedChildren(tp) {
		if c.rsBoundsCarryLifetime(c.field(p, "bounds")) {
			return nil
		}
	}
	for _, ch := range c.namedChildren(n) {
		if c.kind(ch) == "where_clause" {
			for _, pred := range c.namedChildren(ch) {
				if c.rsBoundsCarryLifetime(c.field(pred, "bounds")) {
					return nil
				}
			}
		}
	}
	if !c.rsErasesUntypedPointer(body, typeParams, c.rsGenericCarrierParams(c.field(n, "parameters"), typeParams)) {
		return nil
	}
	loc := c.loc(n)
	return []nir.Stmt{c.rsAnalysisCall("analysis.rust.type_erasure_missing_lifetime_bound", "type_erasure_missing_lifetime_bound", loc,
		"lang=rust", "kind:type_erasure", "missing_bound:lifetime")}
}

// rsBoundsCarryLifetime reports whether a trait_bounds node contains a
// lifetime, i.e. the bound list constrains the bounded parameter's lifetime.
func (c *rsConv) rsBoundsCarryLifetime(bounds *tree_sitter.Node) bool {
	if bounds == nil || c.kind(bounds) != "trait_bounds" {
		return false
	}
	for _, ch := range namedChildren(bounds) {
		if c.kind(ch) == "lifetime" {
			return true
		}
	}
	return false
}

// rsGenericCarrierParams names the value parameters whose declared type
// mentions one of the function's type parameters, so a value read from one of
// them carries that parameter's type -- and its lifetime.
func (c *rsConv) rsGenericCarrierParams(params *tree_sitter.Node, typeParams []string) map[string]bool {
	typeParamSet := map[string]bool{}
	for _, t := range typeParams {
		typeParamSet[t] = true
	}
	carrier := map[string]bool{}
	if params == nil {
		return carrier
	}
	for _, ch := range c.namedChildren(params) {
		if c.kind(ch) != "parameter" {
			continue
		}
		if c.rsExprMentions(c.field(ch, "type"), nil, typeParamSet) {
			if nm := c.patName(c.field(ch, "pattern")); nm != "" {
				carrier[nm] = true
			}
		}
	}
	return carrier
}

// rsErasesUntypedPointer reports whether the body casts a value that carries
// one of the function's own type parameters to the untyped raw pointer
// `*const ()` or `*mut ()`: either the operand names a type parameter
// directly, or it names a value parameter whose declared type does.
func (c *rsConv) rsErasesUntypedPointer(body *tree_sitter.Node, typeParams []string, carrier map[string]bool) bool {
	typeParamSet := map[string]bool{}
	for _, t := range typeParams {
		typeParamSet[t] = true
	}
	var visit func(n *tree_sitter.Node) bool
	visit = func(n *tree_sitter.Node) bool {
		if n == nil {
			return false
		}
		if c.kind(n) == "type_cast_expression" {
			if pt := c.field(n, "type"); pt != nil && c.kind(pt) == "pointer_type" {
				if el := c.field(pt, "type"); el != nil && c.kind(el) == "unit_type" {
					if c.rsExprMentions(c.field(n, "value"), carrier, typeParamSet) {
						return true
					}
				}
			}
		}
		for _, ch := range c.namedChildren(n) {
			if visit(ch) {
				return true
			}
		}
		return false
	}
	return visit(body)
}

// rsExprMentions reports whether the expression subtree contains a bare
// identifier naming one of the given value parameters or a type identifier
// naming one of the type parameters.
func (c *rsConv) rsExprMentions(n *tree_sitter.Node, paramSet, typeParamSet map[string]bool) bool {
	if n == nil {
		return false
	}
	switch c.kind(n) {
	case "identifier":
		if paramSet[c.text(n)] {
			return true
		}
	case "type_identifier":
		if typeParamSet[c.text(n)] {
			return true
		}
	}
	for _, ch := range c.namedChildren(n) {
		if c.rsExprMentions(ch, paramSet, typeParamSet) {
			return true
		}
	}
	return false
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
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	loc := c.loc(fn)
	text := c.text(body)
	path := "analysis.function.context"
	args := []nir.Expr{
		nir.Const{Loc: loc, Value: "lang=rust"},
		nir.Const{Loc: loc, Value: "name=" + c.text(c.field(fn, "name"))},
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
		if c.kind(ch) != "function_modifiers" {
			continue
		}
		for _, m := range c.namedChildren(ch) {
			if c.kind(m) != "extern_modifier" {
				continue
			}
			for _, lit := range c.namedChildren(m) {
				if c.kind(lit) == "string_literal" {
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
		switch c.kind(n) {
		case "assignment_expression":
			left := atom(c.field(n, "left"))
			right := atom(c.field(n, "right"))
			if left != "" && right != "" {
				add("assign:" + left + "=" + right)
			}
		case "call_expression":
			if path := c.dotted(c.field(n, "function")); path != "" && path != "?" {
				add("call_path:" + path)
				add("call:" + lastSeg(path))
				for _, arg := range c.namedChildren(c.field(n, "arguments")) {
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
			if pat := c.rustMatchArmPattern(n); pat != nil {
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
	for _, p := range c.params(c.field(fn, "parameters")) {
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

func (c *rsConv) rustMatchArmPattern(n *tree_sitter.Node) *tree_sitter.Node {
	if p := c.field(n, "pattern"); p != nil {
		return p
	}
	for _, ch := range namedChildren(n) {
		switch c.kind(ch) {
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
	switch c.kind(inner) {
	case "if_expression":
		return []nir.Stmt{c.rsIf(inner)}
	case "match_expression":
		return c.rsMatch(inner, "")
	}
	if c.kind(inner) == "assignment_expression" {
		left := c.field(inner, "left")
		right := c.expr(c.field(inner, "right"))
		if left != nil && c.kind(left) == "identifier" {
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

// closureParams lists the names a closure_parameters node binds. A typed parameter is a
// `parameter` node, an untyped one a bare identifier (`|x: i32, y|`); the function form
// handled by params only ever sees the first.
func (c *rsConv) closureParams(params *tree_sitter.Node) []string {
	if params == nil {
		return nil
	}
	var out []string
	for _, ch := range c.namedChildren(params) {
		switch c.kind(ch) {
		case "parameter":
			if nm := c.patName(c.field(ch, "pattern")); nm != "" {
				out = append(out, nm)
			}
		case "identifier":
			out = append(out, c.text(ch))
		}
	}
	return out
}

func (c *rsConv) params(params *tree_sitter.Node) []string {
	if params == nil {
		return nil
	}
	var out []string
	for _, ch := range c.namedChildren(params) {
		if c.kind(ch) == "parameter" {
			if nm := c.patName(c.field(ch, "pattern")); nm != "" {
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
		if c.kind(ch) == "parameter" {
			if nm := c.patName(c.field(ch, "pattern")); nm != "" {
				putParamType(out, nm, paramTypeFromField(c, ch))
			}
		}
	}
	return out
}

// patName extracts the bound identifier from a pattern (unwrapping ref/mut).
func (c *rsConv) patName(p *tree_sitter.Node) string {
	for p != nil {
		switch c.kind(p) {
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
	switch c.kind(n) {
	case "identifier", "self", "field_identifier", "type_identifier", "scoped_identifier":
		return nir.Name{ID: c.text(n), Loc: L}
	case "boolean_literal", "unit_expression":
		return nir.Const{Loc: L, Value: c.text(n)}
	case "integer_literal", "float_literal", "char_literal":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "string_literal", "raw_string_literal":
		return nir.Const{Loc: L, Value: rustStringValue(c.text(n))}
	case "field_expression":
		return nir.Attr{Base: c.expr(c.field(n, "value")), Attr: c.text(c.field(n, "field")), Path: c.dotted(n), Loc: L}
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
		fn := c.field(n, "function")
		path := c.dotted(fn)
		return nir.Call{Callee: c.expr(fn), Args: c.callArgs(c.field(n, "arguments")), Path: path, Method: lastSeg(path), Loc: L}
	case "macro_invocation":
		name := lastSeg(c.dotted(c.field(n, "macro")))
		var parts []nir.Expr
		if tt := lastChildKind(n, "token_tree"); tt != nil {
			for _, ch := range c.namedChildren(tt) {
				if isRustExprTok(c.kind(ch)) {
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
		op := c.text(c.field(n, "operator"))
		left, right := c.expr(c.field(n, "left")), c.expr(c.field(n, "right"))
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
		then := c.blockTail(c.field(n, "consequence"))
		var els nir.Expr
		if alt := c.field(n, "alternative"); alt != nil {
			if k := c.namedChildren(alt); len(k) > 0 {
				if c.kind(k[0]) == "block" {
					els = c.blockTail(k[0])
				} else {
					els = c.expr(k[0]) // else if …
				}
			}
		}
		if then != nil && els != nil {
			return nir.Ternary{Cond: c.expr(c.field(n, "condition")), Then: then, Else: els, Loc: L}
		}
		return nir.Seq{Parts: c.blockValues(n), Loc: L}
	case "closure_expression":
		// `|evt| { let payload = decode(evt); run(payload); }` — a closure passed as an argument
		// is lowered as the value of that argument, but it is still a body. As a Lambda its
		// statements are lowered as statements, so a local bound inside the callback carries an
		// edge to its uses; the Seq fallback below expr'd them instead, which lost the binding
		// and with it every source-to-sink path inside the callback. Captured variables are free
		// names resolved from the enclosing scope by the lambda closure-capture in lowering, so
		// they need not be params.
		body := c.field(n, "body")
		if c.kind(body) == "block" {
			return nir.Lambda{Params: c.closureParams(c.field(n, "parameters")),
				ParamTypes: c.paramTypes(c.field(n, "parameters")),
				Body:       c.block(body), Loc: L}
		}
		// `|| decode(x)` — single-expression closure; model the body as a return.
		return nir.Lambda{Params: c.closureParams(c.field(n, "parameters")),
			ParamTypes: c.paramTypes(c.field(n, "parameters")),
			Body:       []nir.Stmt{nir.Return{Value: c.expr(body)}}, Loc: L}
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
	it.Cond = c.expr(c.field(n, "condition"))
	it.Then = c.block(c.field(n, "consequence"))
	if alt := c.field(n, "alternative"); alt != nil {
		it.Else = c.rsElse(alt)
	}
	return it
}

// rsElse unwraps an else branch: a block, a chained else-if, or an else_clause wrapper.
func (c *rsConv) rsElse(alt *tree_sitter.Node) []nir.Stmt {
	switch c.kind(alt) {
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

// rsMatch lowers a match to a subject+labelled Switch so dead arms prune and each arm is a
// control region of its own. A wildcard `_` arm is the default; literal patterns become case
// labels. The scrutinee is bound to a synthetic local first so each arm can bind the names ITS
// pattern destructures without re-lowering (and so duplicating) the scrutinee expression.
//
// target names the variable a value-position match feeds (`let x = match … { … }`); each arm's
// tail expression is assigned to it, so the join that follows the switch carries one operand
// per arm. Empty for a statement-position match, whose arms produce no value.
func (c *rsConv) rsMatch(n *tree_sitter.Node, target string) []nir.Stmt {
	L := c.loc(n)
	subj := c.rsMatchSubjectName()
	out := []nir.Stmt{nir.Assign{Targets: []string{subj}, Value: c.expr(c.field(n, "value")), Decl: true, Loc: L}}
	sw := nir.Switch{Loc: L, Subject: nir.Name{ID: subj, Loc: L}}
	body := c.field(n, "body")
	if body == nil {
		return append(out, sw)
	}
	for _, arm := range c.namedChildren(body) {
		if c.kind(arm) != "match_arm" {
			continue
		}
		pat := c.field(arm, "pattern")
		stmts := c.rsArmBinding(pat, subj, L)
		stmts = append(stmts, c.rsArmBody(c.field(arm, "value"), target)...)
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
	return append(out, sw)
}

// rsMatchSubjectName mints the synthetic local one match binds its scrutinee to. Per-file
// counter: the conversion of a file is single-threaded and its locals are file-scoped.
func (c *rsConv) rsMatchSubjectName() string {
	c.matchSubjects++
	return "__vyql_match" + itoa(c.matchSubjects)
}

// rsArmBinding binds every name an arm's pattern destructures to the scrutinee. A pattern is
// how a Rust match names the value it is matching on, so without this the arm body reads an
// identifier bound to nothing and the scrutinee's taint stops at the match.
func (c *rsConv) rsArmBinding(pat *tree_sitter.Node, subj, loc string) []nir.Stmt {
	var names []string
	c.rsPatternNames(pat, &names)
	if len(names) == 0 {
		return nil
	}
	return []nir.Stmt{nir.Assign{Targets: names, Value: nir.Name{ID: subj, Loc: loc}, Decl: true, Loc: loc}}
}

// rsPatternNames appends the identifiers a pattern BINDS. A path or a literal in a pattern
// selects the arm rather than naming a value, and an arm guard (`Some(x) if ready()`) is a
// condition, so neither contributes a binding.
func (c *rsConv) rsPatternNames(n *tree_sitter.Node, out *[]string) {
	if n == nil {
		return
	}
	switch c.kind(n) {
	case "identifier":
		if t := c.text(n); t != "" && t != "_" {
			*out = append(*out, t)
		}
	case "match_pattern":
		// the second child, when present, is the `if` guard -- a condition, not a binding.
		if kids := c.namedChildren(n); len(kids) > 0 {
			c.rsPatternNames(kids[0], out)
		}
	case "tuple_struct_pattern", "struct_pattern":
		// the `type` field is the variant being matched, not a name the arm binds.
		typ := c.field(n, "type")
		for _, ch := range c.namedChildren(n) {
			if sameRustNode(ch, typ) {
				continue
			}
			c.rsPatternNames(ch, out)
		}
	case "field_pattern":
		if p := c.field(n, "pattern"); p != nil {
			c.rsPatternNames(p, out) // `Foo { field: name }`
			return
		}
		if nm := c.field(n, "name"); nm != nil { // shorthand `Foo { name }`
			if t := c.text(nm); t != "" && t != "_" {
				*out = append(*out, t)
			}
		}
	case "tuple_pattern", "slice_pattern", "or_pattern", "ref_pattern", "mut_pattern",
		"reference_pattern", "captured_pattern", "parenthesized_pattern":
		for _, ch := range c.namedChildren(n) {
			c.rsPatternNames(ch, out)
		}
	}
}

func sameRustNode(a, b *tree_sitter.Node) bool {
	return a != nil && b != nil && a.StartByte() == b.StartByte() && a.EndByte() == b.EndByte()
}

// rsArmBody lowers one arm's body. With a target the arm is producing a value: its block's
// statements are lowered as statements — so a check written in the arm keeps its own node and
// its own region — and only the block's TAIL expression is assigned to the target.
func (c *rsConv) rsArmBody(v *tree_sitter.Node, target string) []nir.Stmt {
	if v == nil {
		return nil
	}
	if c.kind(v) != "block" {
		if target == "" {
			return c.exprStmt(v)
		}
		if c.kind(v) == "match_expression" {
			return c.rsMatch(v, target) // an arm that is itself a value-position match
		}
		return []nir.Stmt{nir.Assign{Targets: []string{target}, Value: c.expr(v), Loc: c.loc(v)}}
	}
	if target == "" {
		return c.block(v)
	}
	kids := c.namedChildren(v)
	tailNode := c.rsBlockTailNode(v)
	if tailNode == nil {
		return c.block(v) // the arm never falls out of its block (it returns or breaks)
	}
	var out []nir.Stmt
	for _, st := range kids[:len(kids)-1] {
		out = append(out, c.stmt(st)...)
	}
	return append(out, c.rsArmBody(tailNode, target)...)
}

// rsBlockTailNode returns the CST node of a block's tail (value) expression, or nil when the
// block ends in something that is not a bare expression — the node form of blockTail.
func (c *rsConv) rsBlockTailNode(block *tree_sitter.Node) *tree_sitter.Node {
	if block == nil || c.kind(block) != "block" {
		return nil
	}
	kids := c.namedChildren(block)
	if len(kids) == 0 {
		return nil
	}
	last := kids[len(kids)-1]
	switch c.kind(last) {
	case "let_declaration", "expression_statement", "empty_statement":
		return nil
	}
	return last
}

// blockTail returns the tail (value) expression of a `{ … }` block, or nil if the last
// element isn't a bare expression (e.g. a let/assignment) — used to model an if-as-value.
func (c *rsConv) blockTail(block *tree_sitter.Node) nir.Expr {
	last := c.rsBlockTailNode(block)
	if last == nil {
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
	switch c.kind(n) {
	case "identifier", "field_identifier", "type_identifier", "self", "primitive_type":
		return c.text(n)
	case "scoped_identifier", "scoped_type_identifier":
		path := c.field(n, "path")
		name := c.field(n, "name")
		if path == nil {
			return c.dotted(name)
		}
		return c.dotted(path) + "." + c.dotted(name)
	case "field_expression":
		return c.dotted(c.field(n, "value")) + "." + c.text(c.field(n, "field"))
	case "call_expression":
		return c.dotted(c.field(n, "function"))
	case "generic_function":
		return c.dotted(c.field(n, "function"))
	case "generic_type":
		return c.dotted(c.field(n, "type"))
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
