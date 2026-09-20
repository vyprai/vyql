package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/nir"
)

// krayinVueComponent is krayin/laravel-crm's datagrid table-body component
// (CVE-2021-41924), script and template as the repository ships them: every
// cell rendered through the v-html directive, whose value getRowContent
// returns unchanged.
const krayinVueComponent = `<template>
    <tbody>
        <tr v-for="(row, collectionIndex) in dataCollection">
            <td
                v-if="column.type != 'hidden'"
                v-html="getRowContent(row[column.index])"
                :title="column.title ? row[column.index] : ''"
            ></td>
        </tr>
    </tbody>
</template>

<script>
    export default {
        methods: {
            getRowContent: function (content) {
                return content || (content === 0 ? content : '--')
            },
        }
    }
</script>
`

func writeVueComponent(t *testing.T, name, src string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// vueCreateElementCall returns the first expression statement in the program
// whose value is a createElement call, with its argument shape.
func vueCreateElementCall(prog nir.Program) (nir.Call, bool) {
	for _, mod := range prog.Modules {
		for _, st := range mod.Body {
			s, ok := st.(nir.ExprStmt)
			if !ok {
				continue
			}
			if c, ok := s.Value.(nir.Call); ok && c.Path == "createElement" {
				return c, true
			}
		}
	}
	return nir.Call{}, false
}

// A v-html directive is the markup write of the element it sits on: Vue's own
// compiler lowers it to the data object of a createElement call carrying the
// bound expression under domProps.innerHTML, so that is the shape the frontend
// must produce for a binding to anchor a sink on it.
func TestVueTemplateVHTMLLowersToCompiledRenderShape(t *testing.T) {
	path := writeVueComponent(t, "table-body.vue", krayinVueComponent)

	prog, err := treesitter.ExtractJavaScript([]string{path}, filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	call, ok := vueCreateElementCall(prog)
	if !ok {
		t.Fatalf("v-html directive did not lower to a createElement call; program=%#v", prog)
	}
	if call.Method != "createElement" {
		t.Fatalf("compiled directive call method = %q, want createElement", call.Method)
	}
	if len(call.Args) != 2 {
		t.Fatalf("compiled directive call has %d args, want tag and data object: %#v", len(call.Args), call.Args)
	}
	tag, ok := call.Args[0].(nir.Const)
	if !ok || tag.Value != "'td'" {
		t.Fatalf("compiled directive tag arg = %#v, want the directive's own element td", call.Args[0])
	}
	data, ok := call.Args[1].(nir.Seq)
	if !ok || len(data.Parts) != 1 {
		t.Fatalf("compiled directive data object = %#v, want one domProps pair", call.Args[1])
	}
	domProps, ok := data.Parts[0].(nir.Pair)
	if !ok || domProps.Key != "domProps" {
		t.Fatalf("compiled directive data pair = %#v, want key domProps", data.Parts[0])
	}
	inner, ok := domProps.Value.(nir.Seq)
	if !ok || len(inner.Parts) != 1 {
		t.Fatalf("domProps value = %#v, want one innerHTML pair", domProps.Value)
	}
	innerHTML, ok := inner.Parts[0].(nir.Pair)
	if !ok || innerHTML.Key != "innerHTML" {
		t.Fatalf("domProps pair = %#v, want key innerHTML", inner.Parts[0])
	}
	bound, ok := innerHTML.Value.(nir.Call)
	if !ok || bound.Path != "getRowContent" {
		t.Fatalf("innerHTML value = %#v, want the directive's bound expression getRowContent(...)", innerHTML.Value)
	}
	// The sink's location is the directive's own line — the line the fix edits.
	if want := "table-body.vue:6"; call.Loc != want {
		t.Fatalf("compiled directive call loc = %q, want %q", call.Loc, want)
	}
}

// The script block keeps its own lowering: the directive reaching the graph
// must not come at the cost of the methods beside it.
func TestVueTemplateVHTMLKeepsTheScriptBlock(t *testing.T) {
	path := writeVueComponent(t, "table-body.vue", krayinVueComponent)

	prog, err := treesitter.ExtractJavaScript([]string{path}, filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	fn, ok := findFuncDef(prog, "getRowContent")
	if !ok {
		t.Fatalf("script block method getRowContent was not extracted; program=%#v", prog)
	}
	if !funcBodyHasReturn(fn.Body) {
		t.Fatalf("getRowContent body was not lowered; body=%#v", fn.Body)
	}
}

func funcBodyHasReturn(stmts []nir.Stmt) bool {
	for _, st := range stmts {
		if _, ok := st.(nir.Return); ok {
			return true
		}
	}
	return false
}

// The fix's own form stays dark: v-text writes a text node, and nothing in the
// frontend lowers it, so no markup sink can anchor on a patched component.
func TestVueTemplateVTextLowersNothing(t *testing.T) {
	src := `<template>
    <td v-text="getRowContent(row[column.index])"></td>
</template>
<script>
    export default {
        methods: {
            getRowContent: function (content) { return content }
        }
    }
</script>
`
	path := writeVueComponent(t, "table-body.vue", src)

	prog, err := treesitter.ExtractJavaScript([]string{path}, filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := vueCreateElementCall(prog); ok {
		t.Fatalf("v-text directive lowered to a createElement call; program=%#v", prog)
	}
}

// A component whose markup is all it has — no script block — still yields the
// directive: the template alone is analyzable source for the write it makes.
func TestVueTemplateOnlyComponentLowersTheDirective(t *testing.T) {
	src := `<template>
    <td v-html="format(row.content)"></td>
</template>
`
	path := writeVueComponent(t, "cell.vue", src)

	prog, err := treesitter.ExtractJavaScript([]string{path}, filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	call, ok := vueCreateElementCall(prog)
	if !ok {
		t.Fatalf("template-only .vue yielded no directive call; program=%#v", prog)
	}
	if want := "cell.vue:2"; call.Loc != want {
		t.Fatalf("template-only directive loc = %q, want %q", call.Loc, want)
	}
}

// A commented-out element is markup the component does not render, and a
// directive quoted inside another attribute's value is text, not a directive.
func TestVueTemplateSkipsCommentedAndQuotedDirectives(t *testing.T) {
	src := `<template>
    <div title="v-html='evil()'">
        <!-- <td v-html="evil()"></td> -->
        <td v-html="keep()"></td>
    </div>
</template>
<script>
    export default {}
</script>
`
	path := writeVueComponent(t, "cell.vue", src)

	prog, err := treesitter.ExtractJavaScript([]string{path}, filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	var bound []string
	for _, mod := range prog.Modules {
		for _, st := range mod.Body {
			s, ok := st.(nir.ExprStmt)
			if !ok {
				continue
			}
			c, ok := s.Value.(nir.Call)
			if !ok || c.Path != "createElement" {
				continue
			}
			if data, ok := c.Args[1].(nir.Seq); ok {
				if dp, ok := data.Parts[0].(nir.Pair); ok {
					if ih, ok := dp.Value.(nir.Seq); ok {
						if p, ok := ih.Parts[0].(nir.Pair); ok {
							if b, ok := p.Value.(nir.Call); ok {
								bound = append(bound, b.Path)
							}
						}
					}
				}
			}
		}
	}
	if len(bound) != 1 || bound[0] != "keep" {
		t.Fatalf("directives lowered = %v, want only the live keep() one", bound)
	}
}

// vueDirectiveBounds returns every lowered directive as its bound callee and
// the line the directive sits on.
func vueDirectiveBounds(prog nir.Program) []vueDirectiveBound {
	var out []vueDirectiveBound
	for _, mod := range prog.Modules {
		for _, st := range mod.Body {
			s, ok := st.(nir.ExprStmt)
			if !ok {
				continue
			}
			c, ok := s.Value.(nir.Call)
			if !ok || c.Path != "createElement" {
				continue
			}
			data, ok := c.Args[1].(nir.Seq)
			if !ok || len(data.Parts) != 1 {
				continue
			}
			dp, ok := data.Parts[0].(nir.Pair)
			if !ok || dp.Key != "domProps" {
				continue
			}
			ih, ok := dp.Value.(nir.Seq)
			if !ok || len(ih.Parts) != 1 {
				continue
			}
			p, ok := ih.Parts[0].(nir.Pair)
			if !ok || p.Key != "innerHTML" {
				continue
			}
			if b, ok := p.Value.(nir.Call); ok {
				out = append(out, vueDirectiveBound{callee: b.Path, loc: c.Loc})
			}
		}
	}
	return out
}

type vueDirectiveBound struct {
	callee string
	loc    string
}

// The shapes a real template writes the directive in: a TypeScript component's
// expression, Windows rows, single-quoted attributes, self-closing elements and
// capitalised attribute names all carry the same write, and a bare v-html —
// nothing bound — lowers nothing without taking the valued directives beside it
// down with it.
func TestVueTemplateLowersTheDirectiveInEverySpelling(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []vueDirectiveBound
	}{
		{
			name: "typescript component expression",
			src:  "<template>\n    <td v-html=\"getRowContent(row[column.index] as any)\"></td>\n</template>\n<script lang=\"ts\">\n    export default { methods: { getRowContent: function (c: any) { return c } } }\n</script>\n",
			want: []vueDirectiveBound{{callee: "getRowContent", loc: "c.vue:2"}},
		},
		{
			name: "windows rows",
			src:  "<template>\r\n    <td v-html=\"fmt('x')\"></td>\r\n</template>\r\n",
			want: []vueDirectiveBound{{callee: "fmt", loc: "c.vue:2"}},
		},
		{
			name: "single-quoted attribute",
			src:  "<template>\n    <td v-html='fmt(\"x\")'></td>\n</template>\n",
			want: []vueDirectiveBound{{callee: "fmt", loc: "c.vue:2"}},
		},
		{
			name: "self-closing element",
			src:  "<template>\n    <td v-html=\"one()\" />\n</template>\n",
			want: []vueDirectiveBound{{callee: "one", loc: "c.vue:2"}},
		},
		{
			name: "capitalised attribute",
			src:  "<template>\n    <td V-HTML=\"cap()\"></td>\n</template>\n",
			want: []vueDirectiveBound{{callee: "cap", loc: "c.vue:2"}},
		},
		{
			name: "bare directive beside valued ones",
			src:  "<template>\n    <td v-html></td>\n    <td v-html=\"after()\"></td>\n</template>\n",
			want: []vueDirectiveBound{{callee: "after", loc: "c.vue:3"}},
		},
		{
			name: "three directives on one row",
			src:  "<template>\n    <i v-html=\"p()\"></i><i v-html=\"q()\"></i><i v-html=\"r()\"></i>\n</template>\n",
			want: []vueDirectiveBound{
				{callee: "p", loc: "c.vue:2"},
				{callee: "q", loc: "c.vue:2"},
				{callee: "r", loc: "c.vue:2"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeVueComponent(t, "c.vue", tc.src)

			prog, err := treesitter.ExtractJavaScript([]string{path}, filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			got := vueDirectiveBounds(prog)
			if len(got) != len(tc.want) {
				t.Fatalf("directives lowered = %v, want %v", got, tc.want)
			}
			for i, g := range got {
				if g != tc.want[i] {
					t.Fatalf("directive %d = {%s %s}, want {%s %s}", i, g.callee, g.loc, tc.want[i].callee, tc.want[i].loc)
				}
			}
		})
	}
}

// Two directives on one row are separate statements in the blanked buffer only
// because of the separator the blanking writes between them, and a value that
// spans rows keeps mapping to its own lines.
func TestVueTemplateDirectivesOnOneRowAndAcrossRows(t *testing.T) {
	src := `<template>
    <td v-html="a()"></td><td v-html="b(row[
        0
    ])"></td>
</template>
<script>
    export default {}
</script>
`
	path := writeVueComponent(t, "table-body.vue", src)

	prog, err := treesitter.ExtractJavaScript([]string{path}, filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	var bound []string
	var locs []string
	for _, mod := range prog.Modules {
		for _, st := range mod.Body {
			s, ok := st.(nir.ExprStmt)
			if !ok {
				continue
			}
			c, ok := s.Value.(nir.Call)
			if !ok || c.Path != "createElement" {
				continue
			}
			if data, ok := c.Args[1].(nir.Seq); ok {
				if dp, ok := data.Parts[0].(nir.Pair); ok {
					if ih, ok := dp.Value.(nir.Seq); ok {
						if p, ok := ih.Parts[0].(nir.Pair); ok {
							if b, ok := p.Value.(nir.Call); ok {
								bound = append(bound, b.Path)
								locs = append(locs, c.Loc)
							}
						}
					}
				}
			}
		}
	}
	if len(bound) != 2 || bound[0] != "a" || bound[1] != "b" {
		t.Fatalf("directives lowered = %v, want a() and b() as separate calls", bound)
	}
	if locs[0] != "table-body.vue:2" || locs[1] != "table-body.vue:2" {
		t.Fatalf("directive locs = %v, want both on the row they sit on", locs)
	}
}

// vueForBindings returns every v-for binding a template lowered, as the alias
// it binds, the callee path of the collection it reads, and the line the
// directive sits on.
func vueForBindings(prog nir.Program) []vueForBinding {
	var out []vueForBinding
	for _, mod := range prog.Modules {
		for _, st := range mod.Body {
			a, ok := st.(nir.Assign)
			if !ok || len(a.Targets) != 1 {
				continue
			}
			idx, ok := a.Value.(nir.Index)
			if !ok {
				continue
			}
			out = append(out, vueForBinding{alias: a.Targets[0], path: vueBindingPath(idx.Base), loc: a.Loc})
		}
	}
	return out
}

type vueForBinding struct {
	alias, path, loc string
}

// vueBindingPath names the collection a binding reads: the this-call a bare
// identifier became, or the dotted path of the expression kept as written.
func vueBindingPath(e nir.Expr) string {
	switch b := e.(type) {
	case nir.Call:
		return b.Path
	case nir.Attr:
		return b.Path
	case nir.Name:
		return b.ID
	}
	return "?"
}

// A v-html directive's bound expression reads the aliases of the v-fors it sits
// under, and Vue's own compiler lowers each of those to the binding of its
// alias over an element of the iterated collection. krayin's table-body is the
// shape that matters: two nested v-fors around the directive, both collections
// computed properties, so each alias binds to a this-call's element at the
// v-for's own line — and the bindings come before the directive that reads
// them.
func TestVueTemplateVForBindsTheEnclosingAliases(t *testing.T) {
	src := `<template>
    <tbody>
        <tr v-for="(row, collectionIndex) in dataCollection">
            <template v-for="(column, rowIndex) in columns">
                <td v-html="getRowContent(row[column.index])"></td>
            </template>
        </tr>
    </tbody>
</template>

<script>
    export default {
        computed: {
            columns: function () {
                return this.tableData.columns;
            },

            dataCollection: function () {
                return this.tableData.records.data;
            },
        },

        methods: {
            getRowContent: function (content) {
                return content || (content === 0 ? content : '--')
            },
        }
    }
</script>
`
	path := writeVueComponent(t, "table-body.vue", src)

	prog, err := treesitter.ExtractJavaScript([]string{path}, filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	got := vueForBindings(prog)
	want := []vueForBinding{
		{alias: "row", path: "this.dataCollection", loc: "table-body.vue:3"},
		{alias: "column", path: "this.columns", loc: "table-body.vue:4"},
	}
	if len(got) != len(want) {
		t.Fatalf("v-for bindings = %v, want %v", got, want)
	}
	for i, g := range got {
		if g != want[i] {
			t.Fatalf("binding %d = {%s %s %s}, want {%s %s %s}", i, g.alias, g.path, g.loc, want[i].alias, want[i].path, want[i].loc)
		}
	}
	// The bindings precede the directive's own statement in the module body:
	// the alias is bound before the expression that reads it.
	bindAt := map[string]int{}
	renderAt := -1
	for _, mod := range prog.Modules {
		for si, st := range mod.Body {
			if a, ok := st.(nir.Assign); ok && len(a.Targets) == 1 {
				if _, isIdx := a.Value.(nir.Index); isIdx {
					bindAt[a.Targets[0]] = si
				}
				continue
			}
			if s, ok := st.(nir.ExprStmt); ok {
				if c, ok := s.Value.(nir.Call); ok && c.Path == "createElement" && renderAt < 0 {
					renderAt = si
				}
			}
		}
	}
	for _, alias := range []string{"row", "column"} {
		at, ok := bindAt[alias]
		if !ok {
			t.Fatalf("alias %s has no binding statement", alias)
		}
		if at > renderAt {
			t.Fatalf("binding for %s at body index %d came after the directive statement at %d", alias, at, renderAt)
		}
	}
}

// A v-for nothing is rendered under lowers nothing, and a v-for beside the
// directive — after it on a later sibling element, or around other markup —
// binds no alias the directive could read: only the enclosing chain is scope.
func TestVueTemplateVForOutsideTheDirectiveLowersNothing(t *testing.T) {
	src := `<template>
    <div>
        <p v-html="h(item)"></p>
        <span v-for="item in closedEarly"><i v-text="x(item)"></i></span>
        <ol v-for="later in tainted"><li v-html="g(later)"></li></ol>
    </div>
</template>
<script>
    export default {}
</script>
`
	path := writeVueComponent(t, "c.vue", src)

	prog, err := treesitter.ExtractJavaScript([]string{path}, filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	got := vueForBindings(prog)
	want := []vueForBinding{{alias: "later", path: "this.tainted", loc: "c.vue:5"}}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("v-for bindings = %v, want only the enclosing %v", got, want)
	}

	// A template with no v-html at all lowers nothing, v-fors included: there
	// is no directive whose scope could be needed.
	only := `<template>
    <li v-for="x in xs"></li>
</template>
`
	path = writeVueComponent(t, "only.vue", only)
	prog, err = treesitter.ExtractJavaScript([]string{path}, filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(prog.Modules) != 0 {
		t.Fatalf("template-only .vue with no v-html yielded modules; program=%#v", prog)
	}
}

// An enclosing v-for's alias shadows the component property of the same name:
// the inner collection reads the alias, not this, and the binding keeps the
// expression as written.
func TestVueTemplateVForAliasShadowsTheComponentProperty(t *testing.T) {
	src := `<template>
    <div v-for="row in rows">
        <span v-for="c in row.cols"><i v-html="f(c.x)"></i></span>
    </div>
</template>
<script>
    export default {}
</script>
`
	path := writeVueComponent(t, "c.vue", src)

	prog, err := treesitter.ExtractJavaScript([]string{path}, filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	got := vueForBindings(prog)
	want := []vueForBinding{
		{alias: "row", path: "this.rows", loc: "c.vue:2"},
		{alias: "c", path: "row.cols", loc: "c.vue:3"},
	}
	if len(got) != len(want) {
		t.Fatalf("v-for bindings = %v, want %v", got, want)
	}
	for i, g := range got {
		if g != want[i] {
			t.Fatalf("binding %d = {%s %s %s}, want {%s %s %s}", i, g.alias, g.path, g.loc, want[i].alias, want[i].path, want[i].loc)
		}
	}
}

// The spellings a template writes a v-for in: the alias alone, the of
// separator, the index beside the value (only the value binds), and a
// destructuring pattern, which has no single name to bind — its directive
// still lowers, its alias stays free.
func TestVueTemplateVForSpellings(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []vueForBinding
	}{
		{
			name: "alias alone",
			src:  "<template>\n    <li v-for=\"item in items\"><i v-html=\"g(item)\"></i></li>\n</template>\n",
			want: []vueForBinding{{alias: "item", path: "this.items", loc: "c.vue:2"}},
		},
		{
			name: "of separator",
			src:  "<template>\n    <li v-for=\"x of xs\"><i v-html=\"h(x)\"></i></li>\n</template>\n",
			want: []vueForBinding{{alias: "x", path: "this.xs", loc: "c.vue:2"}},
		},
		{
			name: "value with index and key",
			src:  "<template>\n    <li v-for=\"(v, k) in obj\"><i v-html=\"i(v)\"></i></li>\n</template>\n",
			want: []vueForBinding{{alias: "v", path: "this.obj", loc: "c.vue:2"}},
		},
		{
			name: "same element as the directive",
			src:  "<template>\n    <td v-html=\"f(c)\" v-for=\"c in cols\"></td>\n</template>\n",
			want: []vueForBinding{{alias: "c", path: "this.cols", loc: "c.vue:2"}},
		},
		{
			name: "destructuring pattern binds nothing",
			src:  "<template>\n    <li v-for=\"{id} in users\"><i v-html=\"j(id)\"></i></li>\n</template>\n",
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeVueComponent(t, "c.vue", tc.src)

			prog, err := treesitter.ExtractJavaScript([]string{path}, filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			got := vueForBindings(prog)
			if len(got) != len(tc.want) {
				t.Fatalf("v-for bindings = %v, want %v", got, tc.want)
			}
			for i, g := range got {
				if g != tc.want[i] {
					t.Fatalf("binding %d = {%s %s %s}, want {%s %s %s}", i, g.alias, g.path, g.loc, tc.want[i].alias, tc.want[i].path, tc.want[i].loc)
				}
			}
			// The directive inside lowers whatever the alias situation: the
			// v-for is scope, not a gate.
			if _, ok := vueCreateElementCall(prog); !ok {
				t.Fatalf("directive inside the v-for did not lower; program=%#v", prog)
			}
		})
	}
}
