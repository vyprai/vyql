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
