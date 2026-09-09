package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsphp "github.com/tree-sitter/tree-sitter-php/bindings/go"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// A Blade template is a `.blade.php` file, and tree-sitter-php reads everything
// outside `<?php … ?>` as inert text. A view is almost entirely such text, so its
// expressions — which Blade writes inside echo tags rather than PHP tags — reach
// the graph as nothing at all: the file lowers to its module-context marker and no
// call. phpBladeEchoStmts recovers them, by re-parsing the expression inside each
// echo tag as PHP and lowering it as an expression statement.
//
// The statements are the expressions only, not echoes: `{{ … }}` is the escaping
// form (Blade runs it through htmlspecialchars), so modelling it as an output sink
// would report every view in a Laravel application as unescaped output. What the
// expression itself does — which helper it calls, with which arguments — is what
// this makes visible.
func (c *phConv) phpBladeEchoStmts() []nir.Stmt {
	if !isBladeTemplate(c.file) {
		return nil
	}
	exprs, lines := bladeEchoExprs(string(c.src))
	if len(exprs) == 0 {
		return nil
	}
	// One synthetic source, one expression per line, so a single parse covers the
	// file and each statement's row indexes the map back onto its tag's line.
	var b strings.Builder
	b.WriteString("<?php\n")
	lineMap := make([]int, 0, len(exprs)+1)
	lineMap = append(lineMap, 0) // row 0 is the opening tag
	for i, e := range exprs {
		b.WriteString(e)
		b.WriteString(";\n")
		lineMap = append(lineMap, lines[i])
	}
	src := []byte(b.String())
	p := tree_sitter.NewParser()
	defer p.Close()
	if err := p.SetLanguage(tree_sitter.NewLanguage(tsphp.LanguagePHP())); err != nil {
		return nil
	}
	tree := p.Parse(src, nil)
	if tree == nil {
		return nil
	}
	defer tree.Close()
	sub := &phConv{src: src, root: c.root, file: c.file, lineMap: lineMap}
	var out []nir.Stmt
	for _, st := range sub.namedChildren(tree.RootNode()) {
		// A tag whose contents are not PHP — a client-side template's own
		// interpolation, a Blade directive spliced into one — parses to an error
		// node. Drop it rather than lowering a guess at what it meant.
		if st.HasError() || sub.kind(st) == "ERROR" {
			continue
		}
		out = append(out, sub.stmt(st)...)
	}
	return out
}

// isBladeTemplate reports whether a path names a Blade view. The extension is the
// whole of Laravel's convention for one: the view resolver finds `x.blade.php` for
// the view named `x`, and only that suffix makes the file a template.
func isBladeTemplate(file string) bool {
	return strings.HasSuffix(strings.ToLower(file), ".blade.php")
}

// bladeEchoExprs returns the expression source inside each of a Blade template's
// echo tags — `{{ … }}` (escaped), `{{{ … }}}` (the pre-5.0 escaped spelling) and
// `{!! … !!}` (raw) — paired with the 1-based line the tag opens on. Comments
// (`{{-- … --}}`) hold no expression, and a tag written `@{{ … }}` is emitted
// verbatim for a client-side engine rather than evaluated, so neither is returned.
// A tag spanning lines is folded onto one, and attributed to the line it opens on.
func bladeEchoExprs(s string) ([]string, []int) {
	var exprs []string
	var lines []int
	line, i := 1, 0
	advance := func(to int) {
		line += strings.Count(s[i:to], "\n")
		i = to
	}
	for i < len(s) {
		if s[i] != '{' {
			if s[i] == '\n' {
				line++
			}
			i++
			continue
		}
		if i > 0 && s[i-1] == '@' {
			i++
			continue
		}
		if strings.HasPrefix(s[i:], "{{--") {
			end := strings.Index(s[i+4:], "--}}")
			if end < 0 {
				advance(len(s))
				continue
			}
			advance(i + 4 + end + 4)
			continue
		}
		open, closer := 0, ""
		switch {
		case strings.HasPrefix(s[i:], "{!!"):
			open, closer = 3, "!!}"
		case strings.HasPrefix(s[i:], "{{{"):
			open, closer = 3, "}}}"
		case strings.HasPrefix(s[i:], "{{"):
			open, closer = 2, "}}"
		default:
			i++
			continue
		}
		end := strings.Index(s[i+open:], closer)
		if end < 0 {
			i++
			continue
		}
		if expr := bladeFlatten(s[i+open : i+open+end]); expr != "" {
			exprs = append(exprs, expr)
			lines = append(lines, line)
		}
		advance(i + open + end + len(closer))
	}
	return exprs, lines
}

// bladeFlatten folds a tag's contents onto a single line, so the synthetic source's
// row-to-line map stays one row per tag.
func bladeFlatten(expr string) string {
	expr = strings.NewReplacer("\r", " ", "\n", " ").Replace(expr)
	return strings.TrimSpace(expr)
}
