package lowering

import (
	"strings"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// typeNarrowingName recognizes an instanceof narrowing condition -- `x instanceof T`, a
// BinOp whose Right is a Const carrying the bare checked-type name (the shape the Java
// frontend emits for instanceof_expression). It returns the tested variable and whether
// the condition is negated, in which case the narrowing holds on the ELSE arm.
func typeNarrowingName(cond nir.Expr) (name, typ string, negated bool, ok bool) {
	e := peelThru(cond)
	if u, isU := e.(nir.Unary); isU && u.Op == "!" {
		e = peelThru(u.Operand)
		negated = true
	}
	b, isB := e.(nir.BinOp)
	if !isB || b.Op != "instanceof" {
		return "", "", false, false
	}
	n, isN := b.Left.(nir.Name)
	c, isC := b.Right.(nir.Const)
	if !isN || !isC || c.Value == "" {
		return "", "", false, false
	}
	return n.ID, c.Value, negated, true
}

// classVisibility reports the type-visibility fact for a bare class name, resolved the
// way the reference itself resolves: the current module's own declaration first (a
// package-private type is only nameable from its own package, which is exactly the
// reference an instanceof guard makes), then a declaration unique across the program. A
// name no single module answers for has no fact to attribute, and "unknown" says so
// rather than guessing -- the answer that withholds credit instead of inventing it.
func (l *lowerer) classVisibility(name string) string {
	mod := ""
	if l.classQual[l.curModule+"::"+name] {
		mod = l.curModule
	} else if mods := l.classDefs[name]; len(mods) == 1 {
		for m := range mods {
			mod = m
		}
	}
	if mod == "" {
		return "unknown"
	}
	if l.classExported[mod+"::"+name] {
		return "public"
	}
	return "non_public"
}

// typeNarrowingGuard emits the attribution relation for an instanceof narrowing: an
// analysis.guard.type_narrowing call standing for the value as bounded by the check,
// carrying the checked type and the registry's visibility fact for it as str_args tokens
// (`type=T`, `visibility=public|non_public|unknown`). Bindings decide what the narrowing
// MEANS -- the visibility token is what lets one state "bounded to what the input channel
// cannot construct" without crediting a check on a public, forgeable type. Reads routed
// through the node are typed as the checked type (decl_type), so receiver resolution
// inside the narrowed region keeps working on the value the guard now carries.
func (l *lowerer) typeNarrowingGuard(observed, typ, loc string) string {
	if observed == "" {
		return ""
	}
	if n, ok, _ := l.g.GetNode(observed); ok && loc == "" {
		loc = n.Loc
	}
	if loc == "" {
		loc = "?:0"
	}
	call := l.nodeInline("Call", loc, map[string]string{"decl_type": typ},
		"type_narrowing", "analysis.guard.type_narrowing",
		strings.Join([]string{"type=" + typ, "visibility=" + l.classVisibility(typ)}, "\x00"), "")
	l.flow(observed, call)
	in, _ := l.g.InEdges(observed, "FLOWS")
	for _, ed := range in {
		l.flow(ed.Src, call)
	}
	return call
}
