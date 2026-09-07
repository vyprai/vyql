package lowering

import (
	"strings"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// --- callee aliases -----------------------------------------------------
//
// A call whose callee is a plain identifier resolves through the module's
// import table: `exec(cmd)` after `import { exec } from "node:child_process"`
// carries the callee path "node:child_process.exec", which is what a binding
// naming that library API matches on.
//
// An identifier bound by a declaration instead of an import got no such
// treatment, so the call carried only the local name. Two shapes of that are
// the same call written differently:
//
//	const runIt = exec;                runIt(cmd)
//	const execAsync = promisify(exec); execAsync(cmd)
//
// Both name a library API the scanner already knows; neither reached it. A call
// through such a name now carries the callee path the equivalent direct call
// would have carried, and nothing else about it changes.
//
// The bound value has to land on an import for that to be true, and the reason
// is not caution but ambiguity: object destructuring lowers to exactly this
// shape. `const { StringPrototypeSplit } = primordials` is one Assign of the
// name `primordials`, indistinguishable from an alias of it, so a name bound to
// something the module did not import is left alone.

// calleeAlias is what a module-level declaration bound a name to, when the bound
// value names a callable. path is the initialiser's own callee path ("exec",
// "cp.exec"); wrapper is the path of the call that produced the value
// ("promisify"), empty when the initialiser named the callable directly. site
// identifies the initialiser expression itself, so bindings that share one --
// the several names a destructuring declaration binds -- can be told apart from
// a name bound on its own.
type calleeAlias struct {
	path    string
	wrapper string
	site    string
}

// calleeAliasTable records the module-level declarations that bind a name to a
// callable. Only the module's own top-level statements are read, and a name
// bound more than once there is dropped: this stands in for the `const` idiom --
// one binding, at the top of the file, of the API the rest of the module calls
// through.
func calleeAliasTable(m nir.Module) map[string]calleeAlias {
	var out map[string]calleeAlias
	bound := map[string]bool{}
	sites := map[string]int{}
	for _, s := range m.Body {
		a, ok := s.(nir.Assign)
		if !ok || len(a.Targets) != 1 {
			continue
		}
		name := a.Targets[0]
		if name == "" || strings.ContainsAny(name, ".[") {
			continue
		}
		if bound[name] {
			delete(out, name) // rebound: the name does not stand for one callable
			continue
		}
		bound[name] = true
		if !a.Decl {
			continue
		}
		al, ok := calleeAliasOf(a.Value)
		if !ok {
			continue
		}
		if out == nil {
			out = map[string]calleeAlias{}
		}
		out[name] = al
		sites[al.site]++
	}
	// Several names bound to one initialiser expression are the properties a
	// destructuring declaration picked off it, not that many aliases of it.
	for name, al := range out {
		if sites[al.site] > 1 {
			delete(out, name)
		}
	}
	return out
}

// calleeAliasOf reports the callable an initialiser names, if it names one.
func calleeAliasOf(v nir.Expr) (calleeAlias, bool) {
	for {
		thru, ok := v.(nir.Thru)
		if !ok {
			break
		}
		v = thru.Inner
	}
	switch e := v.(type) {
	case nir.Name:
		if e.ID != "" {
			return calleeAlias{path: e.ID, site: e.ID + "\x00" + e.Loc}, true
		}
	case nir.Attr:
		if e.Path != "" {
			return calleeAlias{path: e.Path, site: e.Path + "\x00" + e.Loc}, true
		}
	case nir.Call:
		// `const execAsync = promisify(exec)` -- a one-argument wrapping call
		// handed a named callable. More than one argument, or an argument that is
		// not itself a callable reference, is a value being computed rather than a
		// callable being wrapped, so it is not an alias.
		if e.Path == "" || len(e.Args) != 1 {
			return calleeAlias{}, false
		}
		inner, ok := calleeAliasOf(e.Args[0])
		if !ok || inner.wrapper != "" {
			return calleeAlias{}, false
		}
		return calleeAlias{path: inner.path, wrapper: e.Path, site: e.Path + "(\x00" + e.Loc}, true
	}
	return calleeAlias{}, false
}

// resolveCalleeAlias returns the callee path a bare identifier stands for when a
// module-level declaration bound it to an imported callable, and whether it
// found one. The result is the path the equivalent direct call would have
// carried, so the caller resolves it through the import table exactly as it
// resolves a callee identifier written out in full.
//
// An import shadows a declaration of the same name and stops the walk: the
// caller already resolves import locals, and the require form records both an
// import and a top-level declaration for the same name.
func (l *lowerer) resolveCalleeAlias(name string) (string, bool) {
	aliases := l.aliasTables[l.curModule]
	if len(aliases) == 0 {
		return "", false
	}
	imports := l.importTables[l.curModule]
	out := ""
	// `const a = exec; const b = a` is a chain; the bound stops a cycle
	// (`const a = b; const b = a`) rather than expressing a real limit.
	for depth := 0; depth < 8; depth++ {
		if _, shadowed := imports[name]; shadowed {
			break
		}
		al, ok := aliases[name]
		if !ok {
			break
		}
		if al.wrapper != "" && !l.forwardsCallable(al.wrapper) {
			break
		}
		out = al.path
		if strings.ContainsRune(out, '.') {
			break // a dotted path: its root resolves as any receiver's does
		}
		name = out
	}
	if out == "" {
		return "", false
	}
	root, dotted := out, strings.ContainsRune(out, '.')
	if dotted {
		root = out[:strings.IndexByte(out, '.')]
	}
	imp, ok := imports[root]
	if !ok {
		return "", false // not an imported API: nothing a binding could name
	}
	if !dotted && imp.kind == "mod" {
		// `const { createHash } = crypto` lowers as a bare binding of `crypto`
		// itself, so reading it as an alias would rename the call from the
		// function to the module it came from.
		return "", false
	}
	return out, true
}

// forwardsCallable reports whether a one-argument wrapping call may be treated
// as returning the callable it was handed. It may when the wrapper has no body
// in the scanned program: a wrapper the scan can see into is the
// interprocedural resolver's question, and a local `makeSafe(exec)` that
// escapes its argument before running it would be reported as a bare `exec` if
// lowering guessed here instead.
func (l *lowerer) forwardsCallable(wrapper string) bool {
	if i := strings.LastIndexByte(wrapper, '.'); i >= 0 {
		wrapper = wrapper[i+1:]
	}
	return len(l.funcShort[wrapper]) == 0
}
