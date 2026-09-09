package lowering

import (
	"github.com/vyprai/vyql/internal/extract/nir"
)

// --- string-keyed dispatch ----------------------------------------------
//
// Call resolution follows a callee it can name: a direct call, a module or class member, an
// identifier a declaration aliased onto an import. A framework's plugin/preset dispatch names
// nothing of the sort. A plugin registers a function by CONVENTION -- exporting it under an
// agreed name -- and the framework invokes it later through a lookup keyed by a string:
//
//	// the plugin, in its own module
//	export const env = async () => { const { raw } = await loadEnvs(); return raw; };
//
//	// the consumer, in another package
//	const envs = await presets.apply('env');
//	definePlugin(stringifyProcessEnvs(envs));
//
// Between the two sits the registry's own generic body (`preset[extension]` on a module the
// scan loaded by path at run time), so there is no syntactic edge from the dispatch to the
// function it runs: the value the plugin produced reached the consumer through nothing the
// resolver could follow, and a taint path that exists at run time had no route in the graph.
//
// A dispatch is modelled here as what it is -- a call of the registered function. The string
// key is not passed on; the arguments after it are what the hook is invoked with, and what the
// hook returns is the dispatch's result.

// dispatchKeyMethods are the method names a convention-based plugin/preset dispatch is spelled
// with. The list is short on purpose: a method name alone is weak evidence, so it stands beside
// the far stronger requirement that the string key NAME a declaration (dispatchTarget). Read
// together, `presets.apply('env')` in a program that declares exactly one module-level `env` is
// a dispatch; `Function.prototype.apply`, whose first argument is a receiver rather than a
// string, is not.
var dispatchKeyMethods = map[string]bool{
	"apply": true, "applyHook": true, "callHook": true, "invokeHook": true, "runHook": true,
}

// dispatchTarget returns the declaration a string-keyed dispatch invokes, or nil.
//
// Every condition is evidence that the call is a lookup rather than an ordinary method call:
// the callee is a member of some registry object, the first argument is a compile-time string
// shaped like an identifier, and the program declares exactly one module-level function of
// that name. The uniqueness requirement is what keeps the guess honest -- two candidates mean
// the key does not name a function, it merely collides with one -- and a module-level
// declaration is what a plugin export is, so a same-named class method is not a candidate.
func (l *lowerer) dispatchTarget(call nir.Call, sc *scope) *funcInfo {
	if !dispatchKeyMethods[call.Method] || len(call.Args) == 0 {
		return nil
	}
	if _, ok := call.Callee.(nir.Attr); !ok {
		return nil // a bare `apply(...)` is a call of that name, not a lookup on a registry
	}
	key, ok := l.constStrVal(call.Args[0], sc)
	if !ok || !identifierKey(key) {
		return nil
	}
	target, ok := l.uniqueTechFuncInfo(l.funcShort[key])
	if !ok || target.cls != "" || target.abstract || target.ctor {
		return nil
	}
	return target
}

// identifierKey reports whether a string could be the name of a declaration. A key that could
// not be one ('some message', 'a.b/c') names no function whatever funcShort happens to hold.
func identifierKey(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_', c == '$':
		case i > 0 && c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}

// flowDispatchKeyCall adds the edges a string-keyed dispatch stands for: the arguments after
// the key reach the registered function's parameters, and its return reaches the call's result.
//
// The edges are added BESIDE whatever the ordinary resolution of the call produced rather than
// in place of it. What the registry's own `apply` body does with its arguments is a separate
// fact from which hook it ends up running, and a dispatch whose key happens to be ambiguous
// still has to keep the conservative argument->result edges it had before.
func (l *lowerer) flowDispatchKeyCall(call nir.Call, args []string, result string, sc *scope) {
	target := l.dispatchTarget(call, sc)
	if target == nil {
		return
	}
	for i := 1; i < len(args); i++ {
		if i-1 < len(target.paramNames) {
			l.flow(args[i], target.params[target.paramNames[i-1]])
		}
	}
	l.flow(target.ret, result)
}
