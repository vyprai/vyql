package treesitter

import "github.com/vyprai/vyql/internal/extract/nir"

// Declared call-flow lookup for the C-family frontends.
//
// Which of a callee's parameters is a pointer the callee fills is binding-layer
// content: `propagate value from args[0] to args[1].pointee` names an API and an
// argument position, not a language construct. So this package holds only the asking
// -- the lookup is injected, exactly as the source-variable one is (sourcevars.go).
// Unset, the frontends attach no declared effect, which is the correct degradation
// for a frontend asked to run without a knowledge base.

var callEffectLookup func(tech, path, method string) []nir.CallEffect

// SetCallEffectLookup installs the resolver. Called by the binding layer at init.
func SetCallEffectLookup(fn func(tech, path, method string) []nir.CallEffect) {
	callEffectLookup = fn
}

// declaredCallEffects reports the out-parameter flows bindings declare for one call.
func declaredCallEffects(tech, path, method string) []nir.CallEffect {
	if callEffectLookup == nil {
		return nil
	}
	return callEffectLookup(tech, path, method)
}
