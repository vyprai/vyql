package parser

// The definition language resolves two kinds of fact that a second lowering pass needs but
// cannot re-derive on its own: what a written name refers to once module aliases are
// applied, and what the corpus declared about concepts and coverage modes.
//
// Both are exported because the binding compiler lives outside this package. It owns
// binding semantics; name resolution and the mechanic vocabulary stay here, where the
// language is defined, rather than being re-derived and allowed to drift.

// V2Names resolves a name written inside one module to its qualified form.
type V2Names struct {
	inner v2NameResolver
}

// NewV2Names builds the resolver for one parsed module, applying its own declarations and
// its `use` aliases.
func NewV2Names(prog *V2Program) V2Names { return V2Names{inner: newV2NameResolver(prog)} }

// Concept returns the qualified concept name, or the input unchanged when nothing resolves it.
func (n V2Names) Concept(name string) string { return n.inner.concept(name) }

// V2Context is the corpus-wide mechanic vocabulary: the roles concepts declare and the
// coverage modes in force, merged across every source including those not being lowered.
type V2Context struct {
	inner v2Mechanics
}

// V2ContextFor merges the built-in mechanics with everything the sources declare.
func V2ContextFor(sources []V2Source) V2Context {
	mechanics := v2Mechanics{ruleSolvers: builtinV2RuleSolvers(), coverageModes: builtinV2CoverageModes()}
	for _, src := range sources {
		mechanics.merge(v2MechanicsFromProgram(src.Program))
	}
	return V2Context{inner: mechanics}
}

// ConceptHasRole reports whether the concept declares the given internal role.
func (c V2Context) ConceptHasRole(concept, role string) bool {
	return c.inner.conceptHasRole(concept, role)
}

// HasCoverageMode reports whether the coverage mode is built in or authored.
func (c V2Context) HasCoverageMode(mode string) bool { return c.inner.coverageModes[mode] }
