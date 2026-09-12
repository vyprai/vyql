package frontend

import (
	"github.com/vyprai/vyql/internal/bindings"
	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
)

// Loading the declared call flows lives here, not in the frontend that consumes them,
// for the same reason the source-variable profiles do (sourcevars.go): which of a
// callee's arguments is an out-parameter is binding-layer content, and reading it in
// the frontend would pull the corpus into a package that should hold only the
// language.
//
// It installs itself, because the flows are consulted DURING extraction while
// BindingsFor runs after it. The load is still lazy: registration only hands over a
// closure, and a technology's flows are read on the first call that asks for them.

func init() { treesitter.SetCallEffectLookup(bindings.CallEffectsFor) }
