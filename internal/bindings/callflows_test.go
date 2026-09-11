package bindings

import (
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// A propagation a binding declares for a call (`propagate … to args[N].pointee`)
// is not a graph label, so turning the compiled set into the labeling spec must
// record nothing for it. Panic -- the previous reading of the kind -- aborted the
// whole scan on a corpus that declared one.
func TestFlowActionIsNotASpecAndDoesNotAbortTheScan(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.c.native;
binding precisionFromArg {
  query pattern callExpr where callee.path ~= "Jsi_GetIntFromValue"
  propagate taint from args[1] to args[2].pointee
}
`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	spec := specFromBindingSet(firstBindingSetForTest(t, sets))
	if len(spec.Inputs)+len(spec.Sinks)+len(spec.Marks)+len(spec.Controls) != 0 {
		t.Fatalf("a declared call flow became a graph label: %+v", spec)
	}
}

// The compiled action reaches the effect extraction applies to the call: the
// source argument flows into the variable the destination argument names.
func TestDeclaredOutParamFlowResolvesToACallEffect(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.c.native;
binding precisionFromArg {
  query pattern callExpr where callee.path ~= "Jsi_GetIntFromValue"
  propagate taint from args[1] to args[2].pointee
}
`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	specs := callFlowSpecsOf(firstBindingSetForTest(t, sets))
	if len(specs) != 1 {
		t.Fatalf("one declared flow expected, got %v", specs)
	}
	got := matchCallFlowSpecs(specs, "Jsi_GetIntFromValue", "Jsi_GetIntFromValue")
	if len(got) != 1 || got[0] != (nir.CallEffect{DestArg: 2, SourceArg: 1}) {
		t.Fatalf("call at path Jsi_GetIntFromValue resolved %v, want one out-param effect", got)
	}
	if got := matchCallFlowSpecs(specs, "Jsi_OtherCall", "Jsi_OtherCall"); len(got) != 0 {
		t.Fatalf("an unrelated call resolved %v", got)
	}
}

// A binding that names the callee by method carries the same effect, and the
// path spelling still matches a call written through a member access.
func TestDeclaredOutParamFlowMatchesByMethodAndByPath(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.c.native;
binding byMethod {
  query pattern callExpr where callee.method == "decode"
  propagate value from args[0] to args[1].pointee
}
`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	specs := callFlowSpecsOf(firstBindingSetForTest(t, sets))
	if got := matchCallFlowSpecs(specs, "decode", "decode"); len(got) != 1 {
		t.Fatalf("a plain call resolved %v", got)
	}
	if got := matchCallFlowSpecs(specs, "codec.decode", "decode"); len(got) != 1 {
		t.Fatalf("a member call resolved %v", got)
	}
	if got := matchCallFlowSpecs(specs, "decode_more", "decode_more"); len(got) != 0 {
		t.Fatalf("a name only sharing a prefix resolved %v", got)
	}
}
