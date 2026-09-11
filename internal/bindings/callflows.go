package bindings

import (
	"strings"
	"sync"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// callFlowSpec is one binding-declared call dataflow, resolved to the argument
// positions the lowering re-binds: `propagate value from args[0] to args[1].pointee`
// on a callee means "the variable the caller passed at argument 1 is filled from
// argument 0".
type callFlowSpec struct {
	Pattern string
	Method  bool
	Prefix  bool
	Effect  nir.CallEffect
}

// Flow tables per technology. They are built from the compiled set the label
// applicators already load (loadBindingSet caches per technology), so a technology
// that declares no call flow costs one cache read and no second parse of the corpus.
var callFlowTable sync.Map // tech -> []callFlowSpec

// CallEffectsFor reports the out-parameter flows bindings declare for a call in
// technology tech. Extraction asks it for every call it builds, so the lookup is
// a cache read plus a scan over the -- usually empty -- declared set.
func CallEffectsFor(tech, path, method string) []nir.CallEffect {
	var specs []callFlowSpec
	if cached, ok := callFlowTable.Load(tech); ok {
		specs = cached.([]callFlowSpec)
	} else {
		specs = callFlowSpecsFor(tech)
		loaded, _ := callFlowTable.LoadOrStore(tech, specs)
		specs = loaded.([]callFlowSpec)
	}
	return matchCallFlowSpecs(specs, path, method)
}

// matchCallFlowSpecs reports which of the declared flows a call answers to, by the
// path or the method token the binding named.
func matchCallFlowSpecs(specs []callFlowSpec, path, method string) []nir.CallEffect {
	var out []nir.CallEffect
	for _, spec := range specs {
		if spec.Prefix {
			name := method
			if name == "" {
				name = lastSeg(path)
			}
			if strings.HasPrefix(strings.ToLower(name), strings.ToLower(spec.Pattern)) {
				out = append(out, spec.Effect)
			}
			continue
		}
		if spec.Method {
			if method == spec.Pattern {
				out = append(out, spec.Effect)
			}
			continue
		}
		if path == spec.Pattern || strings.HasSuffix(path, "."+spec.Pattern) {
			out = append(out, spec.Effect)
		}
	}
	return out
}

// callFlowSpecsFor resolves one technology's binding set and keeps its flow
// mappings. A technology whose bindings directory does not exist yet resolves to
// an empty set, which is the correct reading -- nothing in it is labelled yet.
func callFlowSpecsFor(tech string) []callFlowSpec {
	return callFlowSpecsOf(loadBindingSet(tech))
}

// callFlowSpecsOf lifts a compiled set's flow mappings into the effects lowering
// applies.
func callFlowSpecsOf(set *Set) []callFlowSpec {
	var out []callFlowSpec
	for _, mp := range set.Mappings {
		if mp.Kind != "flow_path" && mp.Kind != "flow_method" && mp.Kind != "flow_prefix" {
			continue
		}
		out = append(out, callFlowSpec{
			Pattern: mp.Pattern,
			Method:  mp.Kind == "flow_method",
			Prefix:  mp.Kind == "flow_prefix",
			Effect: nir.CallEffect{
				DestArg:      mp.FlowDestArg,
				SourceArg:    mp.FlowSourceArg,
				SourceResult: mp.FlowSourceResult,
				Identity:     mp.FlowIdentity,
				Receiver:     mp.FlowReceiver,
			},
		})
	}
	return out
}

func lastSeg(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[i+1:]
	}
	return path
}
