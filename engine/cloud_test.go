package engine

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

const assetMarkerRule = `
package test;
rule MarkedAsset {
  meta { id: "TEST-ASSET-001", severity: critical }
  match custom.Marker as s
  where s holds_asset_kind [custom.Important]
}
`

func assetMarkerGraph() usg.Store {
	s := usg.NewInMemStore()
	s.AddNode(usg.Node{ID: "alpha.resource", Type: "custom.Resource", Props: map[string]string{"loc": "alpha/export", "flag_a": "shared"}})
	s.AddNode(usg.Node{ID: "beta.resource", Type: "custom.Resource", Props: map[string]string{"loc": "beta/export", "flag_b": "enabled"}})
	s.AddNode(usg.Node{ID: "gamma.resource", Type: "custom.Resource", Props: map[string]string{"loc": "gamma/export", "flag_c": "open"}})
	s.AddNode(usg.Node{ID: "private.resource", Type: "custom.Resource", Props: map[string]string{"loc": "private/internal", "flag_a": "closed"}})
	return s
}

func markerAdapter(name, prop string, acceptedValues ...string) adapters.Adapter {
	accepted := map[string]bool{}
	for _, v := range acceptedValues {
		accepted[v] = true
	}
	return adapters.Adapter{
		Name: name, Technology: strings.SplitN(name, ".", 2)[0], Specificity: 2, Fidelity: "resolved", Origin: "test",
		Apply: func(s usg.Store) []adapters.Mapping {
			ids, _ := s.NodesOfType("custom.Resource")
			var out []adapters.Mapping
			for _, id := range ids {
				n, _, _ := s.GetNode(id)
				if accepted[n.Prop(prop)] {
					out = append(out, adapters.Mapping{NodeID: id, Concept: "custom.Marker",
						Detail: map[string]string{"asset_kinds": "custom.Important"}})
				}
			}
			return out
		},
	}
}

func TestMarkedAssetThreeAdapters(t *testing.T) {
	onto := solverContractOntology()
	decls, err := parser.Parse(assetMarkerRule)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}

	sources := []struct {
		adapter  adapters.Adapter
		provider string
	}{
		{markerAdapter("alpha.adapter", "flag_a", "shared"), "alpha"},
		{markerAdapter("beta.adapter", "flag_b", "enabled"), "beta"},
		{markerAdapter("gamma.adapter", "flag_c", "open"), "gamma"},
	}
	for _, p := range sources {
		g := assetMarkerGraph()
		if _, _, err := adapters.Apply(g, []adapters.Adapter{p.adapter}, nil); err != nil {
			t.Fatal(err)
		}
		fs, err := New(onto, g).Evaluate(compiled[0])
		if err != nil {
			t.Fatalf("%s: eval: %v", p.provider, err)
		}
		if len(fs) != 1 {
			t.Fatalf("%s: expected 1 marked asset finding, got %d", p.provider, len(fs))
		}
		if prov := fs[0].Bindings[0].LabelProvenance; !strings.Contains(prov, p.provider) {
			t.Fatalf("%s: finding provenance should cite the adapter, got %q", p.provider, prov)
		}
	}
}
