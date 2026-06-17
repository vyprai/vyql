package engine

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

func TestReachWithAssetFilter(t *testing.T) {
	src := `
package test;
rule ReachAsset {
  meta { id: "TEST-REACH", severity: critical }
  reach custom.Edge -> custom.Asset
  where custom.Asset holds_asset_kind [custom.Important]
}
`
	onto := solverContractOntology()
	decls, _ := parser.Parse(src)
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	s := usg.NewInMemStore()
	s.AddNode(usg.Node{ID: "edge", Type: "custom.Edge", Props: map[string]string{"loc": "edge"}})
	s.AddLabel("edge", usg.Label{Concept: "custom.Edge"})
	s.AddNode(usg.Node{ID: "hop1", Type: "custom.Hop"})
	s.AddNode(usg.Node{ID: "hop2", Type: "custom.Hop"})
	s.AddNode(usg.Node{ID: "asset", Type: "custom.Asset", Props: map[string]string{"loc": "asset"}})
	s.AddLabel("asset", usg.Label{Concept: "custom.Asset", Detail: map[string]string{"asset_kinds": "custom.Important"}})
	s.AddEdge(usg.Edge{Type: "NET", Src: "edge", Dst: "hop1", Props: map[string]string{"rule": "edge-hop"}})
	s.AddEdge(usg.Edge{Type: "NET", Src: "hop1", Dst: "hop2", Props: map[string]string{"rule": "middle-hop"}})
	s.AddEdge(usg.Edge{Type: "NET", Src: "hop2", Dst: "asset", Props: map[string]string{"rule": "asset-hop"}})

	eng := New(onto, s)
	fs, _ := eng.Evaluate(compiled[0])
	if len(fs) != 1 {
		t.Fatalf("expected 1 reach finding, got %d", len(fs))
	}
	named := false
	for _, w := range fs[0].Witness {
		if strings.Contains(w, "asset-hop") {
			named = true
		}
	}
	if !named {
		t.Fatalf("witness should name the final edge rule: %v", fs[0].Witness)
	}
}

func TestAssumeEscalation(t *testing.T) {
	src := `
package test;
rule ActorToCapability {
  meta { id: "TEST-ASSUME", severity: critical }
  assume custom.Actor -> custom.Capability
}
`
	onto := solverContractOntology()
	decls, _ := parser.Parse(src)
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	s := usg.NewInMemStore()
	s.AddNode(usg.Node{ID: "actor", Type: "custom.Actor", Props: map[string]string{"loc": "actor"}})
	s.AddLabel("actor", usg.Label{Concept: "custom.Actor"})
	s.AddNode(usg.Node{ID: "step1", Type: "custom.Step"})
	s.AddNode(usg.Node{ID: "step2", Type: "custom.Step", Props: map[string]string{"priv_level": "WRITE"}})
	s.AddNode(usg.Node{ID: "capability", Type: "custom.Capability", Props: map[string]string{"priv_level": "ADMIN"}})
	s.AddLabel("capability", usg.Label{Concept: "custom.Capability"})
	s.AddEdge(usg.Edge{Type: "STEP", Src: "actor", Dst: "step1", Props: map[string]string{"ability": "first"}})
	s.AddEdge(usg.Edge{Type: "STEP", Src: "step1", Dst: "step2", Props: map[string]string{"ability": "second"}})
	s.AddEdge(usg.Edge{Type: "STEP", Src: "step2", Dst: "capability", Props: map[string]string{"ability": "third"}})

	eng := New(onto, s)
	fs, _ := eng.Evaluate(compiled[0])
	if len(fs) != 1 {
		t.Fatalf("expected 1 escalation finding, got %d", len(fs))
	}
	if len(fs[0].Witness) != 3 {
		t.Fatalf("expected a 3-step ability chain, got %v", fs[0].Witness)
	}
	if !strings.Contains(fs[0].Witness[0], "first") {
		t.Fatalf("witness first step wrong: %v", fs[0].Witness)
	}
}

func TestAssumeMinLevelComesFromOntology(t *testing.T) {
	src := `
module custom;
concept External : principal { }
concept Elevated : privilege {
  assume_min_level: ADMIN
}
rule ExternalToElevated {
  assume custom.External -> custom.Elevated
}
`
	onto := ontology.New()
	cs, err := ontology.LoadConceptText(src)
	if err != nil {
		t.Fatalf("load concepts: %v", err)
	}
	for _, c := range cs {
		onto.Add(c)
	}
	decls, _ := parser.Parse(src)
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	s := usg.NewInMemStore()
	s.AddNode(usg.Node{ID: "ext", Type: "custom.Principal"})
	s.AddLabel("ext", usg.Label{Concept: "custom.External"})
	s.AddNode(usg.Node{ID: "role", Type: "custom.Role", Props: map[string]string{"priv_level": "ADMIN"}})
	s.AddEdge(usg.Edge{Type: "STEP", Src: "ext", Dst: "role", Props: map[string]string{"ability": "assume"}})

	fs, err := New(onto, s).Evaluate(compiled[0])
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("expected data-driven min-level assume finding, got %d", len(fs))
	}
}
