package main

import (
	"testing"

	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/usg"
)

func TestDebugConceptClassificationUsesPassedOntology(t *testing.T) {
	onto := ontology.New()
	onto.Add(ontology.Concept{Name: "Input", Package: "customdebug", Kind: "source"})
	onto.Add(ontology.Concept{Name: "Target", Package: "customdebug", Kind: "sink"})

	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "in", Type: "code.X"})
	store.AddNode(usg.Node{ID: "out", Type: "code.X"})
	store.AddLabel("in", usg.Label{Concept: "customdebug.Input"})
	store.AddLabel("out", usg.Label{Concept: "customdebug.Target"})

	if !isSourceConcept(onto, "customdebug.Input") {
		t.Fatal("source concept should be classified from the passed ontology")
	}
	if !isSource(onto, store, "in") {
		t.Fatal("source node should be classified from the passed ontology")
	}
	if !isSink(onto, store, "out") {
		t.Fatal("sink node should be classified from the passed ontology")
	}
}
