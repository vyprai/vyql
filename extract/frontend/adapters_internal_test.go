package frontend

import (
	"testing"

	"github.com/vyprai/vyql/usg"
)

func TestConstraintAllows(t *testing.T) {
	cases := []struct {
		constraint, recvType string
		want                 bool
	}{
		{"alpha.Type", "alpha.Type", true},
		{"Widget", "vendor.pkg.Widget", true},
		{"vendor.pkg.Widget", "Widget", true},
		{"alpha.Type", "beta.Type", false},
		{"alpha.Type,beta.Type,gamma.Type", "gamma.Type", true},
		{"alpha.Type,beta.Type,gamma.Type", "delta.Type", false},
		{"alpha.Type", "", false}, // empty recv handled by the caller, not here
	}
	for _, c := range cases {
		if got := constraintAllows(c.constraint, c.recvType); got != c.want {
			t.Errorf("constraintAllows(%q,%q)=%v want %v", c.constraint, c.recvType, got, c.want)
		}
	}
}

func TestMatchPath(t *testing.T) {
	// prefix mode: exact, dotted, subscript continuations
	if !matchPath("source.value", []string{"source.value"}, "prefix") {
		t.Error("exact prefix should match")
	}
	if !matchPath("source.value.get", []string{"source.value"}, "prefix") {
		t.Error("dotted continuation should match")
	}
	if matchPath("source.valued", []string{"source.value"}, "prefix") {
		t.Error("a longer word should NOT prefix-match (source.valued != source.value.)")
	}
	// contains mode: substring anywhere (Go varying receivers)
	if !matchPath("obj.Meta.Read.Get", []string{".Meta.Read"}, "contains") {
		t.Error("contains should match a mid-path substring")
	}
	if matchPath("obj.Other", []string{".Meta.Read"}, "contains") {
		t.Error("contains should not falsely match an unrelated path")
	}
}

func TestPackageGatedSinkRequiresPackageEvidence(t *testing.T) {
	spec := adapterSpec{
		Name:       "neutral",
		Technology: "neutral",
		Sinks: []sinkSpec{{
			Concept:  "custom.Target",
			Pattern:  "samplepkg.handle",
			Packages: []string{"samplepkg"},
		}},
	}
	adapter := spec.sinkAdapter()

	withoutPkg := usg.NewInMemStore()
	withoutPkg.AddNode(usg.Node{ID: "arg", Type: "code.Arg", Props: map[string]string{"loc": "sample.x:3"}})
	withoutPkg.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:3", "callee_path": "samplepkg.handle", "method": "handle", "arg0": "arg",
	}})
	if got := adapter.Apply(withoutPkg); len(got) != 0 {
		t.Fatalf("package-gated sink fired without evidence: %+v", got)
	}

	withImport := usg.NewInMemStore()
	withImport.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "sample.x:1", "module": "samplepkg", "package": "samplepkg",
	}})
	withImport.AddNode(usg.Node{ID: "arg", Type: "code.Arg", Props: map[string]string{"loc": "sample.x:3"}})
	withImport.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:3", "callee_path": "samplepkg.handle", "method": "handle", "arg0": "arg",
	}})
	if got := adapter.Apply(withImport); len(got) != 1 || got[0].NodeID != "arg" || got[0].Concept != "custom.Target" {
		t.Fatalf("package-gated sink did not fire with import evidence: %+v", got)
	}

	withSBOM := usg.NewInMemStore()
	withSBOM.AddNode(usg.Node{ID: "pkg:generic/samplepkg@1.0", Type: "sbom.PackageVersion", Props: map[string]string{
		"name": "samplepkg", "version": "1.0",
	}})
	withSBOM.AddNode(usg.Node{ID: "arg", Type: "code.Arg", Props: map[string]string{"loc": "sample.x:3"}})
	withSBOM.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:3", "callee_path": "samplepkg.handle", "method": "handle", "arg0": "arg",
	}})
	if got := adapter.Apply(withSBOM); len(got) != 1 || got[0].NodeID != "arg" {
		t.Fatalf("package-gated sink did not fire with SBOM evidence: %+v", got)
	}
}

func TestPackageGatedSourceRequiresPackageEvidence(t *testing.T) {
	spec := adapterSpec{
		Name:       "neutral",
		Technology: "neutral",
		Inputs: []inputSpec{{
			Concept:  "custom.Source",
			Paths:    []string{"samplepkg.source.value"},
			Match:    "prefix",
			Packages: []string{"samplepkg"},
		}},
	}
	adapter := spec.inputAdapter()

	withoutPkg := usg.NewInMemStore()
	withoutPkg.AddNode(usg.Node{ID: "src", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "samplepkg.source.value", "method": "value",
	}})
	if got := adapter.Apply(withoutPkg); len(got) != 0 {
		t.Fatalf("package-gated source fired without evidence: %+v", got)
	}

	withPkg := usg.NewInMemStore()
	withPkg.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "sample.x:1", "module": "samplepkg", "package": "samplepkg",
	}})
	withPkg.AddNode(usg.Node{ID: "src", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "samplepkg.source.value", "method": "value",
	}})
	if got := adapter.Apply(withPkg); len(got) != 1 || got[0].NodeID != "src" || got[0].Concept != "custom.Source" {
		t.Fatalf("package-gated source did not fire with package evidence: %+v", got)
	}
}

func TestPackageGatedReceiverSourceUsesResolvedType(t *testing.T) {
	spec := adapterSpec{
		Name:       "neutral",
		Technology: "neutral",
		Inputs: []inputSpec{{
			Concept:    "custom.Source",
			Methods:    []string{"value"},
			Receiver:   true,
			Constraint: "samplepkg.Request",
			Packages:   []string{"samplepkg"},
		}},
	}
	adapter := spec.inputAdapter()

	withWrongReceiver := usg.NewInMemStore()
	withWrongReceiver.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "sample.x:1", "module": "samplepkg", "package": "samplepkg",
	}})
	withWrongReceiver.AddNode(usg.Node{ID: "src", Type: "code.Attr", Props: map[string]string{
		"loc": "sample.x:3", "callee_path": "payload.value", "method": "value",
	}})
	if got := adapter.Apply(withWrongReceiver); len(got) != 0 {
		t.Fatalf("receiver source fired without receiver type: %+v", got)
	}

	withReceiver := usg.NewInMemStore()
	withReceiver.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "sample.x:1", "module": "samplepkg", "package": "samplepkg",
	}})
	withReceiver.AddNode(usg.Node{ID: "src", Type: "code.Attr", Props: map[string]string{
		"loc": "sample.x:3", "callee_path": "request.value", "method": "value", "recv_type": "samplepkg.Request",
	}})
	if got := adapter.Apply(withReceiver); len(got) != 1 || got[0].NodeID != "src" || got[0].Concept != "custom.Source" {
		t.Fatalf("receiver source did not fire with receiver type: %+v", got)
	}
}

func TestPackageGatedControlRequiresPackageEvidence(t *testing.T) {
	spec := adapterSpec{
		Name:       "neutral",
		Technology: "neutral",
		Controls: []controlSpec{{
			Concept:  "custom.Control",
			Pattern:  "normalize",
			ByMethod: true,
			Packages: []string{"samplepkg"},
		}},
	}
	adapter := spec.controlAdapter()

	withoutPkg := usg.NewInMemStore()
	withoutPkg.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "samplepkg.normalize", "method": "normalize",
	}})
	if got := adapter.Apply(withoutPkg); len(got) != 0 {
		t.Fatalf("package-gated control fired without evidence: %+v", got)
	}

	withPkg := usg.NewInMemStore()
	withPkg.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "sample.x:1", "module": "samplepkg", "package": "samplepkg",
	}})
	withPkg.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "samplepkg.normalize", "method": "normalize",
	}})
	if got := adapter.Apply(withPkg); len(got) != 1 || got[0].NodeID != "call" || got[0].Concept != "custom.Control" {
		t.Fatalf("package-gated control did not fire with package evidence: %+v", got)
	}
}

func TestReceiverControlLabelsReceiverNode(t *testing.T) {
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "recv", Type: "code.Name", Props: map[string]string{"loc": "sample.x:1"}})
	store.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc":    "sample.x:1",
		"method": "checked",
		"recv":   "recv",
	}})

	spec := adapterSpec{
		Name:       "neutral",
		Technology: "neutral",
		Controls: []controlSpec{{
			Concept:  "custom.Control",
			Pattern:  "checked",
			ByMethod: true,
			Receiver: true,
		}},
	}
	got := spec.controlAdapter().Apply(store)
	if len(got) != 1 || got[0].NodeID != "recv" || got[0].Concept != "custom.Control" {
		t.Fatalf("receiver control mapping wrong: %+v", got)
	}
}
