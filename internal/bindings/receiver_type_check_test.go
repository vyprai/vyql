package bindings

import (
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// A check or issue query can carry a receiver-type predicate
// (`callee.receiver.type`). It must key the label to the call's resolved
// receiver type: hardening performed inside a factory wrapper is visible to
// the build sites that share it only through the type their receiver resolves
// to, so a neutralizer credit keyed to that type is how a shared-factory fix
// reaches every parse site that builds from it. The predicate used to compile
// and then be dropped, labelling every same-named call alike.

func receiverTypeCallNode(id, method, recvType string) usg.Node {
	props := map[string]string{
		"loc":         "Sample.java:9",
		"callee_path": "BUILDER_FACTORY." + method,
		"method":      method,
	}
	if recvType != "" {
		props["recv_type"] = recvType
	}
	return usg.Node{ID: id, Type: "code.Call", Props: props}
}

func TestReceiverConstrainedCheckKeysToResolvedReceiverType(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.java.test;

binding hardenedFactoryBuild {
  query pattern callExpr where callee.method == "newDocumentBuilder" and callee.receiver.type == "samplepkg.HardenedFactory"
  emit check core.XmlHardening at call {
    covers path {
      from: call
      to: call
    }
  }
}
`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, sets))
	if len(spec.Controls) != 1 {
		t.Fatalf("expected one control spec, got %#v", spec.Controls)
	}
	if got := spec.Controls[0].Constraint; got != "samplepkg.HardenedFactory" {
		t.Fatalf("receiver type predicate did not lower onto the check: %q", got)
	}
	binding := spec.checkApplicator()

	hardened := usg.NewInMemStore()
	hardened.AddNode(receiverTypeCallNode("wrapped", "newDocumentBuilder", "samplepkg.HardenedFactory"))
	if got := binding.Apply(hardened); len(got) != 1 || got[0].NodeID != "wrapped" || got[0].Concept != "core.XmlHardening" {
		t.Fatalf("check did not credit the hardened factory's build: %+v", got)
	}

	raw := usg.NewInMemStore()
	raw.AddNode(receiverTypeCallNode("plain", "newDocumentBuilder", "javax.xml.parsers.DocumentBuilderFactory"))
	if got := binding.Apply(raw); len(got) != 0 {
		t.Fatalf("check credited a build whose receiver resolves to the raw factory type: %+v", got)
	}

	unresolved := usg.NewInMemStore()
	unresolved.AddNode(receiverTypeCallNode("opaque", "newDocumentBuilder", ""))
	if got := binding.Apply(unresolved); len(got) != 1 {
		t.Fatalf("check dropped a build whose receiver type is unresolved -- a check cannot be disproved without a type: %+v", got)
	}
}

func TestReceiverConstrainedIssueKeysToResolvedReceiverType(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.java.test;

binding exporterHandler {
  query pattern callExpr where callee.method == "handleRequest" and callee.receiver.type in ["samplepkg.Exporter"]
  emit issue code.UnfilteredRpcRequestDeserialization at call
}
`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, sets))
	if len(spec.Marks) != 1 {
		t.Fatalf("expected one mark spec, got %#v", spec.Marks)
	}
	if got := spec.Marks[0].Constraint; got != "samplepkg.Exporter" {
		t.Fatalf("receiver type predicate did not lower onto the issue: %q", got)
	}
	binding := spec.matchPresenceApplicator()

	exporter := usg.NewInMemStore()
	exporter.AddNode(receiverTypeCallNode("exporter", "handleRequest", "samplepkg.Exporter"))
	if got := binding.Apply(exporter); len(got) != 1 || got[0].NodeID != "exporter" || got[0].Concept != "code.UnfilteredRpcRequestDeserialization" {
		t.Fatalf("issue did not fire on the exporter-typed receiver: %+v", got)
	}

	// a same-named method on a receiver whose declared type is a different
	// interface -- the servlet handler, not the deserializing exporter
	other := usg.NewInMemStore()
	other.AddNode(receiverTypeCallNode("servlet", "handleRequest", "samplepkg.RequestHandler"))
	if got := binding.Apply(other); len(got) != 0 {
		t.Fatalf("issue fired on a receiver of a known unrelated type: %+v", got)
	}
}
