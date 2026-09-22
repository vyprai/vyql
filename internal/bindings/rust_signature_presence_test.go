package bindings

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// rustSignatureBinding is the binding the gap's own sentence asks for: items
// typed by the impl's lifetime rather than the receiver borrow. Every term of
// it reads the declaration -- which trait the impl implements, what the method
// returns -- and no term reads the body, because the two bodies read the same.
const rustSignatureBinding = `
module bindings.rust.test_signature_facts;

binding lendingIteratorItems {
  query pattern presenceNode where node.analysis == "rust.signature" and node.context.implTrait contains "Iterator" and node.context.returnType contains "&'a"
  emit issue custom.LendingIteratorItems at node
}
`

// The gap's named pair, as two files: the lending Reader types its items by the
// impl's lifetime, the owning one returns values it owns. The bodies differ
// only in the accessor they call; the declarations are the whole difference.
const rustLendingReader = `pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Iterator for Reader<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        self.data.first()
    }
}
`

const rustOwningReader = `pub struct Reader {
    data: Vec<u8>,
}

impl Iterator for Reader {
    fn next(&mut self) -> Option<u8> {
        self.data.pop()
    }
}
`

func rustSignatureStore(t *testing.T) usg.Store {
	t.Helper()
	dir := t.TempDir()
	for name, src := range map[string]string{"lending.rs": rustLendingReader, "owning.rs": rustOwningReader} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	prog, err := treesitter.ExtractRust([]string{filepath.Join(dir, "lending.rs"), filepath.Join(dir, "owning.rs")}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// A binding keyed on the impl header and the return type separates the two
// spellings: the lending impl's signature node is labelled, the owning one --
// same method name, same receiver, same trait -- is not, because its items
// carry no lifetime. Before the frontend recorded these facts the query could
// not be written: node.context.implTrait did not resolve to any token family.
func TestRustSignaturePresenceBindingSeparatesLendingAndOwningImpls(t *testing.T) {
	sets, err := compileV2BindingsForTest(rustSignatureBinding)
	if err != nil {
		t.Fatalf("compile lending-iterator binding: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, sets))

	store := rustSignatureStore(t)
	nodes, err := store.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]usg.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}
	marked := map[string]bool{}
	for _, m := range spec.presenceApplicator().Apply(store) {
		n := byID[m.NodeID]
		marked[n.Prop("loc")] = true
		if n.Prop("callee_path") != "analysis.rust.signature" {
			t.Fatalf("binding labelled %q, want only the signature node", n.Prop("callee_path"))
		}
	}
	if !marked["lending.rs:8"] {
		t.Fatalf("the lending impl's signature node was not labelled; marked=%v", marked)
	}
	if marked["owning.rs:6"] {
		t.Fatalf("the owning impl's signature node was labelled; marked=%v", marked)
	}
}
