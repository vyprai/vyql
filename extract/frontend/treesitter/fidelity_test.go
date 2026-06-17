package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/extract/frontend"
	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/lowering"
)

func TestJavaScriptExpressRequestReceiverTypeLabelsAliasedBody(t *testing.T) {
	src := `const express = require("express");
const app = express();
app.post("/submit", (incoming, outgoing) => {
  const x = incoming.body;
  const y = payload.body;
});
`
	dir := t.TempDir()
	p := filepath.Join(dir, "app.js")
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractJavaScript([]string{p}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.LowerTyped(prog, true, frontend.CtorTypesFor("javascript"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := adapters.Apply(g, frontend.JsAdapters(), nil); err != nil {
		t.Fatal(err)
	}
	ids, err := g.NodesWithConcept("code.HttpInput")
	if err != nil {
		t.Fatal(err)
	}
	var sawIncoming, sawPayload bool
	for _, id := range ids {
		n, ok, _ := g.GetNode(id)
		if !ok {
			continue
		}
		switch n.Prop("callee_path") {
		case "incoming.body":
			sawIncoming = n.Prop("recv_type") == "express.Request"
		case "payload.body":
			sawPayload = true
		}
	}
	if !sawIncoming {
		t.Fatalf("incoming.body was not labeled from resolved express.Request receiver; ids=%v", ids)
	}
	if sawPayload {
		t.Fatalf("untyped payload.body was labeled as HttpInput")
	}
}
