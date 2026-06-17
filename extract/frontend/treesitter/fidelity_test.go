package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/engine"
	"github.com/vyprai/vyql/extract/frontend"
	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
)

const twoSinkRules = `
module vypr.injection;
rule Sql {
  meta { id: "VYQL-INJ-001", severity: high }
  taint code.HttpInput -> code.SqlExecution
}
rule Command {
  meta { id: "VYQL-INJ-002", severity: critical }
  taint code.HttpInput -> code.CommandExecution
}
`

// Phase 1a — fidelity → confidence (docs/07): a sink matched by a bare METHOD
// name (cursor.execute — no receiver type known, syntactic) yields a lower
// confidence than one matched by a specific dotted PATH (os.system, resolved).
func TestFidelityDowngradesMethodMatch(t *testing.T) {
	src := `def h():
    x = request.args['q']
    cur.execute("SELECT " + x)
    os.system("ping " + x)
`
	dir := t.TempDir()
	p := filepath.Join(dir, "h.py")
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, _ := treesitter.ExtractPython([]string{p}, dir)
	g, _ := lowering.Lower(prog, true)
	adapters.Apply(g, frontend.PythonAdapters(), nil)

	onto := ontology.Seed()
	decls, _ := parser.Parse(twoSinkRules)
	compiled, errs := engine.CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	eng := engine.New(onto, g)
	conf := map[string]string{}
	for _, cr := range compiled {
		fs, _ := eng.Evaluate(cr)
		for _, f := range fs {
			conf[f.RuleID] = f.Confidence
		}
	}
	if conf["VYQL-INJ-001"] != "medium" {
		t.Fatalf("SQLi via method match should be medium (syntactic), got %q", conf["VYQL-INJ-001"])
	}
	if conf["VYQL-INJ-002"] != "high" {
		t.Fatalf("command-injection via dotted-path match should be high (resolved), got %q", conf["VYQL-INJ-002"])
	}
}

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
