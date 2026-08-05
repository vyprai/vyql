package lowering

import (
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

func TestResolveReceiverPackage(t *testing.T) {
	table := map[string]importEntry{
		// import Bourne from '@hapi/bourne'
		"Bourne": {kind: "mod", module: "@hapi/bourne"},
		// const yaml = require('js-yaml')
		"yaml": {kind: "mod", module: "js-yaml"},
		// const { parse } = require('qs')
		"parse": {kind: "sym", module: "qs", symbol: "parse"},
		// import defusedxml.ElementTree as ET
		"ET": {kind: "mod", module: "defusedxml.ElementTree"},
	}

	cases := []struct{ path, want string }{
		{"Bourne.parse", "@hapi/bourne"}, // aliased scoped package
		{"yaml.load", "js-yaml"},         // aliased plain package
		{"parse", "qs"},                  // destructured symbol, no receiver
		{"ET.fromstring", "defusedxml"},  // submodule collapses to package root
		{"JSON.parse", ""},               // builtin, not imported
		{"this.parse", ""},               // dynamic receiver
		{"", ""},                         // no callee path at all
		{"unknown.parse", ""},            // receiver not in the import table
	}
	for _, c := range cases {
		if got := resolveReceiverPackage(c.path, table); got != c.want {
			t.Errorf("resolveReceiverPackage(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestResolveReceiverPackageWithoutTable(t *testing.T) {
	if got := resolveReceiverPackage("yaml.load", nil); got != "" {
		t.Fatalf("got %q, want empty with no import table", got)
	}
}

// The resolved package must reach the graph, because that is where the binding
// matcher reads it.
func TestCallNodeCarriesReceiverPackage(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:     "app",
		File:    "app.js",
		Imports: []nir.Import{{Local: "yaml", Module: "js-yaml", IsModule: true}},
		Body: []nir.Stmt{
			nir.FuncDef{Name: "handler", Params: []string{"req"}, Body: []nir.Stmt{
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "yaml", Loc: "app.js:2"}, Attr: "load", Path: "yaml.load", Loc: "app.js:2"},
					Args:   []nir.Expr{nir.Name{ID: "req", Loc: "app.js:2"}},
					Path:   "yaml.load", Method: "load", Loc: "app.js:2",
				}},
			}, Loc: "app.js:1"},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	ids, _ := g.NodesOfType("code.Call")
	if len(ids) == 0 {
		t.Fatal("no call nodes lowered")
	}
	var got string
	var seen []string
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		seen = append(seen, n.Prop("callee_path"))
		if n.Prop("callee_path") == "yaml.load" {
			got = n.Prop("recv_package")
		}
	}
	if got != "js-yaml" {
		t.Fatalf("recv_package = %q, want %q (call paths seen: %v)", got, "js-yaml", seen)
	}
}
