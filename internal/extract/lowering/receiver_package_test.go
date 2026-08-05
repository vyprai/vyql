package lowering

import "testing"

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
