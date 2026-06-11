package treesitter_test

import (
	"testing"
)

// Language parity B5: XPath (CWE-643) and LDAP (CWE-90) taint sinks across php/ruby/csharp.
const xpathRule = `package vypr.injection;
rule Xpath { meta { id: "VYQL-INJ-006", severity: high } taint code.HttpInput -> code.XpathQuery }`
const ldapRule = `package vypr.injection;
rule Ldap { meta { id: "VYQL-INJ-005", severity: high } taint code.HttpInput -> code.LdapQuery }`

func TestXpathParityPHP(t *testing.T) {
	if runPHP(t, `<?php $q = $_GET['q']; $xml->xpath("//user[@name='" . $q . "']");`, xpathRule) == 0 {
		t.Fatal("expected XPath-injection for tainted SimpleXML xpath, got 0")
	}
	if runPHP(t, `<?php $xml->xpath("//user[@name='admin']");`, xpathRule) != 0 {
		t.Fatal("a constant XPath is clean, got a finding")
	}
}

func TestLdapParityPHP(t *testing.T) {
	if runPHP(t, `<?php $u = $_GET['u']; ldap_search($conn, "dc=x", "(uid=" . $u . ")");`, ldapRule) == 0 {
		t.Fatal("expected LDAP-injection for tainted ldap_search filter, got 0")
	}
	if runPHP(t, `<?php ldap_search($conn, "dc=x", "(uid=admin)");`, ldapRule) != 0 {
		t.Fatal("a constant LDAP filter is clean, got a finding")
	}
}

func TestXpathParityRuby(t *testing.T) {
	if runRuby(t, `def f(doc); q = params[:q]; doc.xpath("//user[@name='#{q}']"); end`, xpathRule) == 0 {
		t.Fatal("expected XPath-injection for tainted Nokogiri xpath, got 0")
	}
	if runRuby(t, `def f(doc); doc.xpath("//user[@name='admin']"); end`, xpathRule) != 0 {
		t.Fatal("a constant XPath is clean, got a finding")
	}
}

func TestXpathLdapParityCSharp(t *testing.T) {
	runCS := func(src, rule string) int {
		return runCSharp(t, src, rule)
	}
	if runCS(`class C { void F() { var q = Request.QueryString["q"]; doc.SelectNodes("//user[@name='" + q + "']"); } }`, xpathRule) == 0 {
		t.Fatal("expected XPath-injection for tainted SelectNodes, got 0")
	}
	if runCS(`class C { void F() { doc.SelectNodes("//user"); } }`, xpathRule) != 0 {
		t.Fatal("a constant XPath is clean, got a finding")
	}
	if runCS(`class C { void F() { var u = Request.QueryString["u"]; new DirectorySearcher("(uid=" + u + ")"); } }`, ldapRule) == 0 {
		t.Fatal("expected LDAP-injection for tainted DirectorySearcher, got 0")
	}
}
