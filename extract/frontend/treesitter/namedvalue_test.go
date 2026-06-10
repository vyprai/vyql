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
	"github.com/vyprai/vyql/usg"
)

// Named-value matching: keyword args, dict/object entries, and nested list values,
// plus the `nval` absence operator. Covers cert-validation (295), JWT (347),
// cleartext (319), and insecure-cookie (614) for Python and JavaScript.

func runPy(t *testing.T, rule, src string) int {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "a.py")
	_ = os.WriteFile(p, []byte(src), 0o644)
	prog, _ := treesitter.ExtractPython([]string{p}, dir)
	g, _ := lowering.Lower(prog, true)
	adapters.Apply(g, frontend.PythonAdapters(), nil)
	return evalCount(t, g, rule)
}

func runJs(t *testing.T, rule, src string) int {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "a.js")
	_ = os.WriteFile(p, []byte(src), 0o644)
	prog, _ := treesitter.ExtractJavaScript([]string{p}, dir)
	g, _ := lowering.Lower(prog, true)
	adapters.Apply(g, frontend.JsAdapters(), nil)
	return evalCount(t, g, rule)
}

func evalCount(t *testing.T, g usg.Store, rule string) int {
	t.Helper()
	onto := ontology.Seed()
	decls, err := parser.Parse(rule)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, cerrs := engine.CompileRules(decls, onto)
	if len(cerrs) != 0 {
		t.Fatalf("compile: %v", cerrs)
	}
	var n int
	for _, cr := range compiled {
		fs, _ := engine.New(onto, g).Evaluate(cr)
		n += len(fs)
	}
	return n
}

func TestCertValidationDisabledPython(t *testing.T) {
	rule := `package vypr.misconfig;
rule CertValidationDisabled { meta { id: "VYQL-CFG-004", severity: high } match code.CertValidationDisabled as c }`
	if runPy(t, rule, `import requests
requests.get("https://x.com", verify=False)`) == 0 {
		t.Fatal("expected cert finding for verify=False, got 0")
	}
	if runPy(t, rule, `import requests
requests.get("https://x.com", verify=True)`) != 0 {
		t.Fatal("verify=True is fine, got a finding")
	}
	if runPy(t, rule, `import requests
requests.get("https://x.com")`) != 0 {
		t.Fatal("no verify arg is fine here, got a finding")
	}
}

func TestJwtUnverifiedPython(t *testing.T) {
	rule := `package vypr.misconfig;
rule JwtUnverified { meta { id: "VYQL-CFG-005", severity: high } match code.JwtUnverified as c }`
	if runPy(t, rule, `import jwt
jwt.decode(token, algorithms=["none"])`) == 0 {
		t.Fatal("expected JWT finding for algorithms=['none'], got 0")
	}
	if runPy(t, rule, `import jwt
jwt.decode(token, key, algorithms=["HS256"])`) != 0 {
		t.Fatal("HS256 is fine, got a finding")
	}
}

func TestCleartextChannelPython(t *testing.T) {
	rule := `package vypr.misconfig;
rule CleartextChannel { meta { id: "VYQL-CFG-006", severity: low } match code.CleartextChannel as c }`
	if runPy(t, rule, `import requests
requests.get("http://insecure.example/api")`) == 0 {
		t.Fatal("expected cleartext finding for http:// URL, got 0")
	}
	if runPy(t, rule, `import requests
requests.get("https://secure.example/api")`) != 0 {
		t.Fatal("https:// is fine, got a finding")
	}
	// `nval "127.0"` excludes loopback dev traffic.
	if runPy(t, rule, `import requests
requests.get("http://127.0.0.1:5000/api")`) != 0 {
		t.Fatal("loopback http://127.0.0.1 should be excluded, got a finding")
	}
}

// Insecure cookie fires only when a flag is EXPLICITLY disabled — not on omission
// (which would false-positive on cookie deletions and framework-default-protected apps).
func TestInsecureCookiePython(t *testing.T) {
	rule := `package vypr.misconfig;
rule InsecureCookie { meta { id: "VYQL-CFG-007", severity: low } match code.InsecureCookie as c }`
	if runPy(t, rule, `def view(resp, v):
    resp.set_cookie("sid", v, httponly=False)`) == 0 {
		t.Fatal("expected insecure-cookie finding for httponly=False, got 0")
	}
	if runPy(t, rule, `def view(resp, v):
    resp.set_cookie("sid", v, httponly=True)`) != 0 {
		t.Fatal("httponly=True is fine, got a finding")
	}
	if runPy(t, rule, `def view(resp, v):
    resp.set_cookie("sid", v)`) != 0 {
		t.Fatal("omitted flags are not flagged (avoids FP on deletions/defaults), got a finding")
	}
}

func TestCertValidationDisabledJS(t *testing.T) {
	rule := `package vypr.misconfig;
rule CertValidationDisabled { meta { id: "VYQL-CFG-004", severity: high } match code.CertValidationDisabled as c }`
	if runJs(t, rule, `const https = require('https');
https.request({hostname: 'x', rejectUnauthorized: false});`) == 0 {
		t.Fatal("expected cert finding for rejectUnauthorized:false, got 0")
	}
	if runJs(t, rule, `const https = require('https');
https.request({hostname: 'x', rejectUnauthorized: true});`) != 0 {
		t.Fatal("rejectUnauthorized:true is fine, got a finding")
	}
}

func TestInsecureCookieJS(t *testing.T) {
	rule := `package vypr.misconfig;
rule InsecureCookie { meta { id: "VYQL-CFG-007", severity: low } match code.InsecureCookie as c }`
	if runJs(t, rule, `app.get('/', (req, res) => { res.cookie('sid', token, {httpOnly: false}); });`) == 0 {
		t.Fatal("expected insecure-cookie finding for httpOnly:false, got 0")
	}
	if runJs(t, rule, `app.get('/', (req, res) => { res.cookie('sid', token, {httpOnly: true}); });`) != 0 {
		t.Fatal("httpOnly:true is fine, got a finding")
	}
	if runJs(t, rule, `app.get('/', (req, res) => { res.cookie('sid', token); });`) != 0 {
		t.Fatal("omitted flags are not flagged, got a finding")
	}
}
