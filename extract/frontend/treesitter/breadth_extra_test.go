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

// Expansion: JS template-injection breadth — nunjucks.compile(tainted) is SSTI (CWE-1336).
func TestSstiNunjucksJS(t *testing.T) {
	rule := `
package vypr.injection;
rule Template { meta { id: "VYQL-INJ-008", severity: high } taint code.HttpInput -> code.TemplateRender }
`
	scan := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "a.js")
		_ = os.WriteFile(p, []byte(src), 0o644)
		prog, _ := treesitter.ExtractJavaScript([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.JsAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(rule)
		compiled, _ := engine.CompileRules(decls, onto)
		var n int
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			n += len(fs)
		}
		return n
	}
	if scan(`app.get('/', function(req, res){ var t = req.query.tpl; nunjucks.compile(t); });`) == 0 {
		t.Fatal("expected SSTI finding for tainted nunjucks.compile, got 0")
	}
	if scan(`nunjucks.compile('<h1>hello</h1>');`) != 0 {
		t.Fatal("a constant nunjucks template is clean, got a finding")
	}
}

// Expansion: Python weak-cipher presence — DES.new(...) is a broken cipher (CWE-327);
// AES.new(...) is fine.
func TestWeakCipherPython(t *testing.T) {
	rule := `
package vypr.crypto;
rule WeakCipher { meta { id: "VYQL-CRY-002", severity: medium } match code.WeakCipher as c }
`
	scan := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "c.py")
		_ = os.WriteFile(p, []byte(src), 0o644)
		prog, _ := treesitter.ExtractPython([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.PythonAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(rule)
		compiled, _ := engine.CompileRules(decls, onto)
		var n int
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			n += len(fs)
		}
		return n
	}
	if scan("from Crypto.Cipher import DES\nc = DES.new(key, DES.MODE_ECB)") == 0 {
		t.Fatal("expected weak-cipher finding for DES.new, got 0")
	}
	if scan("from Crypto.Cipher import AES\nc = AES.new(key, AES.MODE_GCM)") != 0 {
		t.Fatal("AES.new is fine, should be clean, got a finding")
	}
}
