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

// Expansion / Track 3: the `val "substr"` string-literal value capability.
// CWE-942 permissive CORS (php) and CWE-327 ECB cipher mode (java) only fire when
// a literal argument contains the dangerous value.
func TestValueMatchCorsPHP(t *testing.T) {
	corsRule := `
package vypr.misconfig;
rule PermissiveCors { meta { id: "VYQL-CFG-003", severity: medium } match code.PermissiveCors as c }
`
	scan := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "c.php")
		_ = os.WriteFile(p, []byte(src), 0o644)
		prog, _ := treesitter.ExtractPHP([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.PHPAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(corsRule)
		compiled, _ := engine.CompileRules(decls, onto)
		var n int
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			n += len(fs)
		}
		return n
	}
	if scan("<?php header(\"Access-Control-Allow-Origin: *\");") == 0 {
		t.Fatal("expected permissive-CORS finding for ACAO wildcard, got 0")
	}
	if scan("<?php header(\"Access-Control-Allow-Origin: https://trusted.example\");") != 0 {
		t.Fatal("a specific CORS origin is fine, got a finding")
	}
}

func TestValueMatchEcbJava(t *testing.T) {
	cipherRule := `
package vypr.crypto;
rule WeakCipher { meta { id: "VYQL-CRY-002", severity: medium } match code.WeakCipher as c }
`
	scan := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "C.java")
		_ = os.WriteFile(p, []byte(src), 0o644)
		prog, _ := treesitter.ExtractJava([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.JavaAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(cipherRule)
		compiled, _ := engine.CompileRules(decls, onto)
		var n int
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			n += len(fs)
		}
		return n
	}
	if scan(`class C { void f() { Cipher.getInstance("AES/ECB/PKCS5Padding"); } }`) == 0 {
		t.Fatal("expected weak-cipher finding for ECB mode, got 0")
	}
	if scan(`class C { void f() { Cipher.getInstance("AES/GCM/NoPadding"); } }`) != 0 {
		t.Fatal("AES/GCM is strong, should be clean, got a finding")
	}
}

// CWE-327: node crypto.createCipheriv('des-ecb', ...) / ('aes-128-ecb', ...) selects a
// weak cipher/mode by string; a strong AEAD suite (aes-256-gcm) stays clean.
func TestValueMatchCipherJS(t *testing.T) {
	cipherRule := `
package vypr.crypto;
rule WeakCipher { meta { id: "VYQL-CRY-002", severity: medium } match code.WeakCipher as c }
`
	scan := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "c.js")
		_ = os.WriteFile(p, []byte(src), 0o644)
		prog, _ := treesitter.ExtractJavaScript([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.JsAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(cipherRule)
		compiled, _ := engine.CompileRules(decls, onto)
		var n int
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			n += len(fs)
		}
		return n
	}
	if scan(`const crypto = require('crypto'); crypto.createCipheriv('des-ecb', key, iv);`) == 0 {
		t.Fatal("expected weak-cipher finding for des-ecb, got 0")
	}
	if scan(`const crypto = require('crypto'); crypto.createCipheriv('aes-256-gcm', key, iv);`) != 0 {
		t.Fatal("aes-256-gcm is strong, should be clean, got a finding")
	}
}
