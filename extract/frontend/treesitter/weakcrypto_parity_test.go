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

// Language parity B1: weak crypto (CWE-327) across java/php/ruby/csharp, using the
// named-value feature where the idiom is an algorithm-spec string.

const weakHashRule = `package vypr.crypto;
rule WeakCrypto { meta { id: "VYQL-CRY-001", severity: medium } match code.WeakHash as h }`
const weakCipherRule = `package vypr.crypto;
rule WeakCipher { meta { id: "VYQL-CRY-002", severity: medium } match code.WeakCipher as c }`

func runLang(t *testing.T, g usg.Store, rule string) int {
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

func TestWeakCryptoJava(t *testing.T) {
	run := func(src, rule string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "C.java")
		_ = os.WriteFile(p, []byte(src), 0o644)
		prog, _ := treesitter.ExtractJava([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.JavaAdapters(), nil)
		return runLang(t, g, rule)
	}
	if run(`class C { void f() { Cipher.getInstance("DES/CBC/PKCS5Padding"); } }`, weakCipherRule) == 0 {
		t.Fatal("expected weak-cipher for DES, got 0")
	}
	if run(`class C { void f() { MessageDigest.getInstance("MD5"); } }`, weakHashRule) == 0 {
		t.Fatal("expected weak-hash for MD5, got 0")
	}
	if run(`class C { void f() { MessageDigest.getInstance("SHA-256"); } }`, weakHashRule) != 0 {
		t.Fatal("SHA-256 is strong, got a finding")
	}
	if run(`class C { void f() { Cipher.getInstance("AES/CBC/PKCS5Padding"); } }`, weakCipherRule) != 0 {
		t.Fatal("AES/CBC is strong, got a finding")
	}
}

func TestWeakCryptoPHP(t *testing.T) {
	run := func(src, rule string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "c.php")
		_ = os.WriteFile(p, []byte(src), 0o644)
		prog, _ := treesitter.ExtractPHP([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.PHPAdapters(), nil)
		return runLang(t, g, rule)
	}
	if run(`<?php openssl_encrypt($d, "des-ede3-cbc", $k);`, weakCipherRule) == 0 {
		t.Fatal("expected weak-cipher for des-ede3-cbc, got 0")
	}
	if run(`<?php hash("md5", $d);`, weakHashRule) == 0 {
		t.Fatal("expected weak-hash for hash('md5'), got 0")
	}
	if run(`<?php openssl_encrypt($d, "aes-256-gcm", $k);`, weakCipherRule) != 0 {
		t.Fatal("aes-256-gcm is strong, got a finding")
	}
}

func TestWeakCryptoRuby(t *testing.T) {
	run := func(src, rule string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "c.rb")
		_ = os.WriteFile(p, []byte(src), 0o644)
		prog, _ := treesitter.ExtractRuby([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.RubyAdapters(), nil)
		return runLang(t, g, rule)
	}
	if run(`Digest::MD5.hexdigest(data)`, weakHashRule) == 0 {
		t.Fatal("expected weak-hash for Digest::MD5, got 0")
	}
	if run(`OpenSSL::Cipher.new("des-cbc")`, weakCipherRule) == 0 {
		t.Fatal("expected weak-cipher for Cipher.new('des-cbc'), got 0")
	}
	if run(`Digest::SHA256.hexdigest(data)`, weakHashRule) != 0 {
		t.Fatal("SHA256 is strong, got a finding")
	}
}

func TestWeakCryptoCSharp(t *testing.T) {
	run := func(src, rule string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "C.cs")
		_ = os.WriteFile(p, []byte(src), 0o644)
		prog, _ := treesitter.ExtractCSharp([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.CSharpAdapters(), nil)
		return runLang(t, g, rule)
	}
	if run(`class C { void F() { var d = DES.Create(); } }`, weakCipherRule) == 0 {
		t.Fatal("expected weak-cipher for DES.Create, got 0")
	}
	if run(`class C { void F() { var h = MD5.Create(); } }`, weakHashRule) == 0 {
		t.Fatal("expected weak-hash for MD5.Create, got 0")
	}
	if run(`class C { void F() { var h = SHA256.Create(); } }`, weakHashRule) != 0 {
		t.Fatal("SHA256 is strong, got a finding")
	}
}
