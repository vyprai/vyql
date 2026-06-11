package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/extract/frontend"
	"github.com/vyprai/vyql/extract/frontend/golang"
	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/lowering"
)

// Language parity B4-cleartext: cleartext channel (CWE-319) — http:// URL to an HTTP
// client, loopback excluded (nval "127.0"), https excluded ("https://" has no "http://").
const cleartextRule = `package vypr.misconfig;
rule CleartextChannel { meta { id: "VYQL-CFG-006", severity: low } match code.CleartextChannel as c }`

func TestCleartextParityPHP(t *testing.T) {
	if runPHP(t, `<?php file_get_contents("http://insecure.example/api");`, cleartextRule) == 0 {
		t.Fatal("expected cleartext for http:// in PHP, got 0")
	}
	if runPHP(t, `<?php file_get_contents("https://secure.example/api");`, cleartextRule) != 0 {
		t.Fatal("https:// is fine in PHP, got a finding")
	}
	if runPHP(t, `<?php file_get_contents("http://127.0.0.1/api");`, cleartextRule) != 0 {
		t.Fatal("loopback excluded in PHP, got a finding")
	}
}

func TestCleartextParityRuby(t *testing.T) {
	if runRuby(t, `HTTParty.get("http://insecure.example/api")`, cleartextRule) == 0 {
		t.Fatal("expected cleartext for http:// in Ruby, got 0")
	}
	if runRuby(t, `HTTParty.get("https://secure.example/api")`, cleartextRule) != 0 {
		t.Fatal("https:// is fine in Ruby, got a finding")
	}
}

func TestCleartextParityCSharp(t *testing.T) {
	if runCSharp(t, `class C { void F() { client.DownloadString("http://insecure.example/api"); } }`, cleartextRule) == 0 {
		t.Fatal("expected cleartext for http:// in C#, got 0")
	}
	if runCSharp(t, `class C { void F() { client.DownloadString("https://secure.example/api"); } }`, cleartextRule) != 0 {
		t.Fatal("https:// is fine in C#, got a finding")
	}
}

func TestCleartextParityJava(t *testing.T) {
	run := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "H.java")
		_ = os.WriteFile(p, []byte(src), 0o644)
		prog, _ := treesitter.ExtractJava([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.JavaAdapters(), nil)
		return runLang(t, g, cleartextRule)
	}
	if run(`class H { void f() { new java.net.URL("http://insecure.example/api"); } }`) == 0 {
		t.Fatal("expected cleartext for http:// URL in Java, got 0")
	}
	if run(`class H { void f() { new java.net.URL("https://secure.example/api"); } }`) != 0 {
		t.Fatal("https:// is fine in Java, got a finding")
	}
}

func TestCleartextParityGo(t *testing.T) {
	run := func(src string) int {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "h.go"), []byte(src), 0o644)
		prog, _ := golang.ExtractDir(dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.GoAdapters(), nil)
		return runLang(t, g, cleartextRule)
	}
	if run(`package p
import "net/http"
func h() { http.Get("http://insecure.example/api") }
`) == 0 {
		t.Fatal("expected cleartext for http.Get http:// in Go, got 0")
	}
	if run(`package p
import "net/http"
func h() { http.Get("https://secure.example/api") }
`) != 0 {
		t.Fatal("https:// is fine in Go, got a finding")
	}
}
