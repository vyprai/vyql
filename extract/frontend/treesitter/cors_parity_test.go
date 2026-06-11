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

// Language parity: permissive CORS (CWE-942) using MULTI-`val` (header name AND "*").
// A specific origin is clean because the "*" condition fails.
const corsRule = `package vypr.misconfig;
rule PermissiveCors { meta { id: "VYQL-CFG-003", severity: medium } match code.PermissiveCors as c }`

func TestCorsParityJS(t *testing.T) {
	run := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "a.js")
		_ = os.WriteFile(p, []byte(src), 0o644)
		prog, _ := treesitter.ExtractJavaScript([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.JsAdapters(), nil)
		return runLang(t, g, corsRule)
	}
	if run(`app.use((req, res) => { res.setHeader('Access-Control-Allow-Origin', '*'); });`) == 0 {
		t.Fatal("expected permissive-CORS for ACAO '*', got 0")
	}
	if run(`app.use((req, res) => { res.setHeader('Access-Control-Allow-Origin', 'https://trusted.com'); });`) != 0 {
		t.Fatal("a specific origin is fine, got a finding")
	}
}

func TestCorsParityGo(t *testing.T) {
	run := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "h.go")
		_ = os.WriteFile(p, []byte(src), 0o644)
		prog, _ := golang.ExtractDir(dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.GoAdapters(), nil)
		return runLang(t, g, corsRule)
	}
	if run(`package p
import "net/http"
func h(w http.ResponseWriter) { w.Header().Set("Access-Control-Allow-Origin", "*") }
`) == 0 {
		t.Fatal("expected permissive-CORS for ACAO '*' in Go, got 0")
	}
	if run(`package p
import "net/http"
func h(w http.ResponseWriter) { w.Header().Set("Access-Control-Allow-Origin", "https://trusted.com") }
`) != 0 {
		t.Fatal("a specific origin is fine in Go, got a finding")
	}
}

func TestCorsParityJava(t *testing.T) {
	run := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "H.java")
		_ = os.WriteFile(p, []byte(src), 0o644)
		prog, _ := treesitter.ExtractJava([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.JavaAdapters(), nil)
		return runLang(t, g, corsRule)
	}
	if run(`class H { void f(HttpServletResponse r) { r.setHeader("Access-Control-Allow-Origin", "*"); } }`) == 0 {
		t.Fatal("expected permissive-CORS for ACAO '*' in Java, got 0")
	}
	if run(`class H { void f(HttpServletResponse r) { r.setHeader("Content-Type", "text/html"); } }`) != 0 {
		t.Fatal("a non-CORS header is fine, got a finding")
	}
}

func TestCorsParityPython(t *testing.T) {
	run := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "a.py")
		_ = os.WriteFile(p, []byte(src), 0o644)
		prog, _ := treesitter.ExtractPython([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.PythonAdapters(), nil)
		return runLang(t, g, corsRule)
	}
	if run(`def view(response):
    response.headers.add("Access-Control-Allow-Origin", "*")`) == 0 {
		t.Fatal("expected permissive-CORS for headers.add ACAO '*', got 0")
	}
	if run(`from flask_cors import CORS
CORS(app, origins="*")`) == 0 {
		t.Fatal("expected permissive-CORS for flask-cors origins='*', got 0")
	}
	if run(`def view(response):
    response.headers.add("Access-Control-Allow-Origin", "https://trusted.com")`) != 0 {
		t.Fatal("a specific origin is fine, got a finding")
	}
}
