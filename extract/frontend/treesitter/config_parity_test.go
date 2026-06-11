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

// Language parity B2/B4: cookie (614), JWT (347), cert (295) via named-value matching,
// enabled by Pair emission for php arrays / ruby hashes / go struct literals.

const cookieRule = `package vypr.misconfig;
rule InsecureCookie { meta { id: "VYQL-CFG-007", severity: low } match code.InsecureCookie as c }`
const jwtRule = `package vypr.misconfig;
rule JwtUnverified { meta { id: "VYQL-CFG-005", severity: high } match code.JwtUnverified as c }`
const certRule = `package vypr.misconfig;
rule CertValidationDisabled { meta { id: "VYQL-CFG-004", severity: high } match code.CertValidationDisabled as c }`

func runPHP(t *testing.T, src, rule string) int {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "c.php")
	_ = os.WriteFile(p, []byte(src), 0o644)
	prog, _ := treesitter.ExtractPHP([]string{p}, dir)
	g, _ := lowering.Lower(prog, true)
	adapters.Apply(g, frontend.PHPAdapters(), nil)
	return runLang(t, g, rule)
}

func runRuby(t *testing.T, src, rule string) int {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "c.rb")
	_ = os.WriteFile(p, []byte(src), 0o644)
	prog, _ := treesitter.ExtractRuby([]string{p}, dir)
	g, _ := lowering.Lower(prog, true)
	adapters.Apply(g, frontend.RubyAdapters(), nil)
	return runLang(t, g, rule)
}

func TestInsecureCookiePHP(t *testing.T) {
	if runPHP(t, `<?php setcookie("sid", $v, ["httponly" => false]);`, cookieRule) == 0 {
		t.Fatal("expected insecure-cookie for httponly=>false, got 0")
	}
	if runPHP(t, `<?php setcookie("sid", $v, ["httponly" => true, "secure" => true]);`, cookieRule) != 0 {
		t.Fatal("httponly=>true is fine, got a finding")
	}
}

func TestJwtUnverifiedPHP(t *testing.T) {
	if runPHP(t, `<?php JWT::decode($jwt, $key, ["none"]);`, jwtRule) == 0 {
		t.Fatal("expected JWT finding for alg none, got 0")
	}
	if runPHP(t, `<?php JWT::decode($jwt, $key, ["HS256"]);`, jwtRule) != 0 {
		t.Fatal("HS256 is fine, got a finding")
	}
}

func TestCertValidationDisabledPHP(t *testing.T) {
	if runPHP(t, `<?php curl_setopt_array($ch, [CURLOPT_SSL_VERIFYPEER => false]);`, certRule) == 0 {
		t.Fatal("expected cert finding for VERIFYPEER=>false, got 0")
	}
	if runPHP(t, `<?php curl_setopt_array($ch, [CURLOPT_SSL_VERIFYPEER => true]);`, certRule) != 0 {
		t.Fatal("VERIFYPEER=>true is fine, got a finding")
	}
}

func TestJwtUnverifiedRuby(t *testing.T) {
	if runRuby(t, `JWT.decode(token, nil, false)`, jwtRule) == 0 {
		t.Fatal("expected JWT finding for verify=false, got 0")
	}
	if runRuby(t, `JWT.decode(token, key, true, { algorithm: "HS256" })`, jwtRule) != 0 {
		t.Fatal("verify=true + HS256 is fine, got a finding")
	}
}

func TestInsecureCookieJava(t *testing.T) {
	run := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "C.java")
		_ = os.WriteFile(p, []byte(src), 0o644)
		prog, _ := treesitter.ExtractJava([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.JavaAdapters(), nil)
		return runLang(t, g, cookieRule)
	}
	if run(`class C { void f(Cookie c) { c.setHttpOnly(false); } }`) == 0 {
		t.Fatal("expected insecure-cookie for setHttpOnly(false), got 0")
	}
	if run(`class C { void f(Cookie c) { c.setHttpOnly(true); } }`) != 0 {
		t.Fatal("setHttpOnly(true) is fine, got a finding")
	}
}

func TestInsecureCookieGo(t *testing.T) {
	run := func(src string) int {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "h.go"), []byte(src), 0o644)
		prog, _ := golang.ExtractDir(dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.GoAdapters(), nil)
		return runLang(t, g, cookieRule)
	}
	if run(`package p
import "net/http"
func h() *http.Cookie { return &http.Cookie{Name: "s", Value: "v", HttpOnly: false} }
`) == 0 {
		t.Fatal("expected insecure-cookie for HttpOnly: false, got 0")
	}
	if run(`package p
import "net/http"
func h() *http.Cookie { return &http.Cookie{Name: "s", Value: "v", HttpOnly: true} }
`) != 0 {
		t.Fatal("HttpOnly: true is fine, got a finding")
	}
}
