package golang_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/engine"
	"github.com/vyprai/vyql/extract/frontend"
	"github.com/vyprai/vyql/extract/frontend/golang"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
)

// Named-value matching / CWE-295: tls.Config{InsecureSkipVerify: true} disables TLS cert
// validation. The named-struct literal is modeled as a constructor call so the boolean
// field value is reachable; InsecureSkipVerify: false (or absent) stays clean.
func TestCertValidationDisabledGo(t *testing.T) {
	scan := func(src string) int {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "h.go"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := golang.ExtractDir(dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.GoAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(`
package vypr.misconfig;
rule CertValidationDisabled { meta { id: "VYQL-CFG-004", severity: high } match code.CertValidationDisabled as c }
`)
		compiled, errs := engine.CompileRules(decls, onto)
		if len(errs) != 0 {
			t.Fatalf("compile: %v", errs)
		}
		var n int
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			n += len(fs)
		}
		return n
	}

	if scan(`package p
import "crypto/tls"
func h() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }
`) == 0 {
		t.Fatal("expected cert-validation-disabled finding for InsecureSkipVerify: true, got 0")
	}
	if scan(`package p
import "crypto/tls"
func h() *tls.Config { return &tls.Config{InsecureSkipVerify: false} }
`) != 0 {
		t.Fatal("InsecureSkipVerify: false is fine, should be clean, got a finding")
	}
	if scan(`package p
import "crypto/tls"
func h() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS12} }
`) != 0 {
		t.Fatal("a tls.Config without InsecureSkipVerify is clean, got a finding")
	}
}
