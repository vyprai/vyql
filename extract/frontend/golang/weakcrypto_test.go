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

// Phase B / CWE-327: presence rule — flags use of a weak hash (md5.New) via the
// `mark` adapter mapping + a `match code.WeakHash` rule (no taint flow needed).
func TestWeakCryptoGo(t *testing.T) {
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
package vypr.crypto;
rule WeakCrypto { meta { id: "VYQL-CRY-001", severity: medium } match code.WeakHash as h }
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
import "crypto/md5"
func h() { _ = md5.New() }
`) == 0 {
		t.Fatal("expected weak-crypto finding for md5.New(), got 0")
	}
	if scan(`package p
import "crypto/sha256"
func h() { _ = sha256.New() }
`) != 0 {
		t.Fatal("sha256.New() is strong, should be clean, got a finding")
	}
}
