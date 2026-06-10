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

// Expansion / CWE-327: presence rule for a broken symmetric cipher (DES).
func TestWeakCipherGo(t *testing.T) {
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
rule WeakCipher { meta { id: "VYQL-CRY-002", severity: medium } match code.WeakCipher as c }
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
import "crypto/des"
func h(key []byte) { _, _ = des.NewCipher(key) }
`) == 0 {
		t.Fatal("expected weak-cipher finding for des.NewCipher, got 0")
	}
	if scan(`package p
import "crypto/aes"
func h(key []byte) { _, _ = aes.NewCipher(key) }
`) != 0 {
		t.Fatal("aes.NewCipher is strong, should be clean, got a finding")
	}
}
