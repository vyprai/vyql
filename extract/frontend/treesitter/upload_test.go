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

const uploadRule = `
package vypr.injection;
rule UnrestrictedUpload { meta { id: "VYQL-INJ-015", severity: medium } taint code.HttpInput -> code.UnsafeUpload }
`

// Phase B / CWE-434: a user-controlled upload destination/filename reaching
// move_uploaded_file (arbitrary write).
func TestUnrestrictedUploadPHP(t *testing.T) {
	scan := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "u.php")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := treesitter.ExtractPHP([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.PHPAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(uploadRule)
		compiled, _ := engine.CompileRules(decls, onto)
		var n int
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			n += len(fs)
		}
		return n
	}

	if scan(`<?php
function upload() {
  $dest = "uploads/" . $_FILES['f']['name'];
  move_uploaded_file($_FILES['f']['tmp_name'], $dest);
}
`) == 0 {
		t.Fatal("expected unrestricted-upload finding (tainted destination), got 0")
	}
	if scan(`<?php
function upload() {
  move_uploaded_file($_FILES['f']['tmp_name'], "uploads/fixed.dat");
}
`) != 0 {
		t.Fatal("a constant destination is clean, got a finding")
	}
}
