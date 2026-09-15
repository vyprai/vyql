package frontend_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend"
	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/nir"
)

// The whole of CVE-2025-27512 lives in a .rules file: the polkit rule zincati
// ships at dist/polkit-1/rules.d/zincati.rules lost the parenthesis that bound
// its subject test to the granted actions. Two engine facts kept that file
// unread, and this test pins both. The walk skipped the dist staging directory
// wholesale, so the file was never listed at all; and no frontend claims the
// .rules extension, so even named directly the file answered "no supported
// source found". The claim cannot be a mechanical extension add — udev ships
// the same extension for a key-value grammar no JavaScript parser accepts — so
// it keys on the file's content: only a file that registers a rule through the
// polkit API is the JavaScript a polkit daemon loads.
func TestPolkitRulesFilesAreWalkedClaimedAndParsed(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "dist", "polkit-1", "rules.d")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	polkitPath := filepath.Join(rulesDir, "zincati.rules")
	if err := os.WriteFile(polkitPath, []byte(`// Allow Zincati to deploy a staged deployment through rpm-ostree.
polkit.addRule(function(action, subject) {
    if ((action.id == "org.projectatomic.rpmostree1.deploy" ||
         action.id == "org.projectatomic.rpmostree1.finalize-deployment") &&
        subject.user == "zincati") {
        return polkit.Result.YES;
    }
});
`), 0o644); err != nil {
		t.Fatal(err)
	}
	udevPath := filepath.Join(rulesDir, "60-sensor.rules")
	if err := os.WriteFile(udevPath, []byte(`# udev rule: the .rules extension udev owns, key-value all through
KERNEL=="event*", SUBSYSTEM=="input", MODE="0660", GROUP="input"
`), 0o644); err != nil {
		t.Fatal(err)
	}

	// The walk: dist is build output and skipped — except when it stages
	// polkit-1/rules.d, which is where the walk is the only reader of the
	// rules the package ships.
	entries := treesitter.ListAllFiles(dir)
	var listed bool
	for _, e := range entries {
		if e.Path == polkitPath {
			listed = true
		}
	}
	if !listed {
		t.Fatalf("%s is not walked; the dist staging tree hid the polkit rules from every scan of the tree", polkitPath)
	}

	// The claim: content-keyed. The polkit rule is JavaScript and is claimed by
	// the JavaScript frontend; the udev rule shares the extension and is
	// claimed by no one, because feeding its key-value grammar to the
	// JavaScript parser is the mechanical add this claim exists to refuse.
	class := frontend.ClassifyEntries(entries)
	claimedBy := map[string][]string{}
	for _, lg := range frontend.Languages() {
		for _, f := range lg.FilesFor(entries, class) {
			claimedBy[f] = append(claimedBy[f], lg.Name)
		}
	}
	if got := claimedBy[polkitPath]; len(got) != 1 || got[0] != "javascript" {
		t.Errorf("%s claimed by %v, want exactly [javascript]; a polkit rule is the JavaScript a polkit daemon loads", polkitPath, got)
	}
	if got := claimedBy[udevPath]; len(got) != 0 {
		t.Errorf("%s claimed by %v; udev's key-value .rules must stay unclaimed", udevPath, got)
	}

	// The parse: what the claim feeds the frontend must lower whole — a module
	// whose calls a binding can label — not parse to errors.
	prog, err := treesitter.ExtractJavaScript([]string{polkitPath}, dir)
	if err != nil {
		t.Fatalf("javascript frontend: %v", err)
	}
	if len(prog.Modules) != 1 {
		t.Fatalf("javascript frontend produced %d modules, want 1", len(prog.Modules))
	}
	seen := map[string]bool{}
	var expr func(nir.Expr)
	var body func([]nir.Stmt)
	expr = func(e nir.Expr) {
		switch x := e.(type) {
		case nir.Call:
			seen["call "+x.Path] = true
			for _, a := range x.Args {
				expr(a)
			}
		}
	}
	body = func(sts []nir.Stmt) {
		for _, st := range sts {
			switch s := st.(type) {
			case nir.FuncDef:
				body(s.Body)
			case nir.ExprStmt:
				expr(s.Value)
			}
		}
	}
	body(prog.Modules[0].Body)
	if !seen["call polkit.addRule"] {
		t.Errorf("javascript frontend did not produce the polkit.addRule call from the .rules file; got %v", seen)
	}
}
