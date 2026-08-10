package bindings

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// The binding fingerprint must notice a change anywhere in the binding corpus, including one that
// only moves a file. Moved here with statStaticBindingData when the incremental binding pass left
// package main; it was testing this function, not the CLI.

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func bindingStatKey(root string) string {
	h := sha256.New()
	statStaticBindingData(h, root)
	return hex.EncodeToString(h.Sum(nil))
}

func TestStaticBindingFingerprintIncludesSplitLayout(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "javascript.vyql"), "module bindings.javascript.flat;\n")
	before := bindingStatKey(root)

	writeFile(t, filepath.Join(root, "javascript", "javascript", "001", "codeHttpInput.vyql"), "module bindings.javascript.split;\n")
	afterSplit := bindingStatKey(root)
	if afterSplit == before {
		t.Fatal("static binding fingerprint did not include split binding file")
	}

	writeFile(t, filepath.Join(root, "packages", "generated", "javascript", "express.vyql"), "module bindings.javascript.generated;\n")
	afterGenerated := bindingStatKey(root)
	if afterGenerated != afterSplit {
		t.Fatal("static binding fingerprint should not include generated package corpus")
	}
}
