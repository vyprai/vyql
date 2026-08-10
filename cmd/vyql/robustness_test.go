package main

// Frontend robustness. Every frontend must
// survive adversarial/degenerate input — empty, syntactically broken, unicode, binary,
// and deeply nested — without panicking or erroring. A panic here is a scanner crash on
// a real repo. Drives every entry in the `languages` table (22 langs + config).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend"
)

func robustnessInputs() map[string]string {
	deepOpen := strings.Repeat("(", 2000)
	deepArr := strings.Repeat("[", 2000)
	return map[string]string{
		"empty":          "",
		"whitespace":     "   \n\t\n   ",
		"comment-only":   "// just a comment\n# another\n",
		"broken-syntax":  "func ( { [ <<< unterminated \"string and (((",
		"unicode":        "fn 你好() { let \U0001F600 = \"naïve café résumé\"; }",
		"null-bytes":     "abc\x00\x00def\x00ghi",
		"binary-ish":     "\xff\xfe\x00\x01\x02\x03\x80\x81 random \xde\xad\xbe\xef bytes",
		"deep-nesting":   "x = " + deepOpen + "1" + strings.Repeat(")", 2000),
		"deep-brackets":  "x = " + deepArr + "1" + strings.Repeat("]", 2000),
		"long-line":      "x = \"" + strings.Repeat("A", 200000) + "\"",
		"lone-backslash": "\\\n\\\\\n\\x",
		"cr-lf":          "a = 1\r\nb = 2\r\n",
	}
}

func TestFrontendRobustness(t *testing.T) {
	inputs := robustnessInputs()
	for _, lg := range frontend.Languages() {
		lg := lg
		// pick a deterministic extension for this language.
		var ext string
		for e := range lg.Exts {
			if ext == "" || e < ext {
				ext = e
			}
		}
		t.Run(lg.Name, func(t *testing.T) {
			for name, src := range inputs {
				name, src := name, src
				t.Run(name, func(t *testing.T) {
					dir := t.TempDir()
					// config frontend keys on filename — use a recognized manifest name.
					fname := "snippet" + ext
					if lg.Name == "config" {
						fname = "AndroidManifest.xml"
					}
					if err := os.WriteFile(filepath.Join(dir, fname), []byte(src), 0o644); err != nil {
						t.Fatal(err)
					}
					func() {
						defer func() {
							if r := recover(); r != nil {
								t.Fatalf("frontend %q PANICKED on %q input: %v", lg.Name, name, r)
							}
						}()
						if _, err := lg.Extract([]string{filepath.Join(dir, fname)}, dir); err != nil {
							t.Errorf("frontend %q errored on %q input (should degrade gracefully): %v", lg.Name, name, err)
						}
					}()
				})
			}
		})
	}
}

// FuzzFrontends fuzzes the python + javascript frontends with arbitrary bytes — a panic
// is a failure. Seeded with the crafted adversarial inputs. Run: `go test -run x -fuzz
// FuzzFrontends ./cmd/vyql/`. (The deterministic TestFrontendRobustness above is the CI gate.)
func FuzzFrontends(f *testing.F) {
	for _, src := range robustnessInputs() {
		f.Add(src)
	}
	f.Fuzz(func(t *testing.T, src string) {
		dir := t.TempDir()
		for _, lg := range frontend.Languages() {
			if lg.Name != "python" && lg.Name != "javascript" {
				continue
			}
			ext := ".py"
			if lg.Name == "javascript" {
				ext = ".js"
			}
			p := filepath.Join(dir, "f"+ext)
			_ = os.WriteFile(p, []byte(src), 0o644)
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("%s frontend panicked on fuzz input %q: %v", lg.Name, src, r)
					}
				}()
				_, _ = lg.Extract([]string{p}, dir)
			}()
		}
	})
}

// TestScanRobustness drives the FULL pipeline (extract → lower → adapters → rules) on a
// directory of adversarial inputs across several languages at once — asserting the whole
// scan path degrades gracefully rather than panicking.
func TestScanRobustness(t *testing.T) {
	rules, err := loadRules("")
	if err != nil {
		t.Fatalf("load packs: %v", err)
	}
	dir := t.TempDir()
	files := map[string]string{
		"a.py":    "def f(:\n  x = (((",
		"b.js":    "function ( { var x = `${",
		"c.go":    "package m\nfunc (",
		"d.rb":    "def \xff\x00 end",
		"e.java":  "class { void (",
		"f.rs":    "fn ( { let _ = ",
		"junk.py": "\x00\x01\x02\xff\xfe binary masquerading as python",
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("full scan PANICKED on adversarial corpus: %v", r)
		}
	}()
	if _, _, _, err := scanPaths([]string{dir}, rules); err != nil {
		// an error is acceptable (e.g. nothing analyzable); a panic is not.
		t.Logf("scan returned error on adversarial corpus (acceptable): %v", err)
	}
}
