package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/datadir"
)

// VyQL test specs (`vyql/tests/*.test.vyql`) are declarative, language-agnostic
// behavior tests for the SHIPPED ruleset: a code snippet plus the rule ids it must
// (expect) or must not (reject) produce. They live next to the VyQL data they test,
// so adding a rule/adapter means adding a spec — no Go test code. This runner walks
// them and scans each snippet through the real scan pipeline (all packs).
//
// Format (one or more `test` blocks per file; `#`/`//` comments, blank lines ignored):
//
//	test "short description"
//	  lang   java
//	  expect VYQL-CRY-002      # repeatable — every listed rule MUST fire
//	  reject VYQL-INJ-001      # repeatable — every listed rule must NOT fire
//	  code
//	  ```
//	  class C { void f() { Cipher.getInstance("DES/CBC/PKCS5Padding"); } }
//	  ```

type vyqlSpec struct {
	name   string
	lang   string
	expect []string
	reject []string
	code   string
	file   string
	line   int
}

// primaryExt maps a spec `lang` to the file extension its frontend keys on.
var primaryExt = map[string]string{
	"go": ".go", "python": ".py", "javascript": ".js", "ruby": ".rb",
	"java": ".java", "php": ".php", "csharp": ".cs", "c": ".c", "cpp": ".cpp",
	"rust": ".rs", "bash": ".sh", "scala": ".scala", "lua": ".lua", "kotlin": ".kt",
	"powershell": ".ps1", "swift": ".swift", "perl": ".pl", "solidity": ".sol", "objc": ".m",
}

func parseSpecFile(t *testing.T, path string) []vyqlSpec {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read spec %s: %v", path, err)
	}
	rel := filepath.Base(path)
	var specs []vyqlSpec
	var cur *vyqlSpec
	inCode := false
	var code []string
	lines := strings.Split(string(data), "\n")
	for i, raw := range lines {
		if inCode {
			if strings.TrimSpace(raw) == "```" {
				cur.code = strings.Join(code, "\n")
				specs = append(specs, *cur)
				cur, inCode, code = nil, false, nil
				continue
			}
			code = append(code, raw)
			continue
		}
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		kw, rest, _ := strings.Cut(line, " ")
		rest = strings.TrimSpace(rest)
		switch kw {
		case "test":
			if cur != nil {
				t.Fatalf("%s:%d: new `test` before previous one closed (missing code fence?)", rel, i+1)
			}
			cur = &vyqlSpec{name: strings.Trim(rest, `"`), file: rel, line: i + 1}
		case "lang":
			cur.lang = rest
		case "expect":
			cur.expect = append(cur.expect, rest)
		case "reject":
			cur.reject = append(cur.reject, rest)
		case "code":
			// next non-comment line should open the fence; tolerate `code` alone.
		case "```":
			inCode = true
		default:
			if line == "```" {
				inCode = true
			} else if cur != nil {
				t.Fatalf("%s:%d: unknown spec line %q", rel, i+1, line)
			}
		}
	}
	if cur != nil {
		t.Fatalf("%s:%d: unterminated `test %q` (missing closing code fence)", rel, cur.line, cur.name)
	}
	return specs
}

func TestVyqlSpecs(t *testing.T) {
	root := datadir.Root()
	testsDir := filepath.Join(root, "tests")
	if _, err := os.Stat(testsDir); err != nil {
		t.Skipf("no vyql/tests dir: %v", err)
	}
	rules, err := loadRules("") // the full shipped pack library (vyql/packs)
	if err != nil {
		t.Fatalf("load packs: %v", err)
	}

	var files []string
	_ = filepath.WalkDir(testsDir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".test.vyql") {
			files = append(files, p)
		}
		return nil
	})
	if len(files) == 0 {
		t.Skip("no .test.vyql specs found")
	}

	total := 0
	for _, f := range files {
		for _, s := range parseSpecFile(t, f) {
			s := s
			total++
			t.Run(s.file+"/"+s.name, func(t *testing.T) {
				ext, ok := primaryExt[s.lang]
				if !ok {
					t.Fatalf("%s:%d: unknown lang %q", s.file, s.line, s.lang)
				}
				if len(s.expect) == 0 && len(s.reject) == 0 {
					t.Fatalf("%s:%d: spec has neither expect nor reject", s.file, s.line)
				}
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, "snippet"+ext), []byte(s.code), 0o644); err != nil {
					t.Fatal(err)
				}
				found, _, err := scanPaths([]string{dir}, rules)
				if err != nil {
					t.Fatalf("scan: %v", err)
				}
				fired := map[string]bool{}
				for _, fnd := range found {
					fired[fnd.RuleID] = true
				}
				for _, want := range s.expect {
					if !fired[want] {
						t.Errorf("expected rule %s to fire, but it did not (fired: %s)", want, keys(fired))
					}
				}
				for _, no := range s.reject {
					if fired[no] {
						t.Errorf("rule %s fired but should not have", no)
					}
				}
			})
		}
	}
	t.Logf("ran %d VyQL spec(s) from %d file(s)", total, len(files))
}

func keys(m map[string]bool) string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return strings.Join(out, ", ")
}
