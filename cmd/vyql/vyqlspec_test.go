package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/engine"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
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

type specFile struct {
	name string // explicit filename, or "" for the default snippet name
	code string
}

type vyqlSpec struct {
	name     string
	lang     string
	expect   []string
	reject   []string
	files    []specFile // one or more code blocks (multi-file specs supported)
	graphSrc string     // a `graph` block: an asset/identity graph (mutually exclusive with code)
	src      string     // source spec filename (for messages)
	line     int
}

// primaryExt maps a spec `lang` to the file extension its frontend keys on.
var primaryExt = map[string]string{
	"go": ".go", "python": ".py", "javascript": ".js", "ruby": ".rb",
	"java": ".java", "php": ".php", "csharp": ".cs", "c": ".c", "cpp": ".cpp",
	"rust": ".rs", "bash": ".sh", "scala": ".scala", "lua": ".lua", "kotlin": ".kt",
	"powershell": ".ps1", "swift": ".swift", "perl": ".pl", "solidity": ".sol", "objc": ".m",
	// mobile config files — specs supply the real filename via `file <name>` blocks.
	"config": ".xml",
	"elixir": ".ex",
	"dart":   ".dart",
	"groovy": ".groovy",
	// secretscan runs over any text file; `.env` keys on no real frontend, so a
	// `lang secretscan` spec exercises the secret scanner in isolation.
	"secretscan": ".env",
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
	pendingGraph := false // the next fence is a `graph` block, not a code block
	var code []string
	pendingFile := "" // filename from a preceding `file <name>` line
	closeCur := func() {
		if cur != nil {
			specs = append(specs, *cur)
			cur = nil
		}
	}
	lines := strings.Split(string(data), "\n")
	for i, raw := range lines {
		if inCode {
			if strings.TrimSpace(raw) == "```" {
				if pendingGraph {
					cur.graphSrc = strings.Join(code, "\n")
				} else {
					cur.files = append(cur.files, specFile{name: pendingFile, code: strings.Join(code, "\n")})
				}
				inCode, code, pendingFile, pendingGraph = false, nil, "", false
				continue
			}
			code = append(code, raw)
			continue
		}
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if line == "```" {
			inCode = true
			continue
		}
		kw, rest, _ := strings.Cut(line, " ")
		rest = strings.TrimSpace(rest)
		switch kw {
		case "test":
			closeCur() // a test ends at the next `test` (or EOF)
			cur = &vyqlSpec{name: strings.Trim(rest, `"`), src: rel, line: i + 1}
		case "lang":
			cur.lang = rest
		case "expect":
			cur.expect = append(cur.expect, rest)
		case "reject":
			cur.reject = append(cur.reject, rest)
		case "file":
			pendingFile = rest // next fence writes to this filename
		case "code":
			// optional keyword; the following ``` opens the block
		case "graph":
			pendingGraph = true // the following ``` opens an asset/identity graph block
		default:
			if cur != nil {
				t.Fatalf("%s:%d: unknown spec line %q", rel, i+1, line)
			}
		}
	}
	if inCode {
		t.Fatalf("%s:%d: unterminated code fence in `test %q`", rel, cur.line, cur.name)
	}
	closeCur()
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
	// compile the shipped packs once — `graph` specs evaluate them over a synthetic
	// asset/identity graph (the code specs scan source instead).
	onto := ontology.Seed()
	decls, err := parser.Parse(rules)
	if err != nil {
		t.Fatalf("parse packs: %v", err)
	}
	compiled, cerrs := engine.CompileRules(decls, onto)
	if len(cerrs) != 0 {
		t.Fatalf("compile packs: %v", cerrs)
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
			t.Run(s.src+"/"+s.name, func(t *testing.T) {
				if len(s.expect) == 0 && len(s.reject) == 0 {
					t.Fatalf("%s:%d: spec has neither expect nor reject", s.src, s.line)
				}
				fired := map[string]bool{}
				if s.graphSrc != "" {
					// graph spec: build the asset/identity graph and evaluate the packs.
					store := buildGraphStore(t, s)
					eng := engine.New(onto, store)
					for _, cr := range compiled {
						got, err := eng.Evaluate(cr)
						if err != nil {
							t.Fatalf("evaluate: %v", err)
						}
						for _, fnd := range got {
							fired[fnd.RuleID] = true
						}
					}
				} else {
					// code spec: write the snippet(s) and scan as source.
					ext, ok := primaryExt[s.lang]
					if !ok {
						t.Fatalf("%s:%d: unknown lang %q", s.src, s.line, s.lang)
					}
					if len(s.files) == 0 {
						t.Fatalf("%s:%d: spec %q has no code or graph block", s.src, s.line, s.name)
					}
					dir := t.TempDir()
					for n, fl := range s.files {
						name := fl.name
						if name == "" {
							name = "snippet" + ext
							if n > 0 {
								name = "snippet" + strconv.Itoa(n) + ext
							}
						}
						if err := os.WriteFile(filepath.Join(dir, name), []byte(fl.code), 0o644); err != nil {
							t.Fatal(err)
						}
					}
					found, _, err := scanPaths([]string{dir}, rules)
					if err != nil {
						t.Fatalf("scan: %v", err)
					}
					for _, fnd := range found {
						fired[fnd.RuleID] = true
					}
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

// buildGraphStore parses a `graph` block's mini-DSL into a USG store. Lines:
//
//	node <id> <type-or-concept> [{ k = v, ... }]   — a vertex; auto-labelled with the
//	                                                 concept (props mirrored onto the label)
//	label <id> <concept> [{ k = v, ... }]          — an additional concept label
//	edge <TYPE> <src> -> <dst> [{ k = v, ... }]    — a typed edge (NET/STEP/FLOWS/CHECKS/…)
func buildGraphStore(t *testing.T, s vyqlSpec) *usg.InMemStore {
	t.Helper()
	store := usg.NewInMemStore()
	for n, raw := range strings.Split(s.graphSrc, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		props := map[string]string{}
		if i := strings.Index(line, "{"); i >= 0 {
			props = parseGraphProps(line[i:])
			line = strings.TrimSpace(line[:i])
		}
		f := strings.Fields(line)
		switch {
		case f[0] == "node" && len(f) >= 3:
			_ = store.AddNode(usg.Node{ID: f[1], Type: f[2], Props: props})
			_ = store.AddLabel(f[1], usg.Label{Concept: f[2], Detail: props})
		case f[0] == "label" && len(f) >= 3:
			_ = store.AddLabel(f[1], usg.Label{Concept: f[2], Detail: props})
		case f[0] == "edge" && len(f) >= 5 && f[3] == "->":
			_ = store.AddEdge(usg.Edge{Type: f[1], Src: f[2], Dst: f[4], Props: props})
		default:
			t.Fatalf("%s:%d: malformed graph line %d: %q", s.src, s.line, n+1, raw)
		}
	}
	return store
}

func parseGraphProps(s string) map[string]string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if k, v, ok := strings.Cut(part, "="); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

func keys(m map[string]bool) string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return strings.Join(out, ", ")
}
