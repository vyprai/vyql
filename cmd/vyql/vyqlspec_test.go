package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/bindings"
	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/engine"
	"github.com/vyprai/vyql/internal/ontology"
	"github.com/vyprai/vyql/internal/parser"
	"github.com/vyprai/vyql/internal/review"
	"github.com/vyprai/vyql/internal/usg"
)

// VyQL test specs (`vyql/tests/*.test.vyql`) are declarative, language-agnostic
// behavior tests for the SHIPPED ruleset: a code snippet plus the rule ids it must
// (expect) or must not (reject) produce. They live next to the VyQL data they test,
// so adding a rule/binding means adding a spec — no Go test code. This runner walks
// them and scans each snippet through the real scan pipeline (all packs).
//
// Format (one or more `test` blocks per file; `#`/`//` comments, blank lines ignored):
//
//	test "short description"
//	  lang   java
//	  expect RULE-ID      # repeatable — every listed rule MUST fire
//	  reject RULE-ID      # repeatable — every listed rule must NOT fire
//	  expect_evidence RULE-ID advisory    # rule must carry advisory evidence text
//	  reject_evidence RULE-ID char-filter # rule evidence must not contain text
//	  expect_review some.Concept          # repeatable — review concept must appear
//	  reject_review some.Concept          # repeatable — review concept must not appear
//	  bindings python                    # optional binding set to apply before label checks
//	  expect_label node-id custom.Source # graph binding label assertion
//	  reject_label node-id custom.Source # graph binding negative label assertion
//	  gitlink vendor/lib <sha>  # optional git submodule/gitlink fixture
//	  code
//	  ```
//	  class C { void f() { marker(); } }
//	  ```

type specFile struct {
	name string // explicit filename, or "" for the default snippet name
	code string
}

type evidenceSpec struct {
	ruleID string
	text   string
}

type confidenceSpec struct {
	ruleID string
	level  string
}

type gitlinkSpec struct {
	path string
	sha  string
}

type labelSpec struct {
	nodeID  string
	concept string
}

type vyqlSpec struct {
	name         string
	lang         string
	expect       []string
	reject       []string
	expectConf   []confidenceSpec
	expectEv     []evidenceSpec
	rejectEv     []evidenceSpec
	expectReview []string
	rejectReview []string
	bindingsTech string
	expectLabels []labelSpec
	rejectLabels []labelSpec
	profile      string     // optional threat-model profile (e.g. `profile library`); default = generic/auto
	files        []specFile // one or more code blocks (multi-file specs supported)
	gitlinks     []gitlinkSpec
	graphSrc     string // a `graph` block: an asset/identity graph (mutually exclusive with code)
	src          string // source spec filename (for messages)
	line         int
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
	// textpattern runs over any text file; `.env` keys on no real source frontend.
	"textpattern": ".env",
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
		case "profile":
			cur.profile = rest
		case "expect":
			cur.expect = append(cur.expect, rest)
		case "reject":
			cur.reject = append(cur.reject, rest)
		case "expect_confidence":
			cur.expectConf = append(cur.expectConf, parseConfidenceSpec(t, rel, i+1, rest))
		case "expect_evidence":
			cur.expectEv = append(cur.expectEv, parseEvidenceSpec(t, rel, i+1, rest))
		case "reject_evidence":
			cur.rejectEv = append(cur.rejectEv, parseEvidenceSpec(t, rel, i+1, rest))
		case "expect_review":
			cur.expectReview = append(cur.expectReview, rest)
		case "reject_review":
			cur.rejectReview = append(cur.rejectReview, rest)
		case "bindings":
			cur.bindingsTech = rest
		case "expect_label":
			cur.expectLabels = append(cur.expectLabels, parseLabelSpec(t, rel, i+1, rest))
		case "reject_label":
			cur.rejectLabels = append(cur.rejectLabels, parseLabelSpec(t, rel, i+1, rest))
		case "file":
			pendingFile = rest // next fence writes to this filename
		case "gitlink":
			cur.gitlinks = append(cur.gitlinks, parseGitlinkSpec(t, rel, i+1, rest))
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
	// A spec asserts what one definition detects, and it is written against the
	// engine of the moment. When the definitions are fetched, the bundle is cut
	// at a tag an operator chooses and the two versions move independently, so a
	// failure here says which side is newer rather than that anything is wrong.
	// Asserting them anyway would tie this repository's checks to release timing.
	//
	// They are run where the specs and the definitions are kept together, against
	// the engine they were written for. What this repository checks about a
	// fetched bundle is that it arrived whole and parses, in
	// TestFetchedCVESpecsArriveWhole.
	if !corpusIsVendored() {
		t.Skip("the definitions are fetched; their specs are run where they are kept")
	}
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
	decls, err := parser.ParseV2DefinitionSourcesSelected(v2DefinitionSourcesForRules(rules), lowerNonCoreV2DefinitionSource)
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

	specTempRoot := t.TempDir()
	total := 0
	for _, f := range files {
		for _, s := range parseSpecFile(t, f) {
			s := s
			total++
			specIndex := total
			t.Run(s.src+"/"+s.name, func(t *testing.T) {
				if len(s.expect) == 0 && len(s.reject) == 0 && len(s.expectEv) == 0 && len(s.rejectEv) == 0 &&
					len(s.expectReview) == 0 && len(s.rejectReview) == 0 && len(s.expectLabels) == 0 && len(s.rejectLabels) == 0 {
					t.Fatalf("%s:%d: spec has no expect/reject, review, or label assertion", s.src, s.line)
				}
				fired := map[string]bool{}
				confidence := map[string]string{}
				evidence := map[string][]string{}
				reviewed := map[string]bool{}
				if s.graphSrc != "" {
					// graph spec: build the asset/identity graph and evaluate the packs.
					store := buildGraphStore(t, s)
					if s.bindingsTech != "" {
						if _, _, err := bindings.Apply(store, bindings.BindingsFor(s.bindingsTech), nil); err != nil {
							t.Fatalf("apply %s bindings: %v", s.bindingsTech, err)
						}
					}
					eng := engine.New(onto, store)
					for _, cr := range compiled {
						got, err := eng.Evaluate(cr)
						if err != nil {
							t.Fatalf("evaluate: %v", err)
						}
						for _, fnd := range got {
							fired[fnd.RuleID] = true
							confidence[fnd.RuleID] = fnd.Confidence
							for _, ne := range fnd.NegationEvidence {
								evidence[fnd.RuleID] = append(evidence[fnd.RuleID], ne.Clause+" "+ne.Detail)
							}
							for _, ec := range fnd.ReviewConditions {
								evidence[fnd.RuleID] = append(evidence[fnd.RuleID], strings.Join([]string{
									ec.Category, ec.Condition, ec.Evidence, ec.Assumption, ec.Confidence,
								}, " "))
							}
						}
					}
					for _, row := range review.Collect(store) {
						reviewed[row.Concept] = true
					}
					assertLabelSpecs(t, store, s.expectLabels, true)
					assertLabelSpecs(t, store, s.rejectLabels, false)
				} else {
					// code spec: write the snippet(s) and scan as source.
					ext, ok := primaryExt[s.lang]
					if !ok {
						t.Fatalf("%s:%d: unknown lang %q", s.src, s.line, s.lang)
					}
					if len(s.files) == 0 {
						t.Fatalf("%s:%d: spec %q has no code or graph block", s.src, s.line, s.name)
					}
					dir := filepath.Join(specTempRoot, "spec-"+strconv.Itoa(specIndex))
					if err := os.MkdirAll(dir, 0o755); err != nil {
						t.Fatal(err)
					}
					for n, fl := range s.files {
						name := fl.name
						if name == "" {
							name = "snippet" + ext
							if n > 0 {
								name = "snippet" + strconv.Itoa(n) + ext
							}
						}
						dst := filepath.Join(dir, name)
						if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(dst, []byte(fl.code), 0o644); err != nil {
							t.Fatal(err)
						}
					}
					if len(s.gitlinks) > 0 {
						initGitlinks(t, dir, s.gitlinks)
					}
					// optional `profile` directive: set the trust boundary so profile-gated
					// sources are active for this spec.
					if s.profile != "" {
						applyProfile([]string{dir}, s.profile)
						defer bindings.SetActiveSources(nil)
					}
					found, _, scanGraph, err := scanPaths([]string{dir}, rules)
					if err != nil {
						t.Fatalf("scan: %v", err)
					}
					for _, fnd := range found {
						fired[fnd.RuleID] = true
						confidence[fnd.RuleID] = fnd.Confidence
						for _, ne := range fnd.NegationEvidence {
							evidence[fnd.RuleID] = append(evidence[fnd.RuleID], ne.Clause+" "+ne.Detail)
						}
						for _, ec := range fnd.ReviewConditions {
							evidence[fnd.RuleID] = append(evidence[fnd.RuleID], strings.Join([]string{
								ec.Category, ec.Condition, ec.Evidence, ec.Assumption, ec.Confidence,
							}, " "))
						}
						// Context carries what a finding reports beyond its bindings --
						// the advisory a dependency matched, and why. A spec has to be
						// able to assert on it, or that text can go missing unnoticed.
						evidence[fnd.RuleID] = append(evidence[fnd.RuleID], fnd.Context...)
					}
					if len(s.expectReview) > 0 || len(s.rejectReview) > 0 {
						for _, row := range review.Collect(scanGraph) {
							reviewed[row.Concept] = true
						}
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
				for _, want := range s.expectConf {
					if got := confidence[want.ruleID]; got != want.level {
						t.Errorf("expected rule %s confidence %q, got %q", want.ruleID, want.level, got)
					}
				}
				for _, want := range s.expectEv {
					if !evidenceContains(evidence[want.ruleID], want.text) {
						t.Errorf("expected rule %s evidence to contain %q, got %q", want.ruleID, want.text, strings.Join(evidence[want.ruleID], " | "))
					}
				}
				for _, no := range s.rejectEv {
					if evidenceContains(evidence[no.ruleID], no.text) {
						t.Errorf("rule %s evidence contained forbidden text %q: %q", no.ruleID, no.text, strings.Join(evidence[no.ruleID], " | "))
					}
				}
				for _, want := range s.expectReview {
					if !reviewed[want] {
						t.Errorf("expected review concept %s to appear, but it did not (reviewed: %s)", want, keys(reviewed))
					}
				}
				for _, no := range s.rejectReview {
					if reviewed[no] {
						t.Errorf("review concept %s appeared but should not have", no)
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

func parseEvidenceSpec(t *testing.T, src string, line int, rest string) evidenceSpec {
	t.Helper()
	ruleID, text, ok := strings.Cut(rest, " ")
	if !ok || strings.TrimSpace(ruleID) == "" || strings.TrimSpace(text) == "" {
		t.Fatalf("%s:%d: evidence assertion must be `expect_evidence <RULE> <text>`", src, line)
	}
	return evidenceSpec{ruleID: strings.TrimSpace(ruleID), text: normalizeEvidenceExpectation(strings.TrimSpace(text))}
}

func normalizeEvidenceExpectation(text string) string {
	return text
}

func parseConfidenceSpec(t *testing.T, src string, line int, rest string) confidenceSpec {
	t.Helper()
	ruleID, level, ok := strings.Cut(rest, " ")
	if !ok || strings.TrimSpace(ruleID) == "" || strings.TrimSpace(level) == "" {
		t.Fatalf("%s:%d: confidence assertion must be `expect_confidence <RULE> <level>`", src, line)
	}
	return confidenceSpec{ruleID: strings.TrimSpace(ruleID), level: strings.TrimSpace(level)}
}

func parseLabelSpec(t *testing.T, src string, line int, rest string) labelSpec {
	t.Helper()
	nodeID, concept, ok := strings.Cut(rest, " ")
	if !ok || strings.TrimSpace(nodeID) == "" || strings.TrimSpace(concept) == "" {
		t.Fatalf("%s:%d: label assertion must be `expect_label <node-id> <concept>`", src, line)
	}
	return labelSpec{nodeID: strings.TrimSpace(nodeID), concept: strings.TrimSpace(concept)}
}

func assertLabelSpecs(t *testing.T, store usg.Store, specs []labelSpec, want bool) {
	t.Helper()
	for _, spec := range specs {
		got, err := store.Labels(spec.nodeID)
		if err != nil {
			t.Fatalf("labels(%s): %v", spec.nodeID, err)
		}
		found := false
		for _, label := range got {
			if label.Concept == spec.concept {
				found = true
				break
			}
		}
		if want && !found {
			t.Errorf("expected node %s to have label %s; got %+v", spec.nodeID, spec.concept, got)
		}
		if !want && found {
			t.Errorf("expected node %s not to have label %s; got %+v", spec.nodeID, spec.concept, got)
		}
	}
}

func parseGitlinkSpec(t *testing.T, src string, line int, rest string) gitlinkSpec {
	t.Helper()
	path, sha, ok := strings.Cut(rest, " ")
	if !ok || strings.TrimSpace(path) == "" || strings.TrimSpace(sha) == "" {
		t.Fatalf("%s:%d: gitlink fixture must be `gitlink <path> <sha>`", src, line)
	}
	return gitlinkSpec{path: strings.TrimSpace(path), sha: strings.TrimSpace(sha)}
}

func initGitlinks(t *testing.T, dir string, gitlinks []gitlinkSpec) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "test@example.invalid")
	run("config", "user.name", "VyQL Test")
	run("add", ".")
	for _, gl := range gitlinks {
		run("update-index", "--add", "--cacheinfo", "160000,"+gl.sha+","+gl.path)
	}
	run("commit", "-q", "-m", "fixture")
}

func evidenceContains(items []string, text string) bool {
	text = strings.ToLower(text)
	for _, item := range items {
		if strings.Contains(strings.ToLower(item), text) {
			return true
		}
	}
	return false
}

func keys(m map[string]bool) string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return strings.Join(out, ", ")
}
