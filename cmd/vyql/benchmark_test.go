package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/parser"
)

// TestOWASPBenchmark scores VyQL against an OWASP Benchmark suite and prints a
// per-category Youden scorecard (TPR-FPR). Gated by VYQL_BENCH=1; the suite dir
// is $BENCH_DIR (default /tmp/bench/BenchmarkPython). Protected suites also
// enforce the exact checked-in parity target.
func TestOWASPBenchmark(t *testing.T) {
	if os.Getenv("VYQL_BENCH") == "" {
		t.Skip("set VYQL_BENCH=1 to score against an OWASP Benchmark suite")
	}
	dir := os.Getenv("BENCH_DIR")
	if dir == "" {
		dir = "/tmp/bench/BenchmarkPython"
	}
	runOWASPBenchmarkDir(t, dir)
}

// TestLocalOWASPPortBenchmarks scores every generated local OWASP language port
// and enforces the exact protected parity target for each. It is intentionally
// opt-in because it scans 22 full benchmark corpora.
func TestLocalOWASPPortBenchmarks(t *testing.T) {
	if os.Getenv("VYQL_BENCH_ALL_OWASP") == "" {
		t.Skip("set VYQL_BENCH_ALL_OWASP=1 to score every /Users/rizqme/Workspace/owasp-* port")
	}
	for _, dir := range localOWASPPortDirs() {
		dir := dir
		t.Run(filepath.Base(dir), func(t *testing.T) {
			if _, err := os.Stat(dir); err != nil {
				t.Fatalf("local OWASP port %s is not available: %v", dir, err)
			}
			runOWASPBenchmarkDir(t, dir)
		})
	}
}

func runOWASPBenchmarkDir(t *testing.T, dir string) benchmarkScore {
	t.Helper()
	expected := loadExpected(t, dir)
	if len(expected) == 0 {
		t.Fatalf("no expectedresults*.csv found under %s", dir)
	}

	allRules, _ := loadRules("")
	rules := benchmarkRuleSources(allRules)
	ruleCategory := benchmarkCategories(t, rules)
	// python layout: testcode/ + helpers/. java layout: src/main/java (testcode + helpers).
	candidates := [][]string{
		{filepath.Join(dir, "testcode"), filepath.Join(dir, "helpers")},
		// src/main (not just .../java) so bundled .properties under resources are read,
		// letting config-indirection reads like getProperty("mode") const-fold.
		{filepath.Join(dir, "src", "main")},
		{filepath.Join(dir, "src")},
	}
	var roots []string
	for _, set := range candidates {
		var have []string
		for _, r := range set {
			if _, err := os.Stat(r); err == nil {
				have = append(have, r)
			}
		}
		if len(have) > 0 {
			roots = have
			break
		}
	}
	if len(roots) == 0 {
		roots = []string{dir}
	}
	restoreFast := setEnvForTest("VYQL_OWASP_BENCH_FAST", "1")
	defer restoreFast()
	fs, _, _, err := scanPathsWithProfileDemand(roots, rules, "", true)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// detected[testname][category] = VyQL reported that category in that test file.
	// With BENCH_CONFIDENT=1 only findings WITHOUT an advisory note count (the confident
	// bucket) — this measures "zero FP without advisory": every FP an unsound neutralizer
	// explains drops out, leaving the near-zero-FP confident scorecard.
	confidentOnly := os.Getenv("BENCH_CONFIDENT") != ""
	noteCat := os.Getenv("BENCH_NOTE_CAT") // print the advisory note of each noted finding in this category
	detected := map[string]map[string]bool{}
	for _, f := range fs {
		cat := ruleCategory[f.RuleID]
		if cat == "" {
			continue
		}
		if noteCat != "" && cat == noteCat && hasAdvisoryNote(f) {
			for _, ne := range f.NegationEvidence {
				if !ne.Satisfied && strings.Contains(ne.Clause, "advisory") {
					tn := ""
					if len(f.Bindings) > 0 {
						tn = testNameOf(f.Bindings[len(f.Bindings)-1].Loc)
					}
					fmt.Printf("NOTE %s [%s] %s\n", tn, ne.Clause, ne.Detail)
				}
			}
		}
		if confidentOnly && hasAdvisoryNote(f) {
			continue
		}
		for _, b := range f.Bindings {
			if tn := testNameOf(b.Loc); tn != "" {
				if detected[tn] == nil {
					detected[tn] = map[string]bool{}
				}
				detected[tn][cat] = true
			}
		}
	}

	gotScore := score(t, expected, detected)
	if want, ok := protectedOWASPBenchmarkExpectation(dir); ok {
		gotScore.assert(t, dir, want)
	}
	return gotScore
}

func setEnvForTest(key, value string) func() {
	old, had := os.LookupEnv(key)
	_ = os.Setenv(key, value)
	return func() {
		if had {
			_ = os.Setenv(key, old)
		} else {
			_ = os.Unsetenv(key)
		}
	}
}

func benchmarkRuleSources(rules []parser.V2DefinitionSource) []parser.V2DefinitionSource {
	out := make([]parser.V2DefinitionSource, 0, len(rules))
	for _, src := range rules {
		if strings.Contains(src.Source, "benchmark:") {
			out = append(out, src)
		}
	}
	return out
}

// hasAdvisoryNote reports whether a finding is advisory-gated — an unsound neutralizer
// (regex char-filter, prefix guard, unverifiable transform) lies on or dominates its flow.
func hasAdvisoryNote(f *findings.Finding) bool {
	for _, ne := range f.NegationEvidence {
		if !ne.Satisfied && strings.Contains(ne.Clause, "advisory") {
			return true
		}
	}
	return false
}

type expRow struct {
	category string
	real     bool
}

func loadExpected(t *testing.T, dir string) map[string]expRow {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join(dir, "expectedresults*.csv"))
	out := map[string]expRow{}
	for _, m := range matches {
		f, err := os.Open(m)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			c := strings.Split(line, ",")
			if len(c) < 3 {
				continue
			}
			out[c[0]] = expRow{category: c[1], real: c[2] == "true"}
		}
		f.Close()
	}
	return out
}

// testNameOf extracts "BenchmarkTest01234" from a finding loc like "BenchmarkTest01234.py:47".
func testNameOf(loc string) string {
	base := filepath.Base(loc)
	if i := strings.IndexAny(base, ".:"); i >= 0 {
		base = base[:i]
	}
	if strings.HasPrefix(base, "BenchmarkTest") {
		return base
	}
	return ""
}

func benchmarkCategories(t *testing.T, rules []parser.V2DefinitionSource) map[string]string {
	t.Helper()
	decls, err := parser.ParseV2DefinitionSourcesSelected(v2DefinitionSourcesForRules(rules), lowerNonCoreV2DefinitionSource)
	if err != nil {
		t.Fatalf("parse rules: %v", err)
	}
	out := map[string]string{}
	for _, d := range decls {
		r, ok := d.(*parser.Rule)
		if !ok {
			continue
		}
		id, _ := r.Meta["id"].(string)
		cat, _ := r.Meta["benchmark"].(string)
		if id != "" && cat != "" {
			out[id] = cat
		}
	}
	return out
}

type benchmarkScore struct {
	tp, fn, fp, tn int
	overall        float64
}

const benchmarkCountWildcard = -1

func (s benchmarkScore) assert(t *testing.T, dir string, want benchmarkScore) {
	t.Helper()
	matchesCount := func(got, expected int) bool {
		return expected == benchmarkCountWildcard || got == expected
	}
	if !matchesCount(s.tp, want.tp) || !matchesCount(s.fn, want.fn) || !matchesCount(s.fp, want.fp) || !matchesCount(s.tn, want.tn) || fmt.Sprintf("%+.2f", s.overall) != fmt.Sprintf("%+.2f", want.overall) {
		t.Fatalf("protected OWASP benchmark %s = TP=%d FN=%d FP=%d TN=%d overall=%+.2f; want TP=%d FN=%d FP=%d TN=%d overall=%+.2f",
			dir, s.tp, s.fn, s.fp, s.tn, s.overall, want.tp, want.fn, want.fp, want.tn, want.overall)
	}
}

func protectedOWASPBenchmarkExpectation(dir string) (benchmarkScore, bool) {
	base := filepath.Base(filepath.Clean(dir))
	switch {
	case base == "BenchmarkJava":
		return benchmarkScore{tp: 1415, fn: 0, fp: 0, tn: 1325, overall: 1.0}, true
	case base == "BenchmarkPython":
		// 452 is this corpus's true-positive count. The 1415 that stood here is
		// BenchmarkJava's, so the gate could never pass on any commit.
		return benchmarkScore{tp: 452, fn: 0, fp: benchmarkCountWildcard, tn: benchmarkCountWildcard, overall: 0.90}, true
	case base == "benchjs":
		return benchmarkScore{tp: 1415, fn: 0, fp: benchmarkCountWildcard, tn: benchmarkCountWildcard, overall: 0.78}, true
	case strings.HasPrefix(base, "owasp-") && filepath.Dir(filepath.Clean(dir)) == "/Users/rizqme/Workspace":
		return benchmarkScore{tp: 1415, fn: 0, fp: 0, tn: 1325, overall: 1.0}, true
	default:
		return benchmarkScore{}, false
	}
}

func localOWASPPortDirs() []string {
	ports := []string{
		"bash",
		"c",
		"cpp",
		"csharp",
		"dart",
		"elixir",
		"go",
		"groovy",
		"js",
		"kotlin",
		"lua",
		"objc",
		"perl",
		"php",
		"powershell",
		"python",
		"ruby",
		"rust",
		"scala",
		"solidity",
		"swift",
		"typescript",
	}
	out := make([]string, 0, len(ports))
	for _, port := range ports {
		out = append(out, filepath.Join("/Users/rizqme/Workspace", "owasp-"+port))
	}
	return out
}

func TestProtectedOWASPBenchmarkExpectation(t *testing.T) {
	tests := []struct {
		dir  string
		want benchmarkScore
		ok   bool
	}{
		{dir: "/Users/rizqme/Workspace/BenchmarkJava", want: benchmarkScore{tp: 1415, fn: 0, fp: 0, tn: 1325, overall: 1.0}, ok: true},
		{dir: "/Users/rizqme/Workspace/owasp-python", want: benchmarkScore{tp: 1415, fn: 0, fp: 0, tn: 1325, overall: 1.0}, ok: true},
		{dir: "/tmp/bench/BenchmarkJava", want: benchmarkScore{tp: 1415, fn: 0, fp: 0, tn: 1325, overall: 1.0}, ok: true},
		{dir: "/tmp/bench/BenchmarkPython", want: benchmarkScore{tp: 452, fn: 0, fp: benchmarkCountWildcard, tn: benchmarkCountWildcard, overall: 0.90}, ok: true},
		{dir: "/tmp/benchjs", want: benchmarkScore{tp: 1415, fn: 0, fp: benchmarkCountWildcard, tn: benchmarkCountWildcard, overall: 0.78}, ok: true},
		{dir: "/tmp/random-benchmark", ok: false},
	}
	for _, dir := range localOWASPPortDirs() {
		tests = append(tests, struct {
			dir  string
			want benchmarkScore
			ok   bool
		}{dir: dir, want: benchmarkScore{tp: 1415, fn: 0, fp: 0, tn: 1325, overall: 1.0}, ok: true})
	}
	for _, tt := range tests {
		got, ok := protectedOWASPBenchmarkExpectation(tt.dir)
		if ok != tt.ok {
			t.Fatalf("protectedOWASPBenchmarkExpectation(%q) ok = %v, want %v", tt.dir, ok, tt.ok)
		}
		if ok && got != tt.want {
			t.Fatalf("protectedOWASPBenchmarkExpectation(%q) = %+v, want %+v", tt.dir, got, tt.want)
		}
	}
}

func score(t *testing.T, expected map[string]expRow, detected map[string]map[string]bool) benchmarkScore {
	type tally struct{ tp, fp, fn, tn int }
	cats := map[string]*tally{}
	get := func(c string) *tally {
		if cats[c] == nil {
			cats[c] = &tally{}
		}
		return cats[c]
	}
	dumpCat, dumpKind := os.Getenv("BENCH_DUMP_CAT"), os.Getenv("BENCH_DUMP_KIND") // cat "all" dumps every category
	var dumped []string
	byCat := map[string][]string{} // for dumpCat=="all": category -> matching test names
	for name, e := range expected {
		got := detected[name][e.category]
		tl := get(e.category)
		var kind string
		switch {
		case e.real && got:
			tl.tp++
			kind = "tp"
		case e.real && !got:
			tl.fn++
			kind = "fn"
		case !e.real && got:
			tl.fp++
			kind = "fp"
		default:
			tl.tn++
			kind = "tn"
		}
		if e.category == dumpCat && kind == dumpKind {
			dumped = append(dumped, name)
		}
		if dumpCat == "all" && kind == dumpKind {
			byCat[e.category] = append(byCat[e.category], name)
		}
	}
	if dumpCat == "all" {
		var cs []string
		for c := range byCat {
			cs = append(cs, c)
		}
		sort.Strings(cs)
		for _, c := range cs {
			sort.Strings(byCat[c])
			fmt.Printf("\n%s %s (%d): %s\n", c, dumpKind, len(byCat[c]), strings.Join(byCat[c], " "))
		}
	} else if dumpCat != "" {
		sort.Strings(dumped)
		fmt.Printf("\n%s %s (%d): %s\n", dumpCat, dumpKind, len(dumped), strings.Join(dumped, " "))
	}

	var names []string
	for c := range cats {
		names = append(names, c)
	}
	sort.Strings(names)
	var total benchmarkScore
	var sumY float64
	var nCat int
	fmt.Printf("\n%-16s %5s %5s %5s %5s  %6s %6s  %7s\n", "category", "TP", "FN", "FP", "TN", "TPR", "FPR", "Youden")
	for _, c := range names {
		tl := cats[c]
		total.tp += tl.tp
		total.fn += tl.fn
		total.fp += tl.fp
		total.tn += tl.tn
		tpr := ratio(tl.tp, tl.tp+tl.fn)
		fpr := ratio(tl.fp, tl.fp+tl.tn)
		y := tpr - fpr
		sumY += y
		nCat++
		fmt.Printf("%-16s %5d %5d %5d %5d  %6.2f %6.2f  %+7.2f\n", c, tl.tp, tl.fn, tl.fp, tl.tn, tpr, fpr, y)
	}
	overall := 0.0
	if nCat > 0 {
		overall = sumY / float64(nCat)
	}
	fmt.Printf("%-16s %46s %+7.2f\n", "OVERALL (avg Youden)", "", overall)
	total.overall = overall
	return total
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}
