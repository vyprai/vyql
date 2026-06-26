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
	expected := loadExpected(t, dir)
	if len(expected) == 0 {
		t.Fatalf("no expectedresults*.csv found under %s", dir)
	}

	rules, _ := loadRules("")
	ruleCategory := benchmarkCategories(t, rules)
	// python layout: testcode/ + helpers/. java layout: src/main/java (testcode + helpers).
	candidates := [][]string{
		{filepath.Join(dir, "testcode"), filepath.Join(dir, "helpers")},
		// src/main (not just .../java) so bundled .properties under resources are read,
		// letting config-indirection reads like getProperty("mode") const-fold.
		{filepath.Join(dir, "src", "main")},
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
	fs, _, _, err := scanPaths(roots, rules)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// detected[testname][category] = VyQL reported that category in that test file.
	// With BENCH_CONFIDENT=1 only findings WITHOUT an assumption note count (the confident
	// bucket) — this measures "zero FP without assumption": every FP an unsound neutralizer
	// explains drops out, leaving the near-zero-FP confident scorecard.
	confidentOnly := os.Getenv("BENCH_CONFIDENT") != ""
	noteCat := os.Getenv("BENCH_NOTE_CAT") // print the assumption note of each noted finding in this category
	detected := map[string]map[string]bool{}
	for _, f := range fs {
		cat := ruleCategory[f.RuleID]
		if cat == "" {
			continue
		}
		if noteCat != "" && cat == noteCat && hasAssumptionNote(f) {
			for _, ne := range f.NegationEvidence {
				if !ne.Satisfied && strings.Contains(ne.Clause, "assumption") {
					tn := ""
					if len(f.Bindings) > 0 {
						tn = testNameOf(f.Bindings[len(f.Bindings)-1].Loc)
					}
					fmt.Printf("NOTE %s [%s] %s\n", tn, ne.Clause, ne.Detail)
				}
			}
		}
		if confidentOnly && hasAssumptionNote(f) {
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
}

// hasAssumptionNote reports whether a finding is assumption-gated — an unsound neutralizer
// (regex char-filter, prefix guard, unverifiable transform) lies on or dominates its flow.
func hasAssumptionNote(f *findings.Finding) bool {
	for _, ne := range f.NegationEvidence {
		if !ne.Satisfied && strings.Contains(ne.Clause, "assumption") {
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

func benchmarkCategories(t *testing.T, rules string) map[string]string {
	t.Helper()
	decls, err := parser.ParseV2RuntimeSourcesSelected(v2RuntimeSourcesForRules(rules), lowerNonCoreV2RuntimeSource)
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

func (s benchmarkScore) assert(t *testing.T, dir string, want benchmarkScore) {
	t.Helper()
	if s.tp != want.tp || s.fn != want.fn || s.fp != want.fp || s.tn != want.tn || fmt.Sprintf("%+.2f", s.overall) != fmt.Sprintf("%+.2f", want.overall) {
		t.Fatalf("protected OWASP benchmark %s = TP=%d FN=%d FP=%d TN=%d overall=%+.2f; want TP=%d FN=%d FP=%d TN=%d overall=%+.2f",
			dir, s.tp, s.fn, s.fp, s.tn, s.overall, want.tp, want.fn, want.fp, want.tn, want.overall)
	}
}

func protectedOWASPBenchmarkExpectation(dir string) (benchmarkScore, bool) {
	base := filepath.Base(filepath.Clean(dir))
	switch {
	case base == "BenchmarkJava":
		return benchmarkScore{tp: 1415, fn: 0, fp: 0, tn: 1325, overall: 1.0}, true
	case strings.HasPrefix(base, "owasp-") && filepath.Dir(filepath.Clean(dir)) == "/Users/rizqme/Workspace":
		return benchmarkScore{tp: 1415, fn: 0, fp: 0, tn: 1325, overall: 1.0}, true
	default:
		return benchmarkScore{}, false
	}
}

func TestProtectedOWASPBenchmarkExpectation(t *testing.T) {
	for _, dir := range []string{
		"/Users/rizqme/Workspace/BenchmarkJava",
		"/Users/rizqme/Workspace/owasp-python",
		"/tmp/bench/BenchmarkJava",
	} {
		want := filepath.Base(dir) == "BenchmarkJava" || strings.HasPrefix(filepath.Base(dir), "owasp-")
		if _, ok := protectedOWASPBenchmarkExpectation(dir); ok != want {
			t.Fatalf("protectedOWASPBenchmarkExpectation(%q) = %v, want %v", dir, ok, want)
		}
	}
	if _, ok := protectedOWASPBenchmarkExpectation("/tmp/bench/BenchmarkPython"); ok {
		t.Fatal("ad-hoc BenchmarkPython should remain measurement-only")
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
