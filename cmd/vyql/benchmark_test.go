package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestOWASPBenchmark scores VyQL against an OWASP Benchmark suite (Java or Python) and
// prints a per-category Youden scorecard (TPR-FPR). Gated by VYQL_BENCH=1; the suite dir is
// $BENCH_DIR (default /tmp/bench/BenchmarkPython). This is a measurement harness, not a
// pass/fail gate — it drives the precision-tuning loop.
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
	// python layout: testcode/ + helpers/. java layout: src/main/java (testcode + helpers).
	candidates := [][]string{
		{filepath.Join(dir, "testcode"), filepath.Join(dir, "helpers")},
		// src/main (not just .../java) so bundled .properties under resources are read,
		// letting config-indirection reads like getProperty("hashAlg1") const-fold.
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
	fs, _, err := scanPaths(roots, rules)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// detected[testname][category] = VyQL reported that category in that test file.
	detected := map[string]map[string]bool{}
	for _, f := range fs {
		cat := ruleCategory[f.RuleID]
		if cat == "" {
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

	score(t, expected, detected)
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

// ruleCategory maps a VyQL rule id to its OWASP Benchmark category.
var ruleCategory = map[string]string{
	"VYQL-PATH-001":  "pathtraver",
	"VYQL-INJ-001":   "sqli",
	"VYQL-INJ-002":   "cmdi",
	"VYQL-INJ-003":   "codeinj",
	"VYQL-INJ-004":   "xss",
	"VYQL-INJ-005":   "ldapi",
	"VYQL-INJ-006":   "xpathi",
	"VYQL-CRY-001":   "hash",   // weak hash/digest (MD5/SHA1)
	"VYQL-CRY-002":   "crypto", // weak cipher (DES/RC4/ECB)
	"VYQL-CRY-003":   "weakrand",
	"VYQL-CFG-007":   "securecookie",
	"VYQL-RF-002":    "redirect",
	"VYQL-DESER-001": "deserialization",
	"VYQL-DESER-002": "xxe",
	"VYQL-CFG-014":   "trustbound",
}

func score(t *testing.T, expected map[string]expRow, detected map[string]map[string]bool) {
	type tally struct{ tp, fp, fn, tn int }
	cats := map[string]*tally{}
	get := func(c string) *tally {
		if cats[c] == nil {
			cats[c] = &tally{}
		}
		return cats[c]
	}
	dumpCat, dumpKind := os.Getenv("BENCH_DUMP_CAT"), os.Getenv("BENCH_DUMP_KIND") // e.g. sqli / fp
	var dumped []string
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
	}
	if dumpCat != "" {
		sort.Strings(dumped)
		fmt.Printf("\n%s %s (%d): %s\n", dumpCat, dumpKind, len(dumped), strings.Join(dumped, " "))
	}

	var names []string
	for c := range cats {
		names = append(names, c)
	}
	sort.Strings(names)
	var sumY float64
	var nCat int
	fmt.Printf("\n%-16s %5s %5s %5s %5s  %6s %6s  %7s\n", "category", "TP", "FN", "FP", "TN", "TPR", "FPR", "Youden")
	for _, c := range names {
		tl := cats[c]
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
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}
