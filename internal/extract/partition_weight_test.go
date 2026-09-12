package extract

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend"
)

// A byte of Python lowers to about five JavaScript bytes of graph, and the
// partition planner weighs it so. Without the weight, a partition sized for the
// JavaScript corpus overflows the ceiling on the first dense-language partition
// it builds — the failure mode of a bounded scan that dies with no report.
func TestPlanPartitionsWeighsDenseLanguagesMore(t *testing.T) {
	dir := t.TempDir()
	jsDir := filepath.Join(dir, "js")
	pyDir := filepath.Join(dir, "py")
	if err := os.MkdirAll(jsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Same byte budget of source in each language.
	const n = 8
	for i := 0; i < n; i++ {
		body := "const express = require(\"express\");\n" // ~32B, claimed by the js frontend
		for j := 0; j < 60; j++ {
			body += "// filler line to give the planner something to weigh\n"
		}
		if err := os.WriteFile(filepath.Join(jsDir, name(i, ".js")), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pyDir, name(i, ".py")), []byte("#!/usr/bin/env python\nx = 1\n"+body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A limit half of the JavaScript bytes, so JavaScript partitions too: both
	// languages are compared under the same limit, and only the weight differs.
	var jsBytes int64
	filepath.WalkDir(jsDir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, e := d.Info(); e == nil {
				jsBytes += fi.Size()
			}
		}
		return nil
	})
	jsParts := PlanPartitions([]string{jsDir}, nil, jsBytes/2, jsBytes/4)
	if len(jsParts) < 2 {
		t.Fatalf("JavaScript plan returned %d partition(s), want several at this budget", len(jsParts))
	}
	pyParts := PlanPartitions([]string{pyDir}, nil, jsBytes/2, jsBytes/4)
	if len(pyParts) < 2*len(jsParts) {
		t.Errorf("Python plan returned %d partition(s) for the same bytes of source as JavaScript's %d; the dense language must partition more",
			len(pyParts), len(jsParts))
	}
	// Every file lands in exactly one partition, whatever it weighs.
	seen := map[string]bool{}
	for _, part := range pyParts {
		for p := range part {
			if seen[p] {
				t.Errorf("%s landed in two partitions", p)
			}
			seen[p] = true
		}
	}
	for i := 0; i < n; i++ {
		f := filepath.Join(pyDir, name(i, ".py"))
		if !seen[f] {
			t.Errorf("%s landed in no partition", f)
		}
	}
}

// The weights are measured, not guessed, and they only ever round in the safe
// direction: under-weighting is the direction that overflows a ceiling.
func TestGraphWeightsRoundUpAndDefaultToTheHeaviest(t *testing.T) {
	if got := frontend.GraphWeight("javascript"); got != 100 {
		t.Errorf("javascript weight = %d, want 100: it is the reference corpus", got)
	}
	if got := frontend.GraphWeight("python"); got < 470 {
		t.Errorf("python weight = %d, want at least the measured 1405/298 ≈ 471", got)
	}
	for _, lang := range frontend.Languages() {
		if got := frontend.GraphWeight(lang.Name); got < 100 {
			t.Errorf("%s weight = %d, want at least the JavaScript reference", lang.Name, got)
		}
	}
	// A language nobody has measured must not plan partitions as though it were
	// the sparsest measured language.
	if got := frontend.GraphWeight("a-language-added-tomorrow"); got != frontend.GraphWeight("python") {
		t.Errorf("unmeasured language weight = %d, want the heaviest measured (%d)",
			got, frontend.GraphWeight("python"))
	}
}

func name(i int, ext string) string {
	return "f" + string(rune('0'+i)) + ext
}
