package vyql

import (
	"strings"
	"testing"
)

func buildGraph(t *testing.T, src string) *DepGraph {
	t.Helper()
	f, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return BuildDepGraph([]*File{f})
}

func TestStratifyOrdersNegationAfterItsTarget(t *testing.T) {
	g := buildGraph(t, `module toy;
query q1(x) { match (x: A) yield x }
rule R2 { meta { id: "R2" } match (x: A) where not q1(x) -> signal }
rule R3 { meta { id: "R3" } present C -> finding unless sanitized_by code.SqlParameterization }
`)
	strata, err := Stratify(g)
	if err != nil {
		t.Fatalf("Stratify: %v", err)
	}
	stratumOf := func(name string) int {
		for i, str := range strata {
			for _, n := range str {
				if n == name {
					return i
				}
			}
		}
		t.Fatalf("predicate %q not found in strata %v", name, strata)
		return -1
	}
	if stratumOf("q1") >= stratumOf("R2") {
		t.Fatalf("q1 (stratum %d) must precede R2 (stratum %d): %v",
			stratumOf("q1"), stratumOf("R2"), strata)
	}
	dis := "sanitized_by:code.SqlParameterization"
	if stratumOf(dis) >= stratumOf("R3") {
		t.Fatalf("discharge %q must precede R3: %v", dis, strata)
	}
}

func TestStratifyAllowsPositiveRecursion(t *testing.T) {
	g := buildGraph(t, `module toy;
query q1(x) { match (x: A) where q2(x) yield x }
query q2(y) { match (y: A) where q1(y) yield y }
`)
	strata, err := Stratify(g)
	if err != nil {
		t.Fatalf("positive recursion must be allowed: %v", err)
	}
	stratumOf := func(name string) int {
		for i, str := range strata {
			for _, n := range str {
				if n == name {
					return i
				}
			}
		}
		return -1
	}
	if stratumOf("q1") != stratumOf("q2") {
		t.Fatalf("mutually positive queries must share a stratum: %v", strata)
	}
}

func TestStratifyRejectsCycleThroughNegation(t *testing.T) {
	g := buildGraph(t, `module toy;
query q1(x) { match (x: A) where not q2(x) yield x }
query q2(y) { match (y: A) where q1(y) yield y }
`)
	_, err := Stratify(g)
	if err == nil {
		t.Fatal("a cycle through a negative edge must be a compile error")
	}
	for _, want := range []string{"q1", "q2"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

func TestStratifyRejectsSelfNegation(t *testing.T) {
	g := buildGraph(t, `module toy;
query q1(x) { match (x: A) where not q1(x) yield x }
`)
	_, err := Stratify(g)
	if err == nil {
		t.Fatal("self-negation must be a compile error")
	}
	if !strings.Contains(err.Error(), "q1") {
		t.Errorf("error %q does not name the cycle", err)
	}
}
