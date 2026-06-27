package resultpolicy

import (
	"testing"

	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/parser"
)

func TestIdentityPolicyFromV2Decl(t *testing.T) {
	prog, err := parser.ParseV2(`
module policies.core;
policy resultIdentity default {
  findingKey: [rule.id, primaryTarget.location, primaryTarget.concept]
  flagKey: [concept, location, call.path, call.method]
  fingerprint: [rule.id, primaryTarget.location, primaryTarget.concept]
  stableAcross: [formatting, requirementDiagnosticText, traversalOrder]
}
`)
	if err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	policy, err := identityPolicyFromDecl(prog.Decls[0].(*parser.V2PolicyDecl))
	if err != nil {
		t.Fatalf("identityPolicyFromDecl: %v", err)
	}
	f := &findings.Finding{
		RuleID: "VYQL-INJ-001",
		Bindings: []findings.Binding{
			{Name: "source", Concept: "code.HttpInput", Loc: "app.go:1"},
			{Name: "sink", Concept: "code.SqlExecution", Loc: "app.go:2"},
		},
	}
	fp := policy.FingerprintFinding(f)
	if len(fp) != 16 {
		t.Fatalf("fingerprint = %q, want 16 hex chars", fp)
	}
	sameSource := &findings.Finding{
		RuleID: "VYQL-INJ-001",
		Bindings: []findings.Binding{
			{Name: "source", Concept: "code.HttpInput", Loc: "other.go:99"},
			{Name: "sink", Concept: "code.SqlExecution", Loc: "app.go:2"},
		},
	}
	if got := policy.FingerprintFinding(sameSource); got != fp {
		t.Fatalf("source location changed policy fingerprint: %s vs %s", got, fp)
	}
	differentSinkConcept := &findings.Finding{
		RuleID: "VYQL-INJ-001",
		Bindings: []findings.Binding{
			{Name: "source", Concept: "code.HttpInput", Loc: "app.go:1"},
			{Name: "sink", Concept: "code.CommandExecution", Loc: "app.go:2"},
		},
	}
	if got := policy.FingerprintFinding(differentSinkConcept); got == fp {
		t.Fatalf("target concept did not affect policy fingerprint: %s", got)
	}
}

func TestIdentityPolicyDedupUsesFindingKey(t *testing.T) {
	policy := IdentityPolicy{
		FindingKey:  []string{"rule.id", "primaryTarget.location", "primaryTarget.concept"},
		Fingerprint: []string{"rule.id", "primaryTarget.location", "primaryTarget.concept"},
		FlagKey:     []string{"concept", "location"},
	}
	a := &findings.Finding{RuleID: "R", Bindings: []findings.Binding{{Name: "source", Loc: "a.go:1"}, {Name: "sink", Concept: "code.SqlExecution", Loc: "b.go:2"}}}
	b := &findings.Finding{RuleID: "R", Bindings: []findings.Binding{{Name: "source", Loc: "z.go:9"}, {Name: "sink", Concept: "code.SqlExecution", Loc: "b.go:2"}}}
	c := &findings.Finding{RuleID: "R", Bindings: []findings.Binding{{Name: "sink", Concept: "code.CommandExecution", Loc: "b.go:2"}}}
	got := policy.Dedup([]*findings.Finding{a, b, c})
	if len(got) != 2 {
		t.Fatalf("dedup size = %d, want 2", len(got))
	}
}

func TestIdentityPolicyDedupIsCanonical(t *testing.T) {
	policy := IdentityPolicy{
		FindingKey:  []string{"rule.id", "primaryTarget.location", "primaryTarget.concept"},
		Fingerprint: []string{"rule.id", "primaryTarget.location", "primaryTarget.concept"},
		FlagKey:     []string{"concept", "location"},
	}
	low := &findings.Finding{
		RuleID:     "R",
		Severity:   "medium",
		Confidence: "low",
		Bindings: []findings.Binding{
			{Name: "source", Concept: "code.HttpInput", Loc: "z.go:9", NodeID: "z"},
			{Name: "sink", Concept: "code.SqlExecution", Loc: "b.go:2", NodeID: "sink2"},
		},
	}
	high := &findings.Finding{
		RuleID:      "R",
		Severity:    "high",
		Confidence:  "high",
		Witness:     []string{"source", "mid", "sink"},
		Context:     []string{"ctx"},
		Bindings:    low.Bindings,
		PathLocs:    []string{"z.go:9", "b.go:2"},
		WitnessKind: "taint",
	}
	other := &findings.Finding{
		RuleID:     "R",
		Severity:   "low",
		Confidence: "medium",
		Bindings: []findings.Binding{
			{Name: "sink", Concept: "code.CommandExecution", Loc: "a.go:1", NodeID: "cmd"},
		},
	}

	gotA := policy.Dedup([]*findings.Finding{low, other, high})
	gotB := policy.Dedup([]*findings.Finding{high, low, other})
	if len(gotA) != 2 || len(gotB) != 2 {
		t.Fatalf("dedup sizes = %d/%d, want 2/2", len(gotA), len(gotB))
	}
	if gotA[0] != other || gotB[0] != other {
		t.Fatalf("dedup order should be canonical by finding key: gotA=%#v gotB=%#v", gotA[0], gotB[0])
	}
	if gotA[1] != high || gotB[1] != high {
		t.Fatalf("dedup survivor should be canonical high-evidence finding: gotA=%#v gotB=%#v", gotA[1], gotB[1])
	}
}
