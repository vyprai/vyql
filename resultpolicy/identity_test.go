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
	flagKey := policy.FlagKeyFor(FlagIdentity{
		Concept:    "code.StructuredInputDecode",
		Location:   "app.go:10",
		CallPath:   "decode",
		CallMethod: "Decode",
		NodeID:     "node-1",
	})
	if flagKey != "concept=code.StructuredInputDecode|location=app.go:10|call.path=decode|call.method=Decode" {
		t.Fatalf("flag key = %q", flagKey)
	}
}

func TestConfidencePolicyFromV2Decl(t *testing.T) {
	prog, err := parser.ParseV2(`
module policies.core;
policy confidence default {
  values: [low, medium, high]
  order: [low, medium, high]
  aggregate: min(rule, endpoints, propagation, requirements)
  softRequirement missing: downgrade(1)
  softRequirement unknown: downgrade(1)
  softRequirement conflicting: downgrade(1)
  softRequirement satisfied: keep
}
`)
	if err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	policy, err := confidencePolicyFromDecl(prog.Decls[0].(*parser.V2PolicyDecl))
	if err != nil {
		t.Fatalf("confidencePolicyFromDecl: %v", err)
	}
	if policy.Rank("low") != 1 || policy.Rank("medium") != 2 || policy.Rank("high") != 3 {
		t.Fatalf("confidence ranks wrong: low=%d medium=%d high=%d", policy.Rank("low"), policy.Rank("medium"), policy.Rank("high"))
	}
	if policy.Name(1) != "low" || policy.Name(3) != "high" || policy.MaxRank() != 3 {
		t.Fatalf("confidence names/max wrong: name1=%q name3=%q max=%d", policy.Name(1), policy.Name(3), policy.MaxRank())
	}
}

func TestPriorityPolicyFromV2Decl(t *testing.T) {
	prog, err := parser.ParseV2(`
module policies.core;
policy priority default {
  score severity {
    critical: 4
    high: 3
    medium: 2
    low: 1
    info: 0
    default: 1
  }

  factor confidenceLow {
    when finding.confidence == low
    weight: -2
  }

  bands: [
    { band: "P0", min: 8 },
    { band: "P1", min: 6 }
  ]
}
`)
	if err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	policy, err := PriorityPolicyFromDecl(prog.Decls[0].(*parser.V2PolicyDecl))
	if err != nil {
		t.Fatalf("PriorityPolicyFromDecl: %v", err)
	}
	if policy.SeverityRank("critical") != 4 || policy.SeverityRank("medium") != 2 || policy.SeverityRank("info") != 0 {
		t.Fatalf("severity ranks wrong: critical=%d medium=%d info=%d", policy.SeverityRank("critical"), policy.SeverityRank("medium"), policy.SeverityRank("info"))
	}
	if policy.SeverityRank("custom") != 1 {
		t.Fatalf("default severity rank = %d, want 1", policy.SeverityRank("custom"))
	}
}

func TestLifecyclePolicyFromV2Decl(t *testing.T) {
	prog, err := parser.ParseV2(`
module policies.core;
policy resultLifecycle default {
  flagWhen: emitted(issue) and hasReview(concept)
  candidateWhen: matched(rule)
  findingWhen: candidate and not covered
  checkWhen: emitted(check) and (hasReview(concept) or explainsFinding)
}
`)
	if err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	policy, err := LifecyclePolicyFromDecl(prog.Decls[0].(*parser.V2PolicyDecl))
	if err != nil {
		t.Fatalf("LifecyclePolicyFromDecl: %v", err)
	}
	if !policy.FlagWhenIssue(true) || policy.FlagWhenIssue(false) {
		t.Fatalf("flag lifecycle predicate mismatch")
	}
	if !policy.CandidateWhenMatchedRule(true) || policy.CandidateWhenMatchedRule(false) {
		t.Fatalf("candidate lifecycle predicate mismatch")
	}
	if !policy.FindingWhen(true, false) || policy.FindingWhen(true, true) || policy.FindingWhen(false, false) {
		t.Fatalf("finding lifecycle predicate mismatch")
	}
	if !policy.CheckWhen(true, false) || !policy.CheckWhen(false, true) || policy.CheckWhen(false, false) {
		t.Fatalf("check lifecycle predicate mismatch")
	}
}

func TestLifecyclePolicyEvaluatesLoadedExpressions(t *testing.T) {
	policy := LifecyclePolicy{items: lifecycleDefaultExprs()}
	policy.items["flagWhen"] = parser.V2CallExpr{Name: "emitted", Args: []parser.V2Expr{parser.V2RefExpr{Name: "check"}}}
	if policy.FlagWhenIssue(true) {
		t.Fatal("flag lifecycle ignored loaded expression and treated emitted(check) as emitted(issue)")
	}
	policy.items["flagWhen"] = parser.V2LiteralExpr{Value: true}
	if !policy.FlagWhenIssue(false) {
		t.Fatal("flag lifecycle did not evaluate replacement literal expression")
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

func TestSortStringsLinearOrdersKeys(t *testing.T) {
	got := []string{
		"rule=R|loc=b.go:2|concept=code.SqlExecution",
		"rule=R|loc=a.go:10|concept=code.CommandExecution",
		"rule=R|loc=a.go:1|concept=code.CommandExecution",
		"",
		"rule=R|loc=a.go:1|concept=code.Asset",
	}
	sortStringsLinear(got)
	want := []string{
		"",
		"rule=R|loc=a.go:10|concept=code.CommandExecution",
		"rule=R|loc=a.go:1|concept=code.Asset",
		"rule=R|loc=a.go:1|concept=code.CommandExecution",
		"rule=R|loc=b.go:2|concept=code.SqlExecution",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sorted[%d] = %q, want %q (all=%v)", i, got[i], want[i], got)
		}
	}
}
