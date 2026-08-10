package parser

import (
	"strings"
	"testing"
)

func TestParseV2DefinitionsRejectsAuthoredFlowRuleVerb(t *testing.T) {
	_, err := ParseV2Definitions(`
module rules.test;
rule CustomFlow {
  flow code.HttpInput -> code.SqlExecution
}
`)
	if err == nil || !strings.Contains(err.Error(), `unknown v2 rule verb "flow"`) {
		t.Fatalf("ParseV2Definitions error = %v, want authored flow rejection", err)
	}
}

func TestV2CoversV1RuleCapabilityLedger(t *testing.T) {
	decls := parseIRFiles(t, `
module rules.v1capability;
rule TaintRule {
  taint code.HttpInput as input -> code.SqlExecution as sink
  where sink is code.SqlExecution and input != sink
  unless sink.path coveredBy core.SqlParameterization
  with confidence >= high
}
rule IssueRule {
  issue code.WeakCipher as cipher
  unless cipher.global coveredBy core.CryptoPolicy
}
rule FactRule {
  fact runtime.HttpRequest as req
  where req in [runtime.HttpRequest, runtime.Connection]
}
rule ReachRule {
  reach cloud.Internet -> cloud.Database
  unless cloud.Database.endpoint coveredBy core.NetworkPolicy
}
rule GrantRule {
  grant cloud.User -> cloud.AdminPrivilege
  unless cloud.AdminPrivilege.sameScope coveredBy core.LeastPrivilege
}
rule DominatesRule {
  issue code.OwnerFieldClear as clear
  unless clear.dominates coveredBy core.ResourceRelease
}
rule PostDominatesRule {
  issue code.LockAcquire as lock
  unless lock.postDominates coveredBy core.LockRelease
}
rule SameReceiverRule {
  taint code.HttpInput as input -> code.FilePathAccess as sink
  unless sink.sameReceiver coveredBy core.PathCanonicalization
}
`)
	seenVerbs := map[string]bool{}
	seenCoverage := map[string]bool{}
	for _, d := range decls {
		r, ok := d.(*Rule)
		if !ok {
			continue
		}
		switch body := r.Body.(type) {
		case *FlowStmt:
			seenVerbs[body.Verb] = true
		case *MatchStmt:
			switch r.Name {
			case "IssueRule":
				seenVerbs["issue"] = true
			case "FactRule":
				seenVerbs["fact"] = true
			}
		}
		for _, cl := range r.Clauses {
			switch cl.Unless.(type) {
			case PathCoveredBy:
				seenCoverage["path"] = true
			case EndpointCoveredBy:
				seenCoverage["endpoint"] = true
			case SameReceiverCoveredBy:
				seenCoverage["sameReceiver"] = true
			case SameScopeCoveredBy:
				seenCoverage["sameScope"] = true
			case GlobalCoveredBy:
				seenCoverage["global"] = true
			case DominatesCoveredBy:
				seenCoverage["dominates"] = true
			case PostDominatesCoveredBy:
				seenCoverage["postDominates"] = true
			}
		}
	}
	for _, verb := range []string{"taint", "reach", "grant", "issue", "fact"} {
		if !seenVerbs[verb] {
			t.Fatalf("v1 rule capability ledger missing verb %s in %+v", verb, seenVerbs)
		}
	}
	for _, coverage := range []string{"path", "endpoint", "sameReceiver", "sameScope", "global", "dominates", "postDominates"} {
		if !seenCoverage[coverage] {
			t.Fatalf("v1 rule capability ledger missing coverage %s in %+v", coverage, seenCoverage)
		}
	}
}

func TestLowerV2DefinitionSourcesValidatesCorpus(t *testing.T) {
	rules, err := ParseV2(`
module rules.test;
rule IssueAsFlow {
  issue code.HttpInput as input
}
`)
	if err != nil {
		t.Fatalf("ParseV2 rules: %v", err)
	}
	_, err = LowerV2DefinitionSources([]V2Source{
		{Name: "mechanics.vyql", Program: &V2Program{
			Module: "mechanics.test",
			Decls: []V2Decl{
				&V2MechanicDecl{Kind: "ruleVerb", Name: "issue"},
			},
		}},
		{Name: "rules.vyql", Program: rules},
	})
	if err == nil || !strings.Contains(err.Error(), `duplicate v2 mechanic ruleVerb.issue; first declared in <builtin>`) {
		t.Fatalf("LowerV2DefinitionSources error = %v, want built-in mechanic reservation diagnostic", err)
	}
}

func TestV2DefinitionSourcesFromTextPreservesSingleSource(t *testing.T) {
	src := "module one;\nconcept A : source {}\n\n  module two;\nconcept B : sink {}\n"
	got := V2DefinitionSourcesFromText("inline.vyql", src)
	if len(got) != 1 {
		t.Fatalf("source count = %d, want 1", len(got))
	}
	if got[0].Name != "inline.vyql" || got[0].Source != src {
		t.Fatalf("source = %#v, want original text and name", got[0])
	}
	_, err := ParseV2(got[0].Source)
	if err == nil || !strings.Contains(err.Error(), "module declaration must appear once") {
		t.Fatalf("ParseV2 error = %v, want duplicate module rejection", err)
	}
}

func TestParseV2DefinitionSourcesValidatesCorpus(t *testing.T) {
	_, err := ParseV2DefinitionSources([]V2DefinitionSource{
		{Name: "code.vyql", Source: `
module code;
concept Problem : issue {}
`},
		{Name: "core.vyql", Source: `
module core;
concept Guard : check { covers: [path] }
`},
		{Name: "rules.vyql", Source: `
module rules.test;
rule BadCoverage {
  issue code.Problem as p
  unless p.endpoint coveredBy core.Guard
}
`},
	})
	if err == nil || !strings.Contains(err.Error(), `coverage mode "endpoint" not declared in concept covers [path]`) {
		t.Fatalf("ParseV2DefinitionSources error = %v, want corpus coverage validation", err)
	}
}

func TestParseV2DefinitionSourcesSelectedLowersOnlySelectedSources(t *testing.T) {
	decls, err := ParseV2DefinitionSourcesSelected([]V2DefinitionSource{
		{Name: "code.vyql", Source: `
module code;
concept HttpInput : source {}
concept SqlExecution : sink {}
`},
		{Name: "rules.vyql", Source: `
module rules.test;
rule SelectedOnly {
  taint code.HttpInput -> code.SqlExecution
}
`},
	}, func(src V2DefinitionSource) bool {
		return src.Name == "rules.vyql"
	})
	if err != nil {
		t.Fatalf("ParseV2DefinitionSourcesSelected: %v", err)
	}
	if len(decls) != 1 {
		t.Fatalf("decl count = %d, want only selected rule decl: %+v", len(decls), decls)
	}
	if _, ok := decls[0].(*Rule); !ok {
		t.Fatalf("decl = %T, want *Rule", decls[0])
	}
}

func TestV2ScannerIRPreservesPolicies(t *testing.T) {
	decls, err := ParseV2Definitions(`
module mechanics.sast;
policy resultIdentity default {
  findingKey: [rule.id, primaryTarget.location, primaryTarget.concept]
  flagKey: [concept, location, call.path, call.method]
  fingerprint: [rule.id, primaryTarget.location, primaryTarget.concept]
  stableAcross: [formatting, requirementDiagnosticText, traversalOrder]
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	if len(decls) != 1 {
		t.Fatalf("decls = %d, want policy: %+v", len(decls), decls)
	}
	policy, ok := decls[0].(*V2PolicyDecl)
	if !ok {
		t.Fatalf("decl[0] = %T, want *V2PolicyDecl", decls[0])
	}
	if policy.Module != "mechanics.sast" || policy.Kind != "resultIdentity" || policy.Name != "default" {
		t.Fatalf("policy identity wrong: %+v", policy)
	}
	if got := policy.QualifiedName(); got != "mechanics.sast.policy:resultIdentity:default" {
		t.Fatalf("policy qualified name = %q", got)
	}
}

func TestParseV2DefinitionSourcesSelectedPreservesSelectedPolicies(t *testing.T) {
	decls, err := ParseV2DefinitionSourcesSelected([]V2DefinitionSource{
		{Name: "policy.vyql", Source: `
module policies.default;
policy display default {
  scanAll: [findings, flags, checks, advisoryEvidence, requirementDiagnostics]
  flagSort: [severity, category, location, concept]
  includeNearbyChecks: true
  nearbyCheckLimit: 5
}
`},
		{Name: "code.vyql", Source: `
module code;
concept HttpInput : source {}
concept SqlExecution : sink {}
`},
		{Name: "rules.vyql", Source: `
module rules.test;
rule SelectedOnly {
  taint code.HttpInput -> code.SqlExecution
}
`},
	}, func(src V2DefinitionSource) bool {
		return src.Name == "policy.vyql"
	})
	if err != nil {
		t.Fatalf("ParseV2DefinitionSourcesSelected: %v", err)
	}
	if len(decls) != 1 {
		t.Fatalf("decls = %d, want selected policy: %+v", len(decls), decls)
	}
	if _, ok := decls[0].(*V2PolicyDecl); !ok {
		t.Fatalf("decl[0] = %T, want *V2PolicyDecl", decls[0])
	}
}

func TestV2BindingTechnologyScansModuleSegments(t *testing.T) {
	cases := map[string]string{
		"bindings.javascript.express":      "javascript",
		"stdlib.bindings.python.dbapi":     "python",
		"stdlib.notbindings.python.dbapi":  "",
		"stdlib.bindings":                  "",
		"stdlib.bindings.typescript.react": "typescript",
	}
	for module, want := range cases {
		if got := V2BindingTechnology(module); got != want {
			t.Fatalf("V2BindingTechnology(%q) = %q, want %q", module, got, want)
		}
	}
}

func TestV2LoweringRejectsLegacyHasWhereCall(t *testing.T) {
	_, err := parseV2DefinitionsForTest(`
module rules.legacy;
rule LegacyHas {
  issue runtime.Connection as c
  where has(c.dst, threat.MiningPool)
}
`)
	if err == nil || !strings.Contains(err.Error(), `unsupported call "has"`) {
		t.Fatalf("ParseV2Definitions error = %v, want unsupported has diagnostic", err)
	}
}

func TestV2LoweringSupportsSameReceiverCoveredBy(t *testing.T) {
	decls := parseV2DefinitionsWithCoreMechanics(t, `
module rules.aliases;
rule SameReceiverCoverage {
  taint code.HttpInput as input -> code.SqlExecution as sink
  unless sink.sameReceiver coveredBy core.SqlParameterization
}
`)
	rule := decls[0].(*Rule)
	if _, ok := rule.Clauses[0].Unless.(SameReceiverCoveredBy); !ok {
		t.Fatalf("sameReceiver coveredBy did not preserve coverage mode: %+v", rule.Clauses[0])
	}
}

func TestV2LoweringUsesBuiltinCoverageMechanicForCoveredBy(t *testing.T) {
	decls := parseV2DefinitionsWithCoreMechanics(t, `
module rules.review;
rule GuardedIssue {
  issue code.Problem as p
  unless p.path coveredBy core.Guard
}
`)
	rule := decls[0].(*Rule)
	if _, ok := rule.Clauses[0].Unless.(PathCoveredBy); !ok {
		t.Fatalf("path coveredBy did not lower with builtin coverage mechanic: %+v", rule.Clauses[0])
	}
}

func TestParseV2DefinitionsLowersPackDeclarations(t *testing.T) {
	decls, err := ParseV2Definitions(`
module packs.web;
pack webSecurity {
  includes: [profile web, pack base, rules.injection.SqlInjection]
  excludes: [rules.experimental.NoisyRule]
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	if len(decls) != 1 {
		t.Fatalf("decls = %d, want 1", len(decls))
	}
	pack, ok := decls[0].(*PackDecl)
	if !ok {
		t.Fatalf("decl = %T, want *PackDecl", decls[0])
	}
	if pack.Name != "webSecurity" {
		t.Fatalf("pack name = %q, want webSecurity", pack.Name)
	}
	if got := pack.Fields["includes"]; !stringListFieldEqual(got, []string{"profile.web", "pack.base", "rules.injection.SqlInjection"}) {
		t.Fatalf("pack includes = %#v", got)
	}
	if got := pack.Fields["excludes"]; !stringListFieldEqual(got, []string{"rules.experimental.NoisyRule"}) {
		t.Fatalf("pack excludes = %#v", got)
	}
}

// A standalone matcher is accepted and produces no scanner IR of its own. It is carried
// through the declaration stream instead, because a matcher is a named value test that only
// presence bindings use, and the binding compiler resolves it there.
func TestParseV2DefinitionsAllowsStandaloneMatcherDeclarations(t *testing.T) {
	decls, err := ParseV2Definitions(`
module patterns.javascript;
matcher secretTokenName {
  containsAny: ["token", "secret"]
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	if len(decls) != 1 {
		t.Fatalf("decls = %+v, want the matcher declaration alone", decls)
	}
	m, ok := decls[0].(*V2MatcherDecl)
	if !ok || m.Name != "secretTokenName" {
		t.Fatalf("decls[0] = %+v, want the secretTokenName matcher", decls[0])
	}
}

func TestParseV2DefinitionsRejectsConcatenatedV2Modules(t *testing.T) {
	_, err := ParseV2Definitions(`
module rules.one;
rule One {
  issue code.First as first
}

module rules.two;
rule Two {
  issue code.Second as second
}
`)
	if err == nil || !strings.Contains(err.Error(), "module declaration must appear once") {
		t.Fatalf("ParseV2Definitions multi-module error = %v, want one-module rejection", err)
	}
}

func TestV2UnstablePrivateGuardRejected(t *testing.T) {
	_, err := ParseV2Definitions(`
module bindings.java.rejection;
binding containmentCheck {
  unstable: {
    owner: "test"
    reason: "obsolete private query family should not lower"
  }
  query unstable.privateGuard as call where call.path == "analysis.guard.containment_check"
  emit check core.InputValidation at call {
    advisory: true
    about: code.FilePathAccess
    covers dominates {
      from: call
      to: call
    }
  }
}
`)
	if err == nil {
		t.Fatal("ParseV2Definitions succeeded for unstable.privateGuard")
	}
	if !strings.Contains(err.Error(), `unsupported unstable query family "unstable.privateGuard"`) {
		t.Fatalf("ParseV2Definitions error = %v", err)
	}
}

func TestV2RuleWhereLowering(t *testing.T) {
	decls := parseV2DefinitionsWithCoreMechanics(t, `
module rules.migrated;
rule ToxicWorkloadExposure {
  issue identity.WorkloadIdentity as w
  where reach(cloud.Internet, w.workload) and grant(w, identity.AdminPrivilege)
}
rule PublicSensitiveDatabase {
  reach cloud.Internet -> cloud.Database
  where holdsAssetKind(cloud.Database, [data.Pii])
}
rule CryptoMiningEgress {
  query concept as c where c.concept == runtime.Connection
    references concept as dst where dst.concept == threat.MiningPool and dst.id == c.dst
    select c
}
rule WorkloadDrift {
  issue runtime.Process as p
  where p.image not in [nginx, redis, postgres]
}
rule Confidence {
  issue code.Review as r
  where r.confidence == high
}
rule ReviewOrSecret {
  issue code.Review as r
  where r.category == review or r.category == secret
}
rule NumericScore {
  issue code.Review as r
  where r.score >= 7
}
`)
	if len(decls) != 7 {
		t.Fatalf("decls = %d, want 7", len(decls))
	}
	toxic := decls[0].(*Rule)
	and, ok := toxic.Clauses[0].Where.(And)
	if !ok || len(and.Parts) != 2 {
		t.Fatalf("toxic where = %#v, want two-part And", toxic.Clauses[0].Where)
	}
	if sc, ok := and.Parts[0].(SolverCall); !ok || sc.Verb != "reach" || len(sc.Args) != 2 {
		t.Fatalf("first toxic where part = %#v, want reach solver call", and.Parts[0])
	}
	asset := decls[1].(*Rule)
	if got, ok := asset.Clauses[0].Where.(HoldsAssetKind); !ok || got.Ref.String() != "cloud.Database" || len(got.Kinds) != 1 || got.Kinds[0] != "data.Pii" {
		t.Fatalf("asset where = %#v, want HoldsAssetKind", asset.Clauses[0].Where)
	}
	irRule := decls[2].(*Rule).Body.(*MatchStmt)
	if irRule.TargetKind != "concept" || irRule.Concept != "runtime.Connection" || irRule.Binding != "c" || irRule.Relation != "references" || irRule.RelationProp != "dst" || irRule.RelatedConcept != "threat.MiningPool" {
		t.Fatalf("semantic reference query lowering wrong: %+v", irRule)
	}
	drift := decls[3].(*Rule)
	if got, ok := drift.Clauses[0].Where.(NotIn); !ok || got.Ref.String() != "p.image" || !got.Negate || len(got.Values) != 3 {
		t.Fatalf("drift where = %#v, want NotIn", drift.Clauses[0].Where)
	}
	conf := decls[4].(*Rule)
	if got, ok := conf.Clauses[0].Where.(Cmp); !ok || got.Ref.String() != "r.confidence" || got.Op != "==" || got.Value != "high" {
		t.Fatalf("confidence where = %#v, want Cmp", conf.Clauses[0].Where)
	}
	disj := decls[5].(*Rule)
	or, ok := disj.Clauses[0].Where.(Or)
	if !ok || len(or.Parts) != 2 {
		t.Fatalf("or where = %#v, want two-part Or", disj.Clauses[0].Where)
	}
	numeric := decls[6].(*Rule)
	if got, ok := numeric.Clauses[0].Where.(Cmp); !ok || got.Ref.String() != "r.score" || got.Op != ">=" || got.Value != 7 {
		t.Fatalf("numeric where = %#v, want integer comparison", numeric.Clauses[0].Where)
	}
}

func TestV2RuleConfidenceClauseLowersToScannerIRFloor(t *testing.T) {
	decls := parseV2DefinitionsWithCoreMechanics(t, `
module rules.review;
rule HighConfidenceReview {
  issue code.Review as r
  with confidence >= high
}
`)
	rule := decls[0].(*Rule)
	if got := rule.Meta["confidence_floor"]; got != "high" {
		t.Fatalf("confidence floor = %#v, want high", got)
	}
}

func TestV2RuleConfidenceClauseRequiresLoadedConfidencePolicy(t *testing.T) {
	_, err := parseV2DefinitionSourcesForTest([]V2DefinitionSource{
		{Name: "policies/empty.vyql", Source: `module policies.empty;`},
		{Name: "rules/review.vyql", Source: `module rules.review;
rule HighConfidenceReview {
  issue code.Review as r
  with confidence >= high
}
`},
	})
	if err == nil {
		t.Fatal("ParseV2Definitions succeeded, want missing confidence policy diagnostic")
	}
	if !strings.Contains(err.Error(), "no loaded policy confidence default") {
		t.Fatalf("error = %v, want confidence policy diagnostic", err)
	}
}

func TestV2RuleConfidenceMetadataRequiresLoadedConfidencePolicy(t *testing.T) {
	_, err := parseV2DefinitionSourcesForTest([]V2DefinitionSource{
		{Name: "policies/empty.vyql", Source: `module policies.empty;`},
		{Name: "rules/review.vyql", Source: `module rules.review;
rule HighConfidenceReview {
  meta { confidenceFloor: high }
  issue code.Review as r
}
`},
	})
	if err == nil {
		t.Fatal("ParseV2Definitions succeeded, want missing confidence policy diagnostic")
	}
	if !strings.Contains(err.Error(), "no loaded policy confidence default") {
		t.Fatalf("error = %v, want confidence policy diagnostic", err)
	}
}

func TestV2RuleConfidenceMetadataLowersToScannerIRFloor(t *testing.T) {
	decls := parseV2DefinitionsWithCoreMechanics(t, `
module rules.review;
rule HighConfidenceReview {
  meta { confidenceFloor: high }
  issue code.Review as r
}
`)
	rule := decls[0].(*Rule)
	if got := rule.Meta["confidence_floor"]; got != "high" {
		t.Fatalf("confidence floor = %#v, want high", got)
	}
}

func TestV2RawSemanticQueryLowering(t *testing.T) {
	decls := parseV2DefinitionsWithCoreMechanics(t, `
module rules.migrated;
rule FileToctou {
  query concept as first where first.concept == code.FileCheck reaches concept as second where second.concept == code.FileUse select second
}

rule LateralReachToSecretStore {
  query principal as actor where actor.concept == cloud.ExternalPrincipal
    reaches asset as store where store.concept == cloud.SecretStore
    select store
}

rule InvalidRefundTransition {
  query state as t where t.machine == Order and t.from == "*" and t.to == Refunded select t
}

rule StateReachability {
  query state as start where start.concept == workflow.Open
    reaches state as done where done.concept == workflow.Closed
    select done
}

rule ReachableVulnerableDependency {
  query concept as p where p.concept == sbom.VulnerableDependency
    labeledAs concept as reachable where reachable.concept == sbom.ReachableSymbol
    select p
}

rule CryptoMiningEgress {
  query concept as c where c.concept == runtime.Connection
    references concept as dst where dst.concept == threat.MiningPool and dst.id == c.dst
    select c
}
`)
	order := decls[0].(*Rule).Body.(*OrderStmt)
	if order.First.Concept != "code.FileCheck" || order.First.Binding != "first" || order.Second.Concept != "code.FileUse" || order.Second.Binding != "second" {
		t.Fatalf("concept order lowering wrong: %+v", order)
	}
	reach := decls[1].(*Rule).Body.(*FlowStmt)
	if reach.Verb != "reach" || !reach.SemanticQuery || reach.Src.Concept != "cloud.ExternalPrincipal" || reach.Src.Binding != "actor" || reach.Dst.Concept != "cloud.SecretStore" || reach.Dst.Binding != "store" {
		t.Fatalf("semantic reach lowering wrong: %+v", reach)
	}
	transition := decls[2].(*Rule).Body.(*MatchStmt)
	if transition.TargetKind != "transition" || transition.Binding != "t" || transition.Machine != "Order" || transition.FromState != "*" || transition.ToState != "Refunded" {
		t.Fatalf("transition lowering wrong: %+v", transition)
	}
	stateReach := decls[3].(*Rule).Body.(*FlowStmt)
	if stateReach.Verb != "reach" || !stateReach.SemanticQuery || stateReach.Src.Concept != "workflow.Open" || stateReach.Src.Binding != "start" || stateReach.Dst.Concept != "workflow.Closed" || stateReach.Dst.Binding != "done" {
		t.Fatalf("state reach lowering wrong: %+v", stateReach)
	}
	labeled := decls[4].(*Rule).Body.(*MatchStmt)
	if labeled.TargetKind != "concept" || labeled.Concept != "sbom.VulnerableDependency" || labeled.Binding != "p" || labeled.Relation != "labeledAs" || labeled.RelatedConcept != "sbom.ReachableSymbol" {
		t.Fatalf("labeledAs lowering wrong: %+v", labeled)
	}
	reference := decls[5].(*Rule).Body.(*MatchStmt)
	if reference.TargetKind != "concept" || reference.Concept != "runtime.Connection" || reference.Binding != "c" || reference.Relation != "references" || reference.RelationProp != "dst" || reference.RelatedConcept != "threat.MiningPool" {
		t.Fatalf("references lowering wrong: %+v", reference)
	}
}

func TestV2RawSemanticQueryRejectsUnsupportedWherePredicates(t *testing.T) {
	_, err := parseV2DefinitionSourcesForTest(V2DefinitionSourcesFromText("test.vyql", `
module rules.migrated;
rule ExtraPredicateMustNotBeIgnored {
  query concept as source where source.concept == code.HttpInput and source.kind == "request"
    reaches concept as sink where sink.concept == code.SqlExecution
    select sink
}
`))
	if err == nil {
		t.Fatal("ParseV2Definitions accepted raw semantic query with unsupported predicate")
	}
	if !strings.Contains(err.Error(), "unsupported semantic query shape") {
		t.Fatalf("ParseV2Definitions error = %v, want unsupported semantic query diagnostic", err)
	}
}

func TestV2RuleSupportedCoveredByModesLowerToScannerIRClauseKinds(t *testing.T) {
	decls := parseIRFiles(t, `
module rules.xml;
rule UnhardenedXmlParser {
  issue code.XmlParserCreate as parser
  unless parser.endpoint coveredBy core.XmlHardening
}
rule SameReceiverParser {
  issue code.XmlParserCreate as parser
  unless parser.sameReceiver coveredBy core.XmlHardening
}
rule SameScopeParser {
  issue code.XmlParserCreate as parser
  unless parser.sameScope coveredBy core.XmlHardening
}
rule GlobalParser {
  issue code.XmlParserCreate as parser
  unless parser.global coveredBy core.XmlHardening
}
rule DominatedParser {
  issue code.XmlParserCreate as parser
  unless parser.dominates coveredBy core.XmlHardening
}
`, `
module rules.lifecycle;
rule LockNotReleased {
  issue code.LockAcquire as l
  unless l.postDominates coveredBy core.LockRelease
}
`)
	for _, decl := range decls {
		rule := decl.(*Rule)
		if len(rule.Clauses) != 1 {
			t.Fatalf("rule clauses wrong: %+v", rule)
		}
		switch rule.Name {
		case "UnhardenedXmlParser":
			if _, ok := rule.Clauses[0].Unless.(EndpointCoveredBy); !ok {
				t.Fatalf("endpoint coveredBy did not lower to EndpointCoveredBy: %+v", rule.Clauses[0])
			}
		case "SameReceiverParser":
			if _, ok := rule.Clauses[0].Unless.(SameReceiverCoveredBy); !ok {
				t.Fatalf("sameReceiver coveredBy did not preserve coverage mode: %+v", rule.Clauses[0])
			}
		case "SameScopeParser":
			if _, ok := rule.Clauses[0].Unless.(SameScopeCoveredBy); !ok {
				t.Fatalf("sameScope coveredBy did not preserve coverage mode: %+v", rule.Clauses[0])
			}
		case "GlobalParser":
			if _, ok := rule.Clauses[0].Unless.(GlobalCoveredBy); !ok {
				t.Fatalf("global coveredBy did not preserve coverage mode: %+v", rule.Clauses[0])
			}
		case "DominatedParser":
			if _, ok := rule.Clauses[0].Unless.(DominatesCoveredBy); !ok {
				t.Fatalf("dominates coveredBy did not preserve coverage mode: %+v", rule.Clauses[0])
			}
		case "LockNotReleased":
			if _, ok := rule.Clauses[0].Unless.(PostDominatesCoveredBy); !ok {
				t.Fatalf("postDominates coveredBy did not preserve coverage mode: %+v", rule.Clauses[0])
			}
		default:
			t.Fatalf("unexpected rule %s", rule.Name)
		}
	}
}

func TestV2LoweringPreservesRequiredProfileClause(t *testing.T) {
	decls := parseIRFiles(t, `
module rules.injection;
rule SqlInjection {
  taint code.HttpInput -> code.SqlExecution
  require profile web
}
`)
	rule := decls[0].(*Rule)
	got, ok := rule.Meta["required_profiles"].([]string)
	if !ok || len(got) != 1 || got[0] != "web" {
		t.Fatalf("required profile metadata = %#v, want [web]", rule.Meta["required_profiles"])
	}
}

func TestParseV2RejectsUnknownConfidenceLevel(t *testing.T) {
	_, err := ParseV2(`
module rules.injection;
rule SqlInjection {
  taint code.HttpInput -> code.SqlExecution
  with confidence >= certain
}
`)
	if err == nil || !strings.Contains(err.Error(), "unknown confidence level") {
		t.Fatalf("ParseV2 error = %v, want unknown confidence level", err)
	}
}

func TestV2ConceptFieldsLowerToScannerIRFieldNames(t *testing.T) {
	decls := parseIRFiles(t, `
module code;
concept SqlExecution : sink {
  vulnerableTo: [injection.SqlInjection]
  reviewCondition: "inspect query construction"
  reviewAssumption: "query text can be attacker controlled"
}
`)
	c := decls[0].(*ConceptDecl)
	if _, ok := c.Fields["vulnerable_to"]; !ok {
		t.Fatalf("vulnerableTo did not lower to vulnerable_to: %+v", c.Fields)
	}
	if c.Fields["review_condition"] != "inspect query construction" {
		t.Fatalf("reviewCondition did not lower: %+v", c.Fields)
	}
	if c.Fields["review_assumption"] != "query text can be attacker controlled" {
		t.Fatalf("reviewAssumption did not lower: %+v", c.Fields)
	}
}

func TestV2ScannerIRSupportsGrantRulesAndContextFactConcepts(t *testing.T) {
	decls := parseIRFiles(t, `
module custom;
concept External : principal {}
concept Elevated : privilege {
  grantMinLevel: ADMIN
}
concept PublicEdgeObservation : fact {
  contextConfirmFlagValue: true
}
`, `
module rules.identity;
rule ExternalGrant {
  grant custom.External -> custom.Elevated
}
`)
	var sawFact, sawGrant bool
	for _, decl := range decls {
		switch d := decl.(type) {
		case *ConceptDecl:
			if d.QualifiedName() == "custom.PublicEdgeObservation" {
				sawFact = true
				if d.Kind != "fact" || d.Fields["context_confirm_flag_value"] != true {
					t.Fatalf("context fact concept lowering wrong: %+v", d)
				}
			}
		case *Rule:
			if d.QualifiedName() == "rules.identity.ExternalGrant" {
				body, ok := d.Body.(*FlowStmt)
				if !ok || body.Verb != "grant" {
					t.Fatalf("grant rule lowering wrong: %+v", d.Body)
				}
				sawGrant = true
			}
		}
	}
	if !sawFact || !sawGrant {
		t.Fatalf("missing context fact=%v grant=%v in decls: %+v", sawFact, sawGrant, decls)
	}
}

func TestV2ScannerIRRejectsAuthoredAssumeRuleVerb(t *testing.T) {
	_, err := parseV2DefinitionsForTest(`
module rules.identity;
rule ExternalAssume {
  assume custom.External -> custom.Elevated
}
`)
	if err == nil || !strings.Contains(err.Error(), `unknown v2 rule verb "assume"`) {
		t.Fatalf("ParseV2Definitions error = %v, want authored assume rejection", err)
	}
}

func TestV2ScannerIRRejectsAuthoredAssumeSolverCall(t *testing.T) {
	_, err := parseV2DefinitionsForTest(`
module rules.identity;
rule ExternalAssume {
  issue custom.Marker as m
  where assume(custom.External, custom.Elevated)
}
`)
	if err == nil || !strings.Contains(err.Error(), `unsupported call "assume"`) {
		t.Fatalf("ParseV2Definitions error = %v, want authored assume solver rejection", err)
	}
}

func TestLowerV2DefinitionSourcesRejectsParsedGoOwnedMechanic(t *testing.T) {
	_, err := LowerV2DefinitionSources([]V2Source{{
		Name: "mechanics/bad.vyql",
		Program: &V2Program{
			Module: "mechanics.bad",
			Decls: []V2Decl{
				&V2MechanicDecl{Kind: "ruleVerb", Name: "assume"},
			},
		},
	}})
	if err == nil || !strings.Contains(err.Error(), "mechanic ruleVerb.assume is Go-owned") {
		t.Fatalf("LowerV2DefinitionSources error = %v, want Go-owned mechanic diagnostic", err)
	}
}

func TestLowerV2ProgramRejectsParsedGoOwnedMechanic(t *testing.T) {
	_, err := lowerV2ProgramToDeclarations(&V2Program{
		Module: "mechanics.bad",
		Decls: []V2Decl{
			&V2MechanicDecl{Kind: "ruleVerb", Name: "assume"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "mechanic ruleVerb.assume is Go-owned") {
		t.Fatalf("lowerV2ProgramToDeclarations error = %v, want Go-owned mechanic diagnostic", err)
	}
}

func TestLowerV2DefinitionSourcesRejectsParsedExtensionMechanics(t *testing.T) {
	cases := []struct {
		name string
		decl *V2MechanicDecl
		want string
	}{
		{
			name: "context",
			decl: &V2MechanicDecl{Kind: "context", Name: "internetExposure"},
			want: "mechanic context.internetExposure is recognized by the v2 contract but is not implemented by the current runtime",
		},
		{
			name: "ruleVerb",
			decl: &V2MechanicDecl{Kind: "ruleVerb", Name: "observe"},
			want: "mechanic ruleVerb.observe is an extension rule verb, which is not implemented by the current runtime",
		},
		{
			name: "coverage",
			decl: &V2MechanicDecl{Kind: "coverage", Name: "customDominates"},
			want: "mechanic coverage.customDominates is not a built-in coverage mode and extension coverage mechanics are not implemented by the current runtime",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LowerV2DefinitionSources([]V2Source{{
				Name: "mechanics/custom.vyql",
				Program: &V2Program{
					Module: "mechanics.custom",
					Decls:  []V2Decl{tc.decl},
				},
			}})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LowerV2DefinitionSources error = %v, want %q", err, tc.want)
			}
		})
	}
}

const v2CorePoliciesForLoweringTest = `
module policies.core;
policy resultLifecycle default {
  flagWhen: emitted(issue) and hasReview(concept)
  candidateWhen: matched(rule)
  findingWhen: candidate and not covered
  checkWhen: emitted(check) and (hasReview(concept) or explainsFinding)
}
policy resultIdentity default {
  findingKey: [rule.id, primaryTarget.location, primaryTarget.concept]
  flagKey: [concept, location, call.path, call.method]
  fingerprint: [rule.id, primaryTarget.location, primaryTarget.concept]
  stableAcross: [formatting, requirementDiagnosticText, traversalOrder]
}
policy confidence default {
  values: [low, medium, high]
  order: [low, medium, high]
  aggregate: min(rule, endpoints, propagation, requirements)
  softRequirement missing: downgrade(1)
  softRequirement unknown: downgrade(1) annotate("uninspected evidence")
  softRequirement conflicting: downgrade(1) annotate("conflicting evidence")
  softRequirement satisfied: keep
}
policy diagnostic default {
  format: "structured"
  fields: [file, line, column, declarationId, code, message, why, suggestedFix]
}
`

func parseV2DefinitionsWithCoreMechanics(t *testing.T, src string) []Decl {
	t.Helper()
	return parseIRFiles(t, src)
}

func parseV2DefinitionsForTest(src string) ([]Decl, error) {
	return parseV2DefinitionSourcesForTest(V2DefinitionSourcesFromText("test.vyql", src))
}

func parseV2DefinitionSourcesForTest(sources []V2DefinitionSource) ([]Decl, error) {
	allSources := make([]V2DefinitionSource, 0, len(sources)+1)
	keep := make([]bool, 0, len(sources)+1)
	hasPolicies := false
	for _, source := range sources {
		hasPolicies = hasPolicies || strings.HasPrefix(source.Name, "policies/")
	}
	if !hasPolicies {
		allSources = append(allSources, V2DefinitionSource{Name: "policies/core.vyql", Source: v2CorePoliciesForLoweringTest})
		keep = append(keep, false)
	}
	allSources = append(allSources, sources...)
	for range sources {
		keep = append(keep, true)
	}
	parsed := make([]V2Source, 0, len(allSources))
	for _, source := range allSources {
		prog, err := ParseV2(source.Source)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, V2Source{Name: source.Name, Program: prog})
	}
	decls, err := lowerV2DefinitionSourcesSelected(parsed, keep)
	if err != nil {
		return nil, err
	}
	out := decls[:0]
	for _, decl := range decls {
		switch decl.(type) {
		case *V2MechanicDecl, *V2PolicyDecl:
			continue
		default:
			out = append(out, decl)
		}
	}
	return out, nil
}

func parseIRFiles(t *testing.T, srcs ...string) []Decl {
	t.Helper()
	sources := []V2Source{parseV2SourceForLoweringTest(t, "policies/core.vyql", v2CorePoliciesForLoweringTest)}
	keep := []bool{false}
	for i, src := range srcs {
		for _, raw := range V2DefinitionSourcesFromText("test", src) {
			source := parseV2SourceForLoweringTest(t, raw.Name, raw.Source)
			source.Name = "test/module" + string(rune('A'+i)) + "/" + raw.Name
			sources = append(sources, source)
			keep = append(keep, true)
		}
	}
	decls, err := lowerV2DefinitionSourcesSelected(sources, keep)
	if err != nil {
		t.Fatalf("lowerV2DefinitionSourcesSelected: %v", err)
	}
	return decls
}

func parseV2SourceForLoweringTest(t *testing.T, name, src string) V2Source {
	t.Helper()
	prog, err := ParseV2(src)
	if err != nil {
		t.Fatalf("ParseV2 %s: %v", name, err)
	}
	return V2Source{Name: name, Program: prog}
}

func stringListFieldEqual(got any, want []string) bool {
	items, ok := got.([]string)
	if !ok || len(items) != len(want) {
		return false
	}
	for i := range items {
		if items[i] != want[i] {
			return false
		}
	}
	return true
}
