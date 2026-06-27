package parser

import (
	"strings"
	"testing"
)

func TestConvertV1ToV2SafeSubsetProducesParseableFiles(t *testing.T) {
	res, err := ConvertV1ToV2(`
module code;
concept HttpInput : source { summary: "user input" }
concept SqlExecution : sink { vulnerable_to: [injection.SqlInjection] }

adapter javascript {
  source "req.body" -> code.HttpInput
  sink method "execute" arg 0 -> code.SqlExecution
  control method "escapeSql" -> core.SqlParameterization
  mark method "newDocumentBuilder" -> code.XmlParserCreate
  package "express" {
    source "req.query" -> code.HttpInput
  }
}

module rules.injection;
rule SqlInjection {
  meta { id: "VYQL-INJ-001" severity: high cwe: [CWE89] }
  taint code.HttpInput as input -> code.SqlExecution as sqlSink
  unless sanitized_by core.SqlParameterization
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	if len(res.Files) != 8 {
		t.Fatalf("files = %d, want 8: %+v", len(res.Files), res.Files)
	}
	for _, f := range res.Files {
		if _, err := ParseV2(f.Source); err != nil {
			t.Fatalf("converted file %s did not parse as v2: %v\n%s", f.PathHint, err, f.Source)
		}
	}
	if !migrationLedgerHas(res.Ledger, "control", true) {
		t.Fatalf("ledger missing resolved control coverage suggestion: %+v", res.Ledger)
	}
	if !migrationLedgerHas(res.Ledger, "mark", true) {
		t.Fatalf("ledger missing resolved mark-to-issue note: %+v", res.Ledger)
	}
	if !migrationLedgerHas(res.Ledger, "sanitized_by", true) {
		t.Fatalf("ledger missing resolved sanitized_by coverage suggestion: %+v", res.Ledger)
	}
	sanitized := migrationLedgerRecord(res.Ledger, "sanitized_by", true)
	if sanitized.Line == 0 || !strings.Contains(sanitized.Original, "unless sanitized_by core.SqlParameterization") {
		t.Fatalf("sanitized_by ledger record missing source context: %+v", sanitized)
	}
	var packageSource string
	var ruleSource string
	for _, f := range res.Files {
		if strings.Contains(f.Source, `dependency("express")`) {
			packageSource = f.Source
		}
		if strings.Contains(f.Source, "rule SqlInjection") {
			ruleSource = f.Source
		}
	}
	if packageSource == "" {
		t.Fatalf("package requirement was not converted into dependency requirement")
	}
	if !strings.Contains(ruleSource, "unless sqlSink.path coveredBy core.SqlParameterization") {
		t.Fatalf("rule coverage target did not use destination alias:\n%s", ruleSource)
	}
}

func TestWriteV2PackageRequiresPreservesLegacyOrPackageGate(t *testing.T) {
	var req strings.Builder
	writeV2PackageRequires(&req, []string{"express", "koa", "express"})
	if got := req.String(); !strings.Contains(got, `any(dependency("express"), dependency("koa"), dependency("express"))`) {
		t.Fatalf("multi-package gate did not use v2 any requirement:\n%s", got)
	}
	decls, err := ParseV2Runtime(`
module bindings.javascript.web;
binding requestBody {
` + req.String() + `
  query pattern callExpr where callee.path ~= "request.body"
  emit source code.HttpInput at call.result
}
`)
	if err != nil {
		t.Fatalf("ParseV2Runtime: %v", err)
	}
	adapter := decls[0].(*AdapterDecl)
	if got, want := adapter.Mappings[0].Packages, []string{"express", "koa"}; !stringSlicesEqual(got, want) {
		t.Fatalf("packages = %#v, want %#v", got, want)
	}

	migrator := v2Migrator{file: "legacy.vyql", kindPlan: V2MigrationKindPlan{}}
	src, ok := migrator.convertAdapterMapping("bindings.javascript.web", "javascript", 0, AdapterMapping{
		Kind:     "source",
		Pattern:  "request.body",
		Concept:  "code.HttpInput",
		Packages: []string{"express", "koa"},
	})
	if !ok {
		t.Fatalf("convertAdapterMapping returned unresolved; ledger=%+v", migrator.ledger)
	}
	if !strings.Contains(src, `any(dependency("express"), dependency("koa"))`) {
		t.Fatalf("converted mapping did not preserve multi-package OR gate:\n%s", src)
	}
	decls, err = ParseV2Runtime(src)
	if err != nil {
		t.Fatalf("ParseV2Runtime converted mapping: %v\n%s", err, src)
	}
	adapter = decls[0].(*AdapterDecl)
	if got, want := adapter.Mappings[0].Packages, []string{"express", "koa"}; !stringSlicesEqual(got, want) {
		t.Fatalf("converted packages = %#v, want %#v", got, want)
	}
}

func TestConvertV1TokenFlagToCallValuePattern(t *testing.T) {
	res, err := ConvertV1ToV2(`
adapter ruby {
  flag code.InsecureCookie on any {
    path "set_cookie"
    literal "false"
    not literal "secure"
  }
  flag code.HardcodedSecret in module {
    token contains "lang=ruby"
    token contains "assign:config.secret_token="
  }
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	var stable string
	var presence string
	blocked := 0
	for _, f := range res.Files {
		if strings.Contains(f.Source, "binding insecureCookie") {
			stable = f.Source
		}
		if strings.Contains(f.Source, "binding hardcodedSecret") {
			presence = f.Source
		}
		if strings.Contains(f.Source, "TODO_v2Migrate") {
			blocked++
		}
	}
	if !strings.Contains(stable, `query pattern callExpr where callee.path ~= "set_cookie" and args.any.literal contains "false" and not args.any.literal contains "secure"`) {
		t.Fatalf("literal-token flag did not become callExpr value pattern:\n%s", stable)
	}
	if strings.Contains(stable, "unstable.legacyFlag") || strings.Contains(stable, "unstable:") {
		t.Fatalf("stable value flag retained unstable bridge metadata:\n%s", stable)
	}
	if _, err := ParseV2Runtime(stable); err != nil {
		t.Fatalf("ParseV2Runtime stable flag: %v\n%s", err, stable)
	}
	if !strings.Contains(presence, `query pattern presenceNode where node.scope == "module" and node.token contains "contains:lang=ruby" and node.token contains "contains:assign:config.secret_token="`) {
		t.Fatalf("metadata-token flag did not become presenceNode:\n%s", presence)
	}
	if _, err := ParseV2Runtime(presence); err != nil {
		t.Fatalf("ParseV2Runtime presence flag: %v\n%s", err, presence)
	}
	if blocked != 0 {
		t.Fatalf("metadata-token flag should not become a blocking migration stub; files=%+v", res.Files)
	}
}

func TestConvertV1TokenFlagCheckBecomesPresenceCheck(t *testing.T) {
	res, err := ConvertV1ToV2WithConceptKinds(`
adapter go {
  flag core.MemoryBoundsCheck on any {
    path "__binop.ne"
    literal "Count"
    literal "0"
  }
}
`, "legacy.vyql", map[string]string{"core.MemoryBoundsCheck": "check"})
	if err != nil {
		t.Fatalf("ConvertV1ToV2WithConceptKinds: %v", err)
	}
	if len(res.Files) != 1 {
		t.Fatalf("files = %d, want 1: %+v", len(res.Files), res.Files)
	}
	src := res.Files[0].Source
	if !strings.Contains(src, `query pattern presenceNode where node.kind == "any" and node.path ~= "__binop.ne" and node.token contains "literal:Count" and node.token contains "literal:0"`) {
		t.Fatalf("check-kind token flag did not become presenceNode:\n%s", src)
	}
	if !strings.Contains(src, `emit check core.MemoryBoundsCheck at node`) {
		t.Fatalf("check-kind token flag did not emit check at node:\n%s", src)
	}
	if _, err := ParseV2Runtime(src); err != nil {
		t.Fatalf("ParseV2Runtime check-kind presence flag: %v\n%s", err, src)
	}
}

func TestConvertV1ToV2UnsupportedConstructsProduceBlockingStubs(t *testing.T) {
	res, err := ConvertV1ToV2(`
adapter javascript {
  flag code.SecretComparisonReview on binop {
    operand { identifier contains "token" }
  }
}

module rules.review;
rule NeedsAlong {
  match code.SecretComparisonReview as cmp
  along [cmp]
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	if !migrationLedgerHas(res.Ledger, "flag", true) {
		t.Fatalf("ledger missing resolved flag: %+v", res.Ledger)
	}
	if !migrationLedgerHas(res.Ledger, "along", false) {
		t.Fatalf("ledger missing unresolved along clause: %+v", res.Ledger)
	}
	blocking := 0
	for _, f := range res.Files {
		if strings.Contains(f.Source, "TODO_v2Migrate") {
			blocking++
			if _, err := ParseV2(f.Source); err == nil {
				t.Fatalf("blocking stub parsed successfully:\n%s", f.Source)
			}
		}
	}
	if blocking != 1 {
		t.Fatalf("blocking stubs = %d, want 1; files=%+v", blocking, res.Files)
	}
}

func TestConvertV1ToV2RuleWhereExpressions(t *testing.T) {
	res, err := ConvertV1ToV2(`
module vypr.identity;
rule ToxicWorkloadExposure {
  match identity.WorkloadIdentity as w
  where reach(cloud.Internet, w.workload) and assume(w, identity.AdminPrivilege)
}

module vypr.cloud;
rule PublicSensitiveDatabase {
  reach cloud.Internet -> cloud.Database
  where cloud.Database holds_asset_kind [data.Pii]
}

module vypr.runtime;
rule CryptoMiningEgress {
  match runtime.Connection as c
  where c.dst labeled threat.MiningPool
}

rule WorkloadDrift {
  match runtime.Process as p
  where p.image not in [nginx, redis, postgres, python, node, ruby, java]
}

module vypr.sca;
rule ReachableVulnerableDependency {
  match sbom.VulnerableDependency as p
  where p has sbom.ReachableSymbol
}
`, "packs.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	if len(res.Files) != 5 {
		t.Fatalf("files = %d, want 5: %+v", len(res.Files), res.Files)
	}
	for _, f := range res.Files {
		if _, err := ParseV2(f.Source); err != nil {
			t.Fatalf("converted where file %s did not parse as v2: %v\n%s", f.PathHint, err, f.Source)
		}
	}
	var combined strings.Builder
	for _, f := range res.Files {
		combined.WriteString(f.Source)
	}
	src := combined.String()
	for _, want := range []string{
		"where reach(cloud.Internet, w.workload) and assume(w, identity.AdminPrivilege)",
		"where holdsAssetKind(cloud.Database, [data.Pii])",
		"where has(c.dst, threat.MiningPool)",
		"where p.image not in [nginx, redis, postgres, python, node, ruby, java]",
		"where has(p, sbom.ReachableSymbol)",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("converted where expressions missing %q:\n%s", want, src)
		}
	}
	if !migrationLedgerHas(res.Ledger, "where", true) {
		t.Fatalf("ledger missing resolved where conversion: %+v", res.Ledger)
	}
}

func TestConvertV1ToV2OrderAndTransitionQueries(t *testing.T) {
	res, err := ConvertV1ToV2(`
module vypr.business;
rule InvalidRefundTransition {
  match transition * -> Refunded on Order as t
}

module vypr.concurrency;
rule FileToctou {
  order code.FileCheck before code.FileUse
}
`, "packs.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	if len(res.Files) != 2 {
		t.Fatalf("files = %d, want 2: %+v", len(res.Files), res.Files)
	}
	var combined strings.Builder
	for _, f := range res.Files {
		if _, err := ParseV2(f.Source); err != nil {
			t.Fatalf("converted query file %s did not parse as v2: %v\n%s", f.PathHint, err, f.Source)
		}
		combined.WriteString(f.Source)
	}
	src := combined.String()
	for _, want := range []string{
		`query state as t where t.machine == Order and t.from == "*" and t.to == Refunded select t`,
		`query concept as first where first.concept == code.FileCheck reaches concept as second where second.concept == code.FileUse select second`,
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("converted query rules missing %q:\n%s", want, src)
		}
	}
	if !migrationLedgerHas(res.Ledger, "match transition", true) {
		t.Fatalf("ledger missing resolved transition conversion: %+v", res.Ledger)
	}
	if !migrationLedgerHas(res.Ledger, "order", true) {
		t.Fatalf("ledger missing resolved order conversion: %+v", res.Ledger)
	}
}

func TestConvertV1ToV2StateMachineProducesBlockingStub(t *testing.T) {
	res, err := ConvertV1ToV2(`
state_machine AuthFlow {
  states [Start, Done]
  initial Start
  transition Start -> Done
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	if !migrationLedgerHas(res.Ledger, "state_machine", false) {
		t.Fatalf("ledger missing unresolved state_machine: %+v", res.Ledger)
	}
	if len(res.Files) != 1 || !strings.Contains(res.Files[0].Source, "TODO_v2Migrate") {
		t.Fatalf("state_machine did not produce blocking stub: %+v", res.Files)
	}
	if _, err := ParseV2(res.Files[0].Source); err == nil {
		t.Fatalf("blocking state_machine stub parsed successfully:\n%s", res.Files[0].Source)
	}
}

func TestConvertV1ToV2SimpleFlagsBecomeIssues(t *testing.T) {
	res, err := ConvertV1ToV2(`
adapter javascript {
  flag code.CleartextChannel on any {
    path "http.get"
  }
  flag code.LockAcquire on any {
    method "lock"
  }
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	if len(res.Files) != 2 {
		t.Fatalf("files = %d, want 2: %+v", len(res.Files), res.Files)
	}
	for _, f := range res.Files {
		if _, err := ParseV2(f.Source); err != nil {
			t.Fatalf("converted flag file %s did not parse as v2: %v\n%s", f.PathHint, err, f.Source)
		}
		if !strings.Contains(f.Source, "emit issue") {
			t.Fatalf("converted flag did not emit issue:\n%s", f.Source)
		}
	}
	if !migrationLedgerHas(res.Ledger, "flag", true) {
		t.Fatalf("ledger missing resolved flag conversion: %+v", res.Ledger)
	}
}

func TestConvertV1ToV2TokenFlagPredicatesBecomePresenceNode(t *testing.T) {
	res, err := ConvertV1ToV2(`
adapter perl {
  flag code.CleartextChannel on any {
    path "getstore"
    has "http://"
    lacks "127.0"
  }
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	if len(res.Files) != 1 {
		t.Fatalf("files = %d, want 1: %+v", len(res.Files), res.Files)
	}
	src := res.Files[0].Source
	if !strings.Contains(src, `query pattern presenceNode where node.kind == "any" and node.path ~= "getstore" and node.token contains "http://" and not (node.token contains "127.0")`) {
		t.Fatalf("legacy token flag did not become presenceNode:\n%s", src)
	}
	if _, err := ParseV2Runtime(src); err != nil {
		t.Fatalf("ParseV2Runtime token presence flag: %v\n%s", err, src)
	}
	if !migrationLedgerHas(res.Ledger, "flag", true) {
		t.Fatalf("ledger missing resolved legacy flag conversion: %+v", res.Ledger)
	}
}

func TestConvertV1ToV2AnalysisPathFlagBecomesPresenceNode(t *testing.T) {
	res, err := ConvertV1ToV2(`
adapter sca {
  flag sbom.VulnerableDependency on any {
    path exact "analysis.sca.package"
  }
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	if !migrationLedgerHas(res.Ledger, "flag", true) {
		t.Fatalf("ledger missing resolved analysis flag: %+v", res.Ledger)
	}
	if len(res.Files) != 1 || !strings.Contains(res.Files[0].Source, `query pattern presenceNode where node.kind == "any" and node.path == "analysis.sca.package"`) {
		t.Fatalf("analysis path flag should produce presenceNode: %+v", res.Files)
	}
	if _, err := ParseV2Runtime(res.Files[0].Source); err != nil {
		t.Fatalf("ParseV2Runtime analysis presence flag: %v\n%s", err, res.Files[0].Source)
	}
}

func TestConvertV1ToV2ComplexFlagBecomesPresenceNode(t *testing.T) {
	res, err := ConvertV1ToV2(`
adapter javascript {
  flag code.SecretComparisonReview on binop {
    op any ["==", "==="]
    operand {
      path "__binop.operand"
      identifier contains_any ["token", "secret"]
    }
    lacks call contains_any ["scmp", "timingSafeEqual"]
  }
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	if len(res.Files) != 1 {
		t.Fatalf("files = %d, want 1: %+v", len(res.Files), res.Files)
	}
	src := res.Files[0].Source
	if !strings.Contains(src, `query pattern presenceNode where node.kind == "binop" and node.op in ["==", "==="]`) ||
		!strings.Contains(src, `operand(node, where: operand.path ~= "__binop.operand" and containsAny(operand.identifier, [token, secret]))`) {
		t.Fatalf("complex flag should produce presenceNode:\n%s", src)
	}
	if _, err := ParseV2Runtime(src); err != nil {
		t.Fatalf("ParseV2Runtime complex presence flag: %v\n%s", err, src)
	}
	if !migrationLedgerHas(res.Ledger, "flag", true) {
		t.Fatalf("ledger missing resolved flag conversion: %+v", res.Ledger)
	}
}

func TestConvertV1ToV2OperandFlagBecomesPresenceNode(t *testing.T) {
	res, err := ConvertV1ToV2(`
adapter go {
  flag code.SecretComparisonReview on binop {
    operand {
      key contains_any [".Password", ".Token"]
    }
  }
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	src := res.Files[0].Source
	if !strings.Contains(src, `query pattern presenceNode where node.kind == "binop" and operand(node, where: containsAny(operand.key, [".Password", ".Token"]))`) {
		t.Fatalf("operand flag should produce presenceNode:\n%s", src)
	}
	if _, err := ParseV2Runtime(src); err != nil {
		t.Fatalf("ParseV2Runtime operand presence flag: %v\n%s", err, src)
	}
	if !migrationLedgerHas(res.Ledger, "flag", true) {
		t.Fatalf("ledger missing resolved operand flag: %+v", res.Ledger)
	}
}

func TestConvertV1ToV2LegacyOnlyConceptKindsBecomeFacts(t *testing.T) {
	res, err := ConvertV1ToV2(`
module runtime;
concept Process : observation {}
concept MiningPool : indicator {}
concept Refund : action {}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	for _, f := range res.Files {
		if _, err := ParseV2(f.Source); err != nil {
			t.Fatalf("converted concept kind file did not parse as v2: %v\n%s", err, f.Source)
		}
		if !strings.Contains(f.Source, ": fact") {
			t.Fatalf("legacy-only concept kind was not mapped to fact:\n%s", f.Source)
		}
	}
}

func TestConvertV1ToV2MatchRulesRespectMigratedConceptKinds(t *testing.T) {
	res, err := ConvertV1ToV2(`
module code;
concept PresenceThing : sink {}
concept MixedThing : sink {}
concept GuardedThing : sink {}
module runtime;
concept RuntimeThing : observation {}
module core;
concept Input : source {}
concept Guard : control {}

adapter c {
  sink path "danger" -> code.PresenceThing
  sink path "guarded" -> code.GuardedThing
  flag code.MixedThing on any {
    path "mixed"
  }
}

module rules.mixed;
rule PresenceFinding {
  match code.PresenceThing as p
}
rule MixedFlow {
  taint core.Input -> code.MixedThing
}
rule MixedPresence {
  match code.MixedThing as m
}
rule GuardedPresence {
  match code.GuardedThing as g
  unless guarded_by core.Guard
}
rule RuntimeObservation {
  match runtime.RuntimeThing as r
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	sources := []V2Source{v2CoreMechanicsSourceForTest(t)}
	var combined strings.Builder
	for _, f := range res.Files {
		prog, err := ParseV2(f.Source)
		if err != nil {
			t.Fatalf("converted file %s did not parse as v2: %v\n%s", f.PathHint, err, f.Source)
		}
		sources = append(sources, V2Source{Name: f.PathHint, Program: prog})
		combined.WriteString(f.Source)
	}
	if err := ValidateV2Corpus(sources); err != nil {
		t.Fatalf("converted corpus did not validate: %v", err)
	}
	src := combined.String()
	for _, want := range []string{
		"concept PresenceThing : issue",
		"concept PresenceThingSink : sink",
		"issue code.PresenceThing as p",
		"emit sink code.PresenceThingSink at args[0]",
		"emit issue code.PresenceThing at call",
		"concept MixedThing : issue",
		"concept MixedThingSink : sink",
		"taint core.Input -> code.MixedThingSink",
		"issue code.MixedThing as m",
		"emit issue code.MixedThing at call",
		"emit sink code.MixedThingSink at call",
		"concept GuardedThing : issue",
		"concept GuardedThingSink : sink",
		"issue code.GuardedThing as g",
		"unless g.endpoint coveredBy core.Guard",
		"emit sink code.GuardedThingSink at args[0]",
		"emit issue code.GuardedThing at call",
		"concept RuntimeThing : fact",
		"fact runtime.RuntimeThing as r",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("converted mixed match rules missing %q:\n%s", want, src)
		}
	}
}

func TestConvertV1ToV2MappingValueGuardsBecomeQueryPredicates(t *testing.T) {
	res, err := ConvertV1ToV2(`
adapter python {
  sink exact "yaml.load" val "Loader" nval "SafeLoader" -> code.Deserialization
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	if len(res.Files) != 1 {
		t.Fatalf("files = %d, want 1: %+v", len(res.Files), res.Files)
	}
	src := res.Files[0].Source
	if _, err := ParseV2(src); err != nil {
		t.Fatalf("converted guarded mapping did not parse as v2: %v\n%s", err, src)
	}
	decls, err := ParseV2Runtime(src)
	if err != nil {
		t.Fatalf("converted guarded mapping did not lower to runtime: %v\n%s", err, src)
	}
	got := decls[0].(*AdapterDecl).Mappings[0]
	if got.ValMatches[0] != "Loader" || got.ValAbsents[0] != "SafeLoader" {
		t.Fatalf("converted guarded mapping lost value guards: %+v", got)
	}
	for _, want := range []string{
		`callee.path == "yaml.load"`,
		`args.any.literal contains "Loader"`,
		`not args.any.literal contains "SafeLoader"`,
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("converted mapping missing %q:\n%s", want, src)
		}
	}
}

func TestConvertV1ToV2ArgAllSinksUseArgsAny(t *testing.T) {
	res, err := ConvertV1ToV2(`
adapter bash {
  sink path "cat" arg all -> code.FilePathAccess
  sink method "println" arg all -> code.HtmlRender
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	if len(res.Files) != 2 {
		t.Fatalf("files = %d, want 2: %+v", len(res.Files), res.Files)
	}
	var combined strings.Builder
	for _, f := range res.Files {
		if _, err := ParseV2(f.Source); err != nil {
			t.Fatalf("converted arg-all file %s did not parse as v2: %v\n%s", f.PathHint, err, f.Source)
		}
		combined.WriteString(f.Source)
	}
	src := combined.String()
	for _, want := range []string{
		"emit sink code.FilePathAccess at args.any",
		"emit sink code.HtmlRender at args.any",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("converted arg-all sinks missing %q:\n%s", want, src)
		}
	}
}

func TestConvertV1ToV2CollectionSinksUseCollectionLocations(t *testing.T) {
	res, err := ConvertV1ToV2(`
adapter python {
  sink path "subprocess.call" collection first -> code.CommandExecution
  sink path "subprocess.Popen" collection 2 val "-c" -> code.CommandExecution
  sink method "writerow" collection -> code.CsvCell
  sink path "asyncio.create_subprocess_exec" arg all collection -> code.CommandExecution
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	if len(res.Files) != 4 {
		t.Fatalf("files = %d, want 4: %+v", len(res.Files), res.Files)
	}
	var combined strings.Builder
	for _, f := range res.Files {
		if _, err := ParseV2(f.Source); err != nil {
			t.Fatalf("converted collection file %s did not parse as v2: %v\n%s", f.PathHint, err, f.Source)
		}
		combined.WriteString(f.Source)
	}
	src := combined.String()
	for _, want := range []string{
		"emit sink code.CommandExecution at args[0].collection[0]",
		"emit sink code.CommandExecution at args[0].collection[2]",
		"emit sink code.CsvCell at args[0].collection",
		"emit sink code.CommandExecution at args.any.collection",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("converted collection sinks missing %q:\n%s", want, src)
		}
	}
}

func TestConvertV1ToV2ReceiverConstrainedMappings(t *testing.T) {
	res, err := ConvertV1ToV2(`
adapter java {
  source receiver "getParameter" on "HttpServletRequest" -> code.HttpInput
  sink method "execute" on java.sql.Statement -> code.SqlExecution
  sink receiver "openConnection" -> code.UrlFetch
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	if len(res.Files) != 3 {
		t.Fatalf("files = %d, want 3: %+v", len(res.Files), res.Files)
	}
	var combined strings.Builder
	for _, f := range res.Files {
		if _, err := ParseV2(f.Source); err != nil {
			t.Fatalf("converted receiver file %s did not parse as v2: %v\n%s", f.PathHint, err, f.Source)
		}
		combined.WriteString(f.Source)
	}
	src := combined.String()
	for _, want := range []string{
		`callee.method == "getParameter" and callee.receiver.type == "HttpServletRequest"`,
		`callee.method == "execute" and callee.receiver.type == "java.sql.Statement"`,
		`emit sink code.UrlFetch at callee.receiver`,
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("converted receiver mappings missing %q:\n%s", want, src)
		}
	}
}

func TestConvertV1ToV2TypeMappingsBecomeReceiverTypeFacts(t *testing.T) {
	res, err := ConvertV1ToV2(`
adapter go {
  type "sql.Open" -> sql.DB
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	if len(res.Files) != 1 {
		t.Fatalf("files = %d, want 1: %+v", len(res.Files), res.Files)
	}
	src := res.Files[0].Source
	if _, err := ParseV2(src); err != nil {
		t.Fatalf("converted type file did not parse as v2: %v\n%s", err, src)
	}
	for _, want := range []string{
		`query pattern callExpr where callee.path ~= "sql.Open"`,
		"emit fact runtime.ReceiverType at call.result",
		"about: sql.DB",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("converted type mapping missing %q:\n%s", want, src)
		}
	}
	if !migrationLedgerHas(res.Ledger, "type", true) {
		t.Fatalf("ledger missing resolved type conversion: %+v", res.Ledger)
	}
}

func TestConvertV1ToV2SourceParamUsesParamQuery(t *testing.T) {
	res, err := ConvertV1ToV2(`
adapter library {
  source param -> code.ExternalEntryInput
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	if len(res.Files) != 1 {
		t.Fatalf("files = %d, want 1: %+v", len(res.Files), res.Files)
	}
	src := res.Files[0].Source
	if _, err := ParseV2(src); err != nil {
		t.Fatalf("converted source param file did not parse as v2: %v\n%s", err, src)
	}
	for _, want := range []string{
		"query param as param",
		"emit source code.ExternalEntryInput at param",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("converted source param missing %q:\n%s", want, src)
		}
	}
	if !migrationLedgerHas(res.Ledger, "source_param", true) {
		t.Fatalf("ledger missing resolved source_param conversion: %+v", res.Ledger)
	}
}

func TestConvertV1ToV2ReceiverControlUsesSameReceiverCheck(t *testing.T) {
	res, err := ConvertV1ToV2(`
adapter python {
  control receiver method "relative_to" -> core.PathCanonicalization
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	if len(res.Files) != 1 {
		t.Fatalf("files = %d, want 1: %+v", len(res.Files), res.Files)
	}
	src := res.Files[0].Source
	if _, err := ParseV2(src); err != nil {
		t.Fatalf("converted receiver control file did not parse as v2: %v\n%s", err, src)
	}
	for _, want := range []string{
		`query pattern callExpr where callee.method == "relative_to"`,
		"emit check core.PathCanonicalization at callee.receiver",
		"covers sameReceiver",
		"anchor: callee.receiver",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("converted receiver control missing %q:\n%s", want, src)
		}
	}
	if !migrationLedgerHas(res.Ledger, "control_receiver_method", true) {
		t.Fatalf("ledger missing resolved control_receiver_method conversion: %+v", res.Ledger)
	}
}

func TestConvertV1ToV2FlowUsesPropagateValue(t *testing.T) {
	res, err := ConvertV1ToV2(`
adapter c {
  flow method "decode" arg 1 from args 0
  flow path "parse" arg 0 from result
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	if len(res.Files) != 2 {
		t.Fatalf("files = %d, want 2: %+v", len(res.Files), res.Files)
	}
	var combined strings.Builder
	for _, f := range res.Files {
		if strings.Contains(f.Source, "TODO_v2Migrate") {
			t.Fatalf("flow conversion produced blocking stub:\n%s", f.Source)
		}
		if _, err := ParseV2Runtime(f.Source); err != nil {
			t.Fatalf("converted flow file did not lower as v2: %v\n%s", err, f.Source)
		}
		combined.WriteString(f.Source)
	}
	src := combined.String()
	for _, want := range []string{
		`propagate value from args[0] to args[1].pointee`,
		`propagate value from call.result to args[0].pointee`,
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("converted flow missing %q:\n%s", want, src)
		}
	}
	if !migrationLedgerHas(res.Ledger, "flow_method", true) || !migrationLedgerHas(res.Ledger, "flow_path", true) {
		t.Fatalf("ledger missing resolved flow conversions: %+v", res.Ledger)
	}
}

func TestConvertV1ToV2GlobalFilterUsesCharFilterCheck(t *testing.T) {
	res, err := ConvertV1ToV2(`
adapter ruby {
  filter method "gsub" global
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	if len(res.Files) != 1 {
		t.Fatalf("files = %d, want 1: %+v", len(res.Files), res.Files)
	}
	src := res.Files[0].Source
	if _, err := ParseV2(src); err != nil {
		t.Fatalf("converted filter file did not parse as v2: %v\n%s", err, src)
	}
	for _, want := range []string{
		`query pattern callExpr where callee.method == "gsub"`,
		"call.filter.global == true",
		"emit check threat.CharFilter at call",
		"covers path",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("converted filter missing %q:\n%s", want, src)
		}
	}
	if !migrationLedgerHas(res.Ledger, "filter", true) {
		t.Fatalf("ledger missing resolved filter conversion: %+v", res.Ledger)
	}
}

func TestConvertV1ToV2NonGlobalFilterUsesCharFilterCheck(t *testing.T) {
	res, err := ConvertV1ToV2(`
adapter javascript {
  filter method "replace"
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	if !migrationLedgerHas(res.Ledger, "filter", true) {
		t.Fatalf("ledger missing resolved filter conversion: %+v", res.Ledger)
	}
	if len(res.Files) != 1 || strings.Contains(res.Files[0].Source, "TODO_v2Migrate") {
		t.Fatalf("non-global filter produced blocking stub: %+v", res.Files)
	}
	src := res.Files[0].Source
	if _, err := ParseV2(src); err != nil {
		t.Fatalf("converted non-global filter file did not parse as v2: %v\n%s", err, src)
	}
	if strings.Contains(src, "call.filter.global == true") {
		t.Fatalf("non-global filter should not force global marker:\n%s", src)
	}
}

func TestConvertV1ToV2AnalysisAssumeProducesBlockingStub(t *testing.T) {
	res, err := ConvertV1ToV2(`
adapter java {
  assume guard path "analysis.guard.containment_check" -> code.FilePathAccess
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	if len(res.Files) != 1 {
		t.Fatalf("files = %d, want 1: %+v", len(res.Files), res.Files)
	}
	src := res.Files[0].Source
	if !strings.Contains(src, "TODO_v2Migrate") {
		t.Fatalf("analysis assume should produce blocking stub:\n%s", src)
	}
	if !migrationLedgerHas(res.Ledger, "assume_guard_path", false) {
		t.Fatalf("ledger missing unresolved analysis assume conversion: %+v", res.Ledger)
	}
}

func TestConvertV1ToV2AssumeBecomesAdvisoryCheck(t *testing.T) {
	res, err := ConvertV1ToV2(`
module core;
concept Assumption : control { analysis_role: neutralizer_assumption }

adapter javascript {
  assume sanitizer method "escapeXPath" -> code.XpathQuery
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	var conceptSource, assumeSource string
	for _, f := range res.Files {
		if strings.Contains(f.Source, "concept Assumption") {
			conceptSource = f.Source
		}
		if strings.Contains(f.Source, "advisory: true") {
			assumeSource = f.Source
		}
	}
	if !strings.Contains(conceptSource, "concept Assumption : check") {
		t.Fatalf("control concept did not migrate to check:\n%s", conceptSource)
	}
	for _, want := range []string{
		"emit check core.Assumption at call",
		"advisory: true",
		"about: code.XpathQuery",
		"covers path",
	} {
		if !strings.Contains(assumeSource, want) {
			t.Fatalf("converted assume missing %q:\n%s", want, assumeSource)
		}
	}
	for _, f := range res.Files {
		if _, err := ParseV2(f.Source); err != nil {
			t.Fatalf("converted assume file %s did not parse as v2: %v\n%s", f.PathHint, err, f.Source)
		}
	}
	decls, err := ParseV2Runtime(assumeSource)
	if err != nil {
		t.Fatalf("converted assume did not lower to runtime: %v\n%s", err, assumeSource)
	}
	got := decls[0].(*AdapterDecl).Mappings[0]
	if got.Kind != "assume_sanitizer_method" || got.Pattern != "escapeXPath" || got.About != "code.XpathQuery" {
		t.Fatalf("converted assume runtime mapping wrong: %+v", got)
	}
	if !migrationLedgerHas(res.Ledger, "assume", true) {
		t.Fatalf("ledger missing resolved assume conversion: %+v", res.Ledger)
	}
}

func TestConvertV1ToV2AnalysisAssumeBlocksMigrationUntilStableFacts(t *testing.T) {
	res, err := ConvertV1ToV2(`
adapter python {
  assume guard path "analysis.guard.containment_check" -> code.FilePathAccess
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	if !migrationLedgerHas(res.Ledger, "assume_guard_path", false) {
		t.Fatalf("ledger missing unresolved analysis assume: %+v", res.Ledger)
	}
	if len(res.Files) != 1 || !strings.Contains(res.Files[0].Source, "TODO_v2Migrate") {
		t.Fatalf("analysis assume should produce blocking stub: %+v", res.Files)
	}
}

func TestConvertV1ToV2AdapterMetadataBecomesStablePattern(t *testing.T) {
	res, err := ConvertV1ToV2(`
adapter textpattern {
  meta {
    cross_language: true,
    text_pattern_event: "analysis.text_pattern.credential_literal",
    text_pattern_extensions: [".go", ".py"]
  }
  flag code.HardcodedSecret on any { path "analysis.text_pattern.credential_literal" }
}
`, "textpattern.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	if len(res.Files) != 2 {
		t.Fatalf("files = %d, want stable metadata plus stable mapping: %+v", len(res.Files), res.Files)
	}
	metadata := 0
	stable := 0
	for _, f := range res.Files {
		if strings.Contains(f.Source, "TODO_v2Migrate") {
			t.Fatalf("adapter metadata should not produce blocking stub:\n%s", f.Source)
		}
		if strings.Contains(f.Source, "pattern adapterMetadata") {
			metadata++
			if !strings.Contains(f.Source, `adapter: {`) || !strings.Contains(f.Source, `name: "textpattern"`) ||
				!strings.Contains(f.Source, `text_pattern_event: "analysis.text_pattern.credential_literal"`) {
				t.Fatalf("adapter metadata did not become stable pattern:\n%s", f.Source)
			}
		} else {
			stable++
			if !strings.Contains(f.Source, `query pattern presenceNode where node.kind == "any" and node.path ~= "analysis.text_pattern.credential_literal"`) {
				t.Fatalf("metadata-backed mapping did not become presenceNode:\n%s", f.Source)
			}
		}
		if _, err := ParseV2Runtime(f.Source); err != nil {
			t.Fatalf("stable metadata-backed file did not lower: %v\n%s", err, f.Source)
		}
	}
	if metadata != 1 || stable != 1 {
		t.Fatalf("metadata migration metadata=%d stable=%d; files=%+v", metadata, stable, res.Files)
	}
	if !migrationLedgerHas(res.Ledger, "adapter meta", true) {
		t.Fatalf("ledger missing resolved adapter metadata: %+v", res.Ledger)
	}
}

func TestConvertV1ToV2LegacyCapabilityMatrix(t *testing.T) {
	cases := []struct {
		name       string
		src        string
		resolved   []string
		unresolved []string
		want       []string
	}{
		{
			name: "model presentation and profile declarations",
			src: `
module code;
concept HttpInput : source { summary: "input" }
threat injection.SqlInjection { cwe: [CWE89] }
review code.HttpInput { category: "input" text: "review input" }
profile web { title: "Web" packs: [injection] }
`,
			want: []string{
				"concept HttpInput : source",
				"threat SqlInjection",
				"review code.HttpInput",
				"profile web",
			},
		},
		{
			name: "adapter mappings and package gates",
			src: `
adapter java {
  meta { cross_language: true }
  source param -> code.ExternalEntryInput
  source receiver "getParameter" on "HttpServletRequest" -> code.HttpInput
  sink path "Statement.execute" arg 1 -> code.SqlExecution
  sink method "println" arg all -> code.HtmlRender
  sink receiver "openConnection" -> code.UrlFetch
  sink exact "Random" -> code.WeakRandomValue
  sink path "subprocess.call" collection first -> code.CommandExecution
  type "sql.Open" -> sql.DB
  package "express" {
    source "req.query" -> code.HttpInput
  }
}
`,
			resolved: []string{"adapter meta", "source_param", "type"},
			want: []string{
				"pattern adapterMetadata",
				`name: "java"`,
				"query param as param",
				"callee.method == \"getParameter\" and callee.receiver.type == \"HttpServletRequest\"",
				"emit sink code.SqlExecution at args[1]",
				"emit sink code.HtmlRender at args.any",
				"emit sink code.UrlFetch at callee.receiver",
				"emit sink code.CommandExecution at args[0].collection[0]",
				"emit fact runtime.ReceiverType at call.result",
				`dependency("express")`,
			},
		},
		{
			name: "checks propagation filters and advisory assumptions",
			src: `
adapter python {
  control "escape" -> core.HtmlEscape
  control receiver method "relative_to" -> core.PathCanonicalization
  mark method "newDocumentBuilder" -> code.XmlParserCreate
  filter method "gsub" global
  filter path "replace"
  flow method "decode" arg 1 from args 0
  flow path "parse" arg 0 from result
  assume guard method "startswith" -> code.FilePathAccess
  assume sanitizer path "normpath" -> code.FilePathAccess
}
`,
			resolved: []string{"control", "control_receiver_method", "mark", "filter", "flow_method", "flow_path", "assume"},
			want: []string{
				"covers path",
				"covers sameReceiver",
				"emit issue code.XmlParserCreate at call",
				"call.filter.global == true",
				"propagate value from args[0] to args[1].pointee",
				"propagate value from call.result to args[0].pointee",
				"advisory: true",
				"covers dominates",
			},
		},
		{
			name: "presence flags and structured predicates",
			src: `
adapter javascript {
  flag code.CleartextChannel on any { path "http.get" }
  flag code.SecretComparisonReview on binop {
    op any ["==", "==="]
    operand { identifier contains_any ["token", "secret"] }
    lacks call contains_any ["scmp", "timingSafeEqual"]
  }
}
`,
			resolved: []string{"flag"},
			want: []string{
				"emit issue code.CleartextChannel",
				"query pattern presenceNode",
				"operand(node, where: containsAny(operand.identifier, [token, secret]))",
			},
		},
		{
			name: "rule verbs coverage clauses and semantic where",
			src: `
module core;
concept Input : source {}
concept SqlParameterization : control {}
concept AuthGuard : control {}
concept CloseHandle : control {}
module code;
concept SqlExecution : sink {}
module identity;
concept User : principal {}
concept AdminPrivilege : privilege {}

adapter javascript {
  package "express" {
    sink method "execute" -> code.SqlExecution
  }
}

module rules.injection;
rule SqlInjection {
  taint core.Input as input -> code.SqlExecution as sqlSink
  unless sanitized_by core.SqlParameterization
  unless guarded_by core.AuthGuard
  unless closed_by core.CloseHandle
  where sqlSink has sbom.ReachableSymbol
}

rule AdminAssumption {
  assume identity.User -> identity.AdminPrivilege
}
`,
			resolved: []string{"sanitized_by", "guarded_by", "closed_by", "where", "rule assume"},
			want: []string{
				`dependency("express")`,
				"unless sqlSink.path coveredBy core.SqlParameterization",
				"unless sqlSink.endpoint coveredBy core.AuthGuard",
				"unless sqlSink.dominates coveredBy core.CloseHandle",
				"where has(sqlSink, sbom.ReachableSymbol)",
				"grant identity.User -> identity.AdminPrivilege",
			},
		},
		{
			name: "semantic queries and blocking legacy constructs",
			src: `
module vypr.business;
rule InvalidRefundTransition {
  match transition * -> Refunded on Order as t
}

module vypr.concurrency;
rule FileToctou {
  order code.FileCheck before code.FileUse
}

state_machine AuthFlow {
  states [Start, Done]
  initial Start
  transition Start -> Done
}

rule NeedsAlong {
  match code.SecretComparisonReview as cmp
  along [cmp]
}
`,
			resolved:   []string{"match transition", "order"},
			unresolved: []string{"state_machine", "along"},
			want: []string{
				"query state as t",
				"query concept as first",
				"TODO_v2Migrate",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ConvertV1ToV2(tc.src, "legacy.vyql")
			if err != nil {
				t.Fatalf("ConvertV1ToV2: %v", err)
			}
			combined := convertedV2Sources(t, res, len(tc.unresolved) > 0)
			for _, construct := range tc.resolved {
				if !migrationLedgerHas(res.Ledger, construct, true) {
					t.Fatalf("ledger missing resolved %q: %+v", construct, res.Ledger)
				}
			}
			for _, construct := range tc.unresolved {
				if !migrationLedgerHas(res.Ledger, construct, false) {
					t.Fatalf("ledger missing unresolved %q: %+v", construct, res.Ledger)
				}
			}
			for _, want := range tc.want {
				if !strings.Contains(combined, want) {
					t.Fatalf("converted sources missing %q:\n%s", want, combined)
				}
			}
		})
	}
}

func convertedV2Sources(t *testing.T, res V2MigrationResult, allowBlocking bool) string {
	t.Helper()
	var combined strings.Builder
	blocking := 0
	for _, f := range res.Files {
		combined.WriteString(f.Source)
		if strings.Contains(f.Source, "TODO_v2Migrate") {
			blocking++
			if _, err := ParseV2(f.Source); err == nil {
				t.Fatalf("blocking stub %s parsed successfully:\n%s", f.PathHint, f.Source)
			}
			continue
		}
		if _, err := ParseV2(f.Source); err != nil {
			t.Fatalf("converted file %s did not parse as v2: %v\n%s", f.PathHint, err, f.Source)
		}
	}
	if blocking > 0 && !allowBlocking {
		t.Fatalf("unexpected blocking stubs = %d:\n%s", blocking, combined.String())
	}
	if blocking == 0 && allowBlocking {
		t.Fatalf("expected at least one blocking stub:\n%s", combined.String())
	}
	return combined.String()
}

func migrationLedgerHas(records []V2MigrationRecord, construct string, resolved bool) bool {
	return migrationLedgerRecord(records, construct, resolved).Construct != ""
}

func migrationLedgerRecord(records []V2MigrationRecord, construct string, resolved bool) V2MigrationRecord {
	for _, r := range records {
		if r.Construct == construct && r.Resolved == resolved {
			return r
		}
	}
	return V2MigrationRecord{}
}
