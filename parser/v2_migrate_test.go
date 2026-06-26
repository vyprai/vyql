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

func TestConvertV1ToV2LegacyFlagPredicatesUseUnstableQuery(t *testing.T) {
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
	if _, err := ParseV2(src); err != nil {
		t.Fatalf("converted legacy flag did not parse as v2: %v\n%s", err, src)
	}
	for _, want := range []string{
		`owner: "migration"`,
		`reason: "v1 flag predicates depend on legacy token/path matching not yet promoted to stable v2 facts"`,
		"query unstable.legacyFlag as node where",
		`node.kind == "any"`,
		`node.path ~= "getstore"`,
		`node.token contains "http://"`,
		`not (node.token contains "127.0")`,
		"emit issue code.CleartextChannel at node",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("converted legacy flag missing %q:\n%s", want, src)
		}
	}
	if !migrationLedgerHas(res.Ledger, "flag", true) {
		t.Fatalf("ledger missing resolved legacy flag conversion: %+v", res.Ledger)
	}
}

func TestConvertV1ToV2AnalysisPathFlagUsesLegacyQuery(t *testing.T) {
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
	if len(res.Files) != 1 || strings.Contains(res.Files[0].Source, "TODO_v2Migrate") {
		t.Fatalf("analysis path flag produced blocking stub: %+v", res.Files)
	}
	if _, err := ParseV2(res.Files[0].Source); err != nil {
		t.Fatalf("converted analysis flag did not parse as v2: %v\n%s", err, res.Files[0].Source)
	}
}

func TestConvertV1ToV2ComplexFlagUsesExtendedLegacyQuery(t *testing.T) {
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
	if _, err := ParseV2(src); err != nil {
		t.Fatalf("converted complex flag did not parse as v2: %v\n%s", err, src)
	}
	for _, want := range []string{
		`owner: "migration"`,
		`reason: "v1 flag predicates depend on legacy token/path matching not yet promoted to stable v2 facts"`,
		"query unstable.legacyFlag as node where",
		`node.op in ["==", "==="]`,
		`operand(node, where: operand.path ~= "__binop.operand" and containsAny(operand.identifier, [token, secret]))`,
		`not (containsAny(node.scopeCall.any, [scmp, timingSafeEqual]))`,
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("converted complex flag missing %q:\n%s", want, src)
		}
	}
	if !migrationLedgerHas(res.Ledger, "flag", true) {
		t.Fatalf("ledger missing resolved flag conversion: %+v", res.Ledger)
	}
}

func TestConvertV1ToV2LegacyFlagQuotesInvalidBareValues(t *testing.T) {
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
	if _, err := ParseV2(src); err != nil {
		t.Fatalf("converted leading-dot values did not parse as v2: %v\n%s", err, src)
	}
	if !strings.Contains(src, `containsAny(operand.key, [".Password", ".Token"])`) {
		t.Fatalf("leading-dot values were not quoted:\n%s", src)
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
		"emit issue code.MixedThing at node",
		"emit sink code.MixedThingSink at node",
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

func TestConvertV1ToV2AnalysisAssumeUsesUnstableQuery(t *testing.T) {
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
	if _, err := ParseV2(src); err != nil {
		t.Fatalf("converted analysis assume file did not parse as v2: %v\n%s", err, src)
	}
	for _, want := range []string{
		`owner: "migration"`,
		`reason: "v1 analysis assume evidence reads implementation analysis nodes not yet promoted to stable v2 facts"`,
		`query unstable.analysisAssumeGuard as call where call.path == "analysis.guard.containment_check"`,
		"emit check core.Assumption at call",
		"advisory: true",
		"about: code.FilePathAccess",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("converted analysis assume missing %q:\n%s", want, src)
		}
	}
	if !migrationLedgerHas(res.Ledger, "assume", true) {
		t.Fatalf("ledger missing resolved analysis assume conversion: %+v", res.Ledger)
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

func TestConvertV1ToV2AnalysisAssumeNoLongerBlocksMigration(t *testing.T) {
	res, err := ConvertV1ToV2(`
adapter python {
  assume guard path "analysis.guard.containment_check" -> code.FilePathAccess
}
`, "legacy.vyql")
	if err != nil {
		t.Fatalf("ConvertV1ToV2: %v", err)
	}
	if !migrationLedgerHas(res.Ledger, "assume", true) {
		t.Fatalf("ledger missing resolved analysis assume: %+v", res.Ledger)
	}
	if len(res.Files) != 1 || strings.Contains(res.Files[0].Source, "TODO_v2Migrate") {
		t.Fatalf("analysis assume produced blocking stub: %+v", res.Files)
	}
}

func TestConvertV1ToV2AdapterMetadataBridge(t *testing.T) {
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
	var metaSource string
	for _, f := range res.Files {
		if strings.Contains(f.Source, "pattern adapterMetadata") {
			metaSource = f.Source
			break
		}
	}
	if metaSource == "" {
		t.Fatalf("metadata bridge file not emitted: %+v", res.Files)
	}
	if _, err := ParseV2(metaSource); err != nil {
		t.Fatalf("metadata bridge did not parse as v2: %v\n%s", err, metaSource)
	}
	decls, err := ParseV2Runtime(metaSource)
	if err != nil {
		t.Fatalf("metadata bridge did not lower: %v\n%s", err, metaSource)
	}
	ad := decls[0].(*AdapterDecl)
	if ad.Name != "textpattern" || ad.Meta["text_pattern_event"] != "analysis.text_pattern.credential_literal" {
		t.Fatalf("lowered metadata wrong: %+v", ad)
	}
	if got, ok := ad.Meta["text_pattern_extensions"].([]string); !ok || len(got) != 2 || got[0] != ".go" {
		t.Fatalf("lowered metadata list wrong: %#v", ad.Meta["text_pattern_extensions"])
	}
	if !migrationLedgerHas(res.Ledger, "adapter meta", true) {
		t.Fatalf("ledger missing adapter meta conversion: %+v", res.Ledger)
	}
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
