package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vyprai/vyql/parser"
)

func TestDefinitionsMigrateV2WritesFilesAndLedger(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "legacy.vyql")
	out := filepath.Join(dir, "out")
	ledger := filepath.Join(dir, "ledger.json")
	if err := os.WriteFile(in, []byte(`
module code;
concept HttpInput : source {}
concept SqlExecution : sink {}
module core;
concept SqlParameterization : control {}
adapter javascript {
  source "req.body" -> code.HttpInput
  sink method "execute" arg 0 -> code.SqlExecution
  control method "escapeSql" -> core.SqlParameterization
}
module rules.injection;
rule SqlInjection {
  taint code.HttpInput as input -> code.SqlExecution as sqlSink
  unless sanitized_by core.SqlParameterization
}
`), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	if err := cmdDefinitions([]string{"migrate-v2", "-in", in, "-out", out, "-ledger", ledger}); err != nil {
		t.Fatalf("migrate-v2: %v", err)
	}

	generated := filepath.Join(out, "rules", "injection", "SqlInjection.vyql")
	raw, err := os.ReadFile(generated)
	if err != nil {
		t.Fatalf("read generated rule: %v", err)
	}
	if !strings.Contains(string(raw), "unless sqlSink.path coveredBy core.SqlParameterization") {
		t.Fatalf("generated rule missing alias-aware coverage target:\n%s", raw)
	}
	if _, err := parser.ParseV2(string(raw)); err != nil {
		t.Fatalf("generated rule did not parse as v2: %v\n%s", err, raw)
	}
	if err := cmdDefinitions([]string{"check-v2", "-in", out}); err != nil {
		t.Fatalf("check-v2 should accept migrated output: %v", err)
	}

	records := readMigrationLedger(t, ledger)
	if !migrationCommandLedgerHas(records, "sanitized_by", true) {
		t.Fatalf("ledger missing sanitized_by suggestion: %+v", records)
	}
	sanitized := migrationCommandLedgerRecord(records, "sanitized_by", true)
	if sanitized.Line == 0 || !strings.Contains(sanitized.Original, "unless sanitized_by core.SqlParameterization") {
		t.Fatalf("sanitized_by ledger record missing source context: %+v", sanitized)
	}
	if !migrationCommandLedgerHas(records, "control", true) {
		t.Fatalf("ledger missing control coverage suggestion: %+v", records)
	}
}

func TestDefinitionsCheckV2RejectsLegacySyntax(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "legacy.vyql")
	if err := os.WriteFile(in, []byte(`adapter javascript { source "req.body" -> code.HttpInput }`), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	err := cmdDefinitions([]string{"check-v2", "-in", in})
	if err == nil {
		t.Fatal("check-v2 accepted legacy v1 syntax")
	}
	if !strings.Contains(err.Error(), "v2 parse failed") {
		t.Fatalf("check-v2 error = %v, want v2 parse diagnostic", err)
	}
}

func TestDefinitionsCheckV2RejectsDuplicateDeclarationsAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "a.vyql"), `module code;
concept Duplicate : source {}
`)
	writeTestFile(t, filepath.Join(dir, "b.vyql"), `module code;
concept Duplicate : source {}
`)

	err := cmdDefinitions([]string{"check-v2", "-in", dir})
	if err == nil || !strings.Contains(err.Error(), "duplicate v2 declaration code.Duplicate") {
		t.Fatalf("check-v2 error = %v, want duplicate declaration diagnostic", err)
	}
}

func TestDefinitionsCheckV2RejectsCrossFileEmitKindMismatch(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "concept.vyql"), `module code;
concept Thing : sink {}
`)
	writeTestFile(t, filepath.Join(dir, "binding.vyql"), `module bindings.javascript.test;
binding bad {
  query pattern callExpr where callee.path ~= "x"
  emit source code.Thing at call.result
}
`)

	err := cmdDefinitions([]string{"check-v2", "-in", dir})
	if err == nil || !strings.Contains(err.Error(), "emit source uses concept code.Thing of kind sink") {
		t.Fatalf("check-v2 error = %v, want emit kind mismatch diagnostic", err)
	}
}

func TestDefinitionsCheckV2RejectsCrossFileRuleEndpointMismatch(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "mechanics.vyql"), v2CoreMechanicsDefinition)
	writeTestFile(t, filepath.Join(dir, "concepts.vyql"), `module code;
concept Input : sink {}
concept Exec : sink {}
`)
	writeTestFile(t, filepath.Join(dir, "rule.vyql"), `module rules.test;
rule BadTaint {
  taint code.Input -> code.Exec
}
`)

	err := cmdDefinitions([]string{"check-v2", "-in", dir})
	if err == nil || !strings.Contains(err.Error(), "from uses concept code.Input of kind sink; want source") {
		t.Fatalf("check-v2 error = %v, want endpoint kind diagnostic", err)
	}
}

func TestDefinitionsCheckV2AllowsUsesAliasConceptKind(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "concept.vyql"), `module code;
concept HttpInput : source {}
`)
	writeTestFile(t, filepath.Join(dir, "binding.vyql"), `module bindings.javascript.test;
uses code.HttpInput as Input;
binding ok {
  query pattern callExpr where callee.path ~= "x"
  emit source Input at call.result
}
`)

	if err := cmdDefinitions([]string{"check-v2", "-in", dir}); err != nil {
		t.Fatalf("check-v2 should accept uses alias: %v", err)
	}
}

func TestDefinitionsCheckV2RejectsUnknownUses(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "binding.vyql"), `module bindings.javascript.test;
uses code.Missing;
binding bad {
  query pattern callExpr where callee.path ~= "x"
  emit source code.Missing at call.result
}
`)

	err := cmdDefinitions([]string{"check-v2", "-in", dir})
	if err == nil || !strings.Contains(err.Error(), "uses code.Missing does not resolve to a v2 declaration") {
		t.Fatalf("check-v2 error = %v, want unknown uses diagnostic", err)
	}
}

func TestDefinitionsCheckV2RejectsCoverageModeMissingFromCheckConcept(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "concepts.vyql"), `module core;
concept HttpInput : source {}
concept StateChange : sink {}
concept AuthorizationCheck : check { covers: [path] }
`)
	writeTestFile(t, filepath.Join(dir, "rule.vyql"), `module rules.authz;
rule MissingAuthorization {
  taint core.HttpInput -> core.StateChange as op
  unless op.endpoint coveredBy core.AuthorizationCheck
}
`)

	err := cmdDefinitions([]string{"check-v2", "-in", dir})
	if err == nil || !strings.Contains(err.Error(), `coverage mode "endpoint" not declared in concept covers [path]`) {
		t.Fatalf("check-v2 error = %v, want coverage-mode diagnostic", err)
	}
}

func TestDefinitionsCheckV2RejectsRuleVerbWithoutMechanic(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "concepts.vyql"), `module code;
concept Input : source {}
concept Exec : sink {}
`)
	writeTestFile(t, filepath.Join(dir, "rule.vyql"), `module rules.test;
rule MissingMechanic {
  taint code.Input -> code.Exec
}
`)

	err := cmdDefinitions([]string{"check-v2", "-in", dir})
	if err == nil || !strings.Contains(err.Error(), `uses verb "taint" without mechanic ruleVerb taint`) {
		t.Fatalf("check-v2 error = %v, want missing ruleVerb mechanic diagnostic", err)
	}
}

func TestDefinitionsCheckV2RejectsCoverageModeWithoutMechanic(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "concept.vyql"), `module core;
concept AuthorizationCheck : check { covers: [endpoint] }
`)

	err := cmdDefinitions([]string{"check-v2", "-in", dir})
	if err == nil || !strings.Contains(err.Error(), `coverage mode "endpoint" without mechanic coverage endpoint`) {
		t.Fatalf("check-v2 error = %v, want missing coverage mechanic diagnostic", err)
	}
}

func TestDefinitionsLintUnstableReportsQuarantinedUses(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "binding.vyql"), `module bindings.javascript.migration;
concept LegacyFlagIssue : issue {}
binding legacyFlag {
  unstable: {
    owner: "migration"
    reason: "legacy flag predicates depend on token matching"
  }
  query unstable.legacyFlag as node where node.kind == "any"
  emit issue LegacyFlagIssue at node
}
`)
	writeTestFile(t, filepath.Join(dir, "pattern.vyql"), `module patterns.javascript.migration;
pattern frameworkRoute as route {
  unstable: {
    owner: "frontend"
    reason: "route extraction fact schema is pending"
  }
  node: unstable.frameworkRoute
}
`)
	writeTestFile(t, filepath.Join(dir, "adapter-meta.vyql"), `module patterns.javascript.meta;
pattern adapterMetadata {
  unstable: {
    owner: "migration"
    reason: "v1 adapter package metadata is not modeled as stable v2 requirements yet"
    adapter: "javascript"
    meta: {
      package: "express"
    }
  }
}
`)

	files, err := vyqlFilesUnder(dir)
	if err != nil {
		t.Fatalf("list v2 files: %v", err)
	}
	uses, err := lintV2UnstableFiles(files)
	if err != nil {
		t.Fatalf("lint unstable: %v", err)
	}
	if len(uses) != 3 {
		t.Fatalf("unstable lint reported %d use(s), want 3: %+v", len(uses), uses)
	}
	want := map[string]string{
		"binding:legacyFlag":      "unstable.legacyFlag",
		"pattern:frameworkRoute":  "unstable.frameworkRoute",
		"pattern:adapterMetadata": "unstable.metadata",
	}
	for _, use := range uses {
		key := use.Kind + ":" + use.Name
		if want[key] != use.Target {
			t.Fatalf("unstable use %+v, want target %q for %s", use, want[key], key)
		}
		if use.Owner == "" || use.Reason == "" {
			t.Fatalf("unstable use missing owner/reason: %+v", use)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Fatalf("unstable lint missing uses: %+v", want)
	}
}

func TestDefinitionsLintUnstableCleanTree(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "clean.vyql"), `module code;
concept HttpInput : source {}
concept SqlExecution : sink {}
`)

	files, err := vyqlFilesUnder(dir)
	if err != nil {
		t.Fatalf("list v2 files: %v", err)
	}
	uses, err := lintV2UnstableFiles(files)
	if err != nil {
		t.Fatalf("lint unstable: %v", err)
	}
	if len(uses) != 0 {
		t.Fatalf("clean tree reported unstable uses: %+v", uses)
	}
}

func TestDefinitionsLintRequiresUnstableFlag(t *testing.T) {
	err := cmdDefinitions([]string{"lint", "-in", t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "requires --unstable") {
		t.Fatalf("lint error = %v, want --unstable requirement", err)
	}
}

func TestDefinitionsMigrateV2FailsOnUnresolvedConstructs(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "legacy.vyql")
	out := filepath.Join(dir, "out")
	if err := os.WriteFile(in, []byte(`
adapter javascript {
  flow prefix "decode" arg 1 from result
}
`), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	err := cmdDefinitions([]string{"migrate-v2", "-in", in, "-out", out})
	if err == nil || !strings.Contains(err.Error(), "unresolved construct") {
		t.Fatalf("migrate-v2 error = %v, want unresolved construct failure", err)
	}
	ledger := filepath.Join(out, "migration-ledger.json")
	records := readMigrationLedger(t, ledger)
	if !migrationCommandLedgerHas(records, "flow_prefix", false) {
		t.Fatalf("ledger missing unresolved flow_prefix: %+v", records)
	}
	var stubFound bool
	err = filepath.WalkDir(out, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".vyql") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(raw), "TODO_v2Migrate") {
			stubFound = true
			if _, err := parser.ParseV2(string(raw)); err == nil {
				t.Fatalf("blocking stub parsed successfully:\n%s", raw)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk output: %v", err)
	}
	if !stubFound {
		t.Fatalf("no blocking TODO_v2Migrate stub found under %s", out)
	}
}

func TestDefinitionsMigrateV2DirectoryPreservesInputRelativePaths(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in")
	out := filepath.Join(dir, "out")
	for subdir, pattern := range map[string]string{
		"a": "one",
		"b": "two",
	} {
		path := filepath.Join(in, subdir, "same.vyql")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		src := `adapter javascript { source "` + pattern + `" -> code.HttpInput }`
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatalf("write input: %v", err)
		}
	}
	writeTestFile(t, filepath.Join(in, "concepts.vyql"), `module code;
concept HttpInput : source {}
`)
	if err := cmdDefinitions([]string{"migrate-v2", "-in", in, "-out", out}); err != nil {
		t.Fatalf("migrate-v2: %v", err)
	}
	generated := []string{
		filepath.Join(out, "a", "same", "javascript", "000", "codeHttpInput.vyql"),
		filepath.Join(out, "b", "same", "javascript", "000", "codeHttpInput.vyql"),
	}
	for _, path := range generated {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read generated %s: %v", path, err)
		}
		if _, err := parser.ParseV2(string(raw)); err != nil {
			t.Fatalf("generated file %s did not parse as v2: %v\n%s", path, err, raw)
		}
	}
	aRaw, _ := os.ReadFile(generated[0])
	bRaw, _ := os.ReadFile(generated[1])
	if !strings.Contains(string(aRaw), `"one"`) || !strings.Contains(string(bRaw), `"two"`) {
		t.Fatalf("directory migration did not preserve both generated files:\n%s\n%s", aRaw, bRaw)
	}
}

func TestDefinitionsMigrateV2DirectoryCopiesSpecFixtures(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in")
	out := filepath.Join(dir, "out")
	def := filepath.Join(in, "packs", "runtime.vyql")
	spec := filepath.Join(in, "tests", "runtime.test.vyql")
	sidecar := filepath.Join(in, "adapters", "packages", "top1000.sources.json")
	if err := os.MkdirAll(filepath.Dir(def), 0o755); err != nil {
		t.Fatalf("mkdir def: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(spec), 0o755); err != nil {
		t.Fatalf("mkdir spec: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(sidecar), 0o755); err != nil {
		t.Fatalf("mkdir sidecar: %v", err)
	}
	if err := os.WriteFile(def, []byte(`module code;
concept HttpInput : source {}
concept StateChangingOp : sink {}
adapter javascript { source "req.body" -> code.HttpInput }
module rules.test;
rule StateChangeFlow {
  taint code.HttpInput -> code.StateChangingOp
}
rule StateChangeReview {
  match code.StateChangingOp as op
}`), 0o600); err != nil {
		t.Fatalf("write def: %v", err)
	}
	if err := os.WriteFile(spec, []byte("test \"fixture\"\n  expect VYQL-INJ-001\n  graph\n  ```\n  node src code.HttpInput\n  node op code.StateChangingOp\n  edge FLOWS src -> op\n  ```\n"), 0o600); err != nil {
		t.Fatalf("write spec: %v", err)
	}
	if err := os.WriteFile(sidecar, []byte(`{"schema":1}`+"\n"), 0o600); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}

	if err := cmdDefinitions([]string{"migrate-v2", "-in", in, "-out", out}); err != nil {
		t.Fatalf("migrate-v2: %v", err)
	}
	copiedSpec, err := os.ReadFile(filepath.Join(out, "tests", "runtime.test.vyql"))
	if err != nil {
		t.Fatalf("migrate-v2 should copy executable test specs: %v", err)
	}
	if !strings.Contains(string(copiedSpec), `test "fixture"`) {
		t.Fatalf("copied spec lost fixture content:\n%s", copiedSpec)
	}
	if !strings.Contains(string(copiedSpec), "label op code.StateChangingOpSink") {
		t.Fatalf("copied spec did not add v2 graph alias label:\n%s", copiedSpec)
	}
	if raw, err := os.ReadFile(filepath.Join(out, "adapters", "packages", "top1000.sources.json")); err != nil || string(raw) != "{\"schema\":1}\n" {
		t.Fatalf("migrate-v2 should copy non-vyql sidecar files, raw=%q err=%v", raw, err)
	}
	raw, err := os.ReadFile(filepath.Join(out, "packs", "runtime", "javascript", "000", "codeHttpInput.vyql"))
	if err != nil {
		t.Fatalf("read generated def: %v", err)
	}
	if _, err := parser.ParseV2(string(raw)); err != nil {
		t.Fatalf("generated definition did not parse as v2: %v\n%s", err, raw)
	}
}

func TestDefinitionsCheckV2RepositoryCorpus(t *testing.T) {
	repoRoot := testRepoRoot(t)
	in := filepath.Join(repoRoot, "vyql")

	inputDefinitions, inputSpecs, err := testCorpusFilesUnder(in)
	if err != nil {
		t.Fatalf("list input corpus: %v", err)
	}
	if len(inputDefinitions) == 0 {
		t.Fatalf("repo corpus under %s has no .vyql files", in)
	}

	if err := cmdDefinitions([]string{"check-v2", "-in", in}); err != nil {
		t.Fatalf("check-v2 repo corpus: %v", err)
	}
	specCount := 0
	for _, path := range inputSpecs {
		specCount += len(parseSpecFile(t, path))
	}
	if specCount == 0 {
		t.Fatalf("repo spec corpus has no executable specs")
	}
}

func readMigrationLedger(t *testing.T, path string) []parser.V2MigrationRecord {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	var records []parser.V2MigrationRecord
	if err := json.Unmarshal(raw, &records); err != nil {
		t.Fatalf("decode ledger: %v", err)
	}
	return records
}

func migrationCommandLedgerHas(records []parser.V2MigrationRecord, construct string, resolved bool) bool {
	return migrationCommandLedgerRecord(records, construct, resolved).Construct != ""
}

func migrationCommandLedgerRecord(records []parser.V2MigrationRecord, construct string, resolved bool) parser.V2MigrationRecord {
	for _, r := range records {
		if r.Construct == construct && r.Resolved == resolved {
			return r
		}
	}
	return parser.V2MigrationRecord{}
}

func testRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "vyql", "ontology", "concepts")); err != nil {
		t.Fatalf("locate repo root from %s: %v", file, err)
	}
	return root
}

func testCorpusFilesUnder(root string) (definitions []string, specs []string, err error) {
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".test.vyql") {
			specs = append(specs, path)
			return nil
		}
		if strings.HasSuffix(path, ".vyql") {
			definitions = append(definitions, path)
		}
		return nil
	})
	return definitions, specs, err
}

func writeTestFile(t *testing.T, path, src string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
