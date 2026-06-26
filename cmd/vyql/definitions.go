package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vyprai/vyql/definitions"
	"github.com/vyprai/vyql/parser"
)

type v1DefinitionFile struct {
	Path   string
	Source string
	Decls  []parser.Decl
}

type v2GeneratedDefinition struct {
	Path   string
	Source string
}

const v2CoreMechanicsDefinition = `module mechanics.core;

mechanic ruleVerb taint {
  solver: dataflow.taint
  fromKinds: [source]
  toKinds: [sink]
  allowedClauses: [where, coveredBy, confidence]
  defaultWitness: "taint"
  finding: true
}

mechanic ruleVerb flow {
  solver: dataflow.flow
  fromKinds: [source]
  toKinds: [sink]
  allowedClauses: [where, coveredBy, confidence]
  defaultWitness: "flow"
  finding: true
}

mechanic ruleVerb reach {
  solver: graph.reach
  fromKinds: [asset, exposure]
  toKinds: [asset, exposure]
  allowedClauses: [where, coveredBy, confidence]
  defaultWitness: "reach"
  finding: true
}

mechanic ruleVerb grant {
  solver: graph.grant
  fromKinds: [principal]
  toKinds: [principal, privilege]
  allowedClauses: [where, coveredBy, confidence]
  defaultWitness: "grant"
  finding: true
}

mechanic ruleVerb assume {
  solver: graph.assume
  fromKinds: [principal]
  toKinds: [principal, privilege]
  allowedClauses: [where, coveredBy, confidence]
  defaultWitness: "assume"
  finding: true
}

mechanic ruleVerb issue {
  solver: fact.exists
  fromKinds: [issue]
  allowedClauses: [where, coveredBy, confidence]
  defaultWitness: "issue"
  finding: true
}

mechanic ruleVerb fact {
  solver: fact.exists
  fromKinds: [fact, asset, exposure, principal, privilege, state, observation]
  allowedClauses: [where, coveredBy, confidence]
  defaultWitness: "fact"
  finding: true
}

mechanic ruleVerb query {
  solver: query.semantic
  fromKinds: [concept, fact, asset, exposure, principal, privilege, state, observation]
  allowedClauses: [where, confidence]
  defaultWitness: "query"
  finding: true
}

mechanic coverage path {
  capability: coverage.path
  coversWhen: solver.pathCovered(check.anchor, candidate.path)
  targetParts: [path]
  suppresses: true
}

mechanic coverage endpoint {
  capability: coverage.endpoint
  coversWhen: solver.sameEndpoint(check.anchor, candidate.endpoint)
  targetParts: [endpoint]
  suppresses: true
}

mechanic coverage sameReceiver {
  capability: coverage.sameReceiver
  coversWhen: solver.sameValue(check.anchor, candidate.sameReceiver)
  targetParts: [sameReceiver]
  suppresses: true
}

mechanic coverage sameScope {
  capability: coverage.sameScope
  coversWhen: solver.sameScope(check.anchor, candidate.sameScope)
  targetParts: [sameScope]
  suppresses: true
}

mechanic coverage dominates {
  capability: coverage.dominates
  coversWhen: solver.dominates(check.anchor, candidate.dominates)
  targetParts: [dominates]
  suppresses: true
}

mechanic coverage global {
  capability: coverage.global
  coversWhen: solver.always()
  targetParts: [global]
  suppresses: true
}
`

func cmdDefinitions(args []string) error {
	if len(args) > 0 && args[0] == "migrate-v2" {
		return cmdDefinitionsMigrateV2(args[1:])
	}
	if len(args) > 0 && args[0] == "check-v2" {
		return cmdDefinitionsCheckV2(args[1:])
	}
	if len(args) > 0 && args[0] == "lint" {
		return cmdDefinitionsLint(args[1:])
	}
	fs := flag.NewFlagSet("definitions", flag.ExitOnError)
	kind := fs.String("kind", "all", "definition kind: all | concepts | rules | adapters | reviews")
	lang := fs.String("lang", "", "adapter language filter, e.g. python, javascript, go")
	query := fs.String("query", "", "case-insensitive substring filter across names, concepts, patterns, packages, CWE, and text")
	max := fs.Int("max", 80, "maximum rows per section")
	format := fs.String("format", "text", "output format: text | json")
	_ = fs.Parse(args)

	cat, err := definitions.Inspect(definitions.InspectOptions{
		Kind:     *kind,
		Language: *lang,
		Query:    *query,
		Max:      *max,
	})
	if err != nil {
		return err
	}
	switch *format {
	case "json":
		b, err := json.MarshalIndent(cat, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
	case "text":
		printDefinitions(cat)
	default:
		return fmt.Errorf("unknown -format %q (use text or json)", *format)
	}
	return nil
}

type v2UnstableUse struct {
	Source string
	Module string
	Kind   string
	Name   string
	Target string
	Owner  string
	Reason string
}

func cmdDefinitionsLint(args []string) error {
	fs := flag.NewFlagSet("definitions lint", flag.ExitOnError)
	in := fs.String("in", "", "v2 .vyql file or directory to lint")
	unstable := fs.Bool("unstable", false, "report quarantined unstable.* v2 uses")
	_ = fs.Parse(args)
	if !*unstable {
		return fmt.Errorf("definitions lint currently requires --unstable")
	}
	if *in == "" {
		return fmt.Errorf("definitions lint --unstable requires -in <file|dir>")
	}
	files, err := vyqlFilesUnder(*in)
	if err != nil {
		return err
	}
	uses, err := lintV2UnstableFiles(files)
	if err != nil {
		return err
	}
	if len(uses) == 0 {
		fmt.Printf("no unstable v2 uses under %s\n", *in)
		return nil
	}
	for _, use := range uses {
		fmt.Printf("%s: %s %s %s: %s owner=%q reason=%q\n", use.Source, use.Module, use.Kind, use.Name, use.Target, use.Owner, use.Reason)
	}
	fmt.Printf("found %d unstable v2 use(s) under %s\n", len(uses), *in)
	return nil
}

func lintV2UnstableFiles(files []string) ([]v2UnstableUse, error) {
	uses := make([]v2UnstableUse, 0)
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		prog, err := parser.ParseV2(string(raw))
		if err != nil {
			return nil, fmt.Errorf("%s: v2 parse failed: %w", path, err)
		}
		uses = append(uses, collectV2UnstableUses(path, prog)...)
	}
	sort.Slice(uses, func(i, j int) bool {
		if uses[i].Source != uses[j].Source {
			return uses[i].Source < uses[j].Source
		}
		if uses[i].Module != uses[j].Module {
			return uses[i].Module < uses[j].Module
		}
		if uses[i].Kind != uses[j].Kind {
			return uses[i].Kind < uses[j].Kind
		}
		if uses[i].Name != uses[j].Name {
			return uses[i].Name < uses[j].Name
		}
		return uses[i].Target < uses[j].Target
	})
	return uses, nil
}

func collectV2UnstableUses(source string, prog *parser.V2Program) []v2UnstableUse {
	if prog == nil {
		return nil
	}
	uses := make([]v2UnstableUse, 0)
	for _, d := range prog.Decls {
		switch x := d.(type) {
		case *parser.V2BindingDecl:
			owner, reason := v2UnstableMetaStrings(x.Unstable)
			uses = append(uses, collectV2QueryUnstableUses(source, prog.Module, "binding", x.Name, owner, reason, x.Query.Expr)...)
		case *parser.V2PatternDecl:
			owner, reason, hasMeta := v2PatternUnstableMeta(x.Items)
			before := len(uses)
			for _, item := range x.Items {
				if item.Kind == "node" && strings.HasPrefix(item.Name, "unstable.") {
					uses = append(uses, v2UnstableUse{Source: source, Module: prog.Module, Kind: "pattern", Name: x.Name, Target: item.Name, Owner: owner, Reason: reason})
				}
			}
			if len(uses) == before && hasMeta {
				uses = append(uses, v2UnstableUse{Source: source, Module: prog.Module, Kind: "pattern", Name: x.Name, Target: "unstable.metadata", Owner: owner, Reason: reason})
			}
		case *parser.V2RuleDecl:
			uses = append(uses, collectV2QueryUnstableUses(source, prog.Module, "rule", x.Name, "", "", x.Body.Query)...)
		}
	}
	return uses
}

func collectV2QueryUnstableUses(source, module, kind, name, owner, reason string, q *parser.V2QueryExpr) []v2UnstableUse {
	if q == nil {
		return nil
	}
	uses := make([]v2UnstableUse, 0, 1+len(q.Steps))
	if strings.HasPrefix(q.Family, "unstable.") {
		uses = append(uses, v2UnstableUse{Source: source, Module: module, Kind: kind, Name: name, Target: q.Family, Owner: owner, Reason: reason})
	}
	for _, step := range q.Steps {
		if strings.HasPrefix(step.Family, "unstable.") {
			uses = append(uses, v2UnstableUse{Source: source, Module: module, Kind: kind, Name: name, Target: step.Family, Owner: owner, Reason: reason})
		}
	}
	return uses
}

func v2PatternUnstableMeta(items []parser.V2PatternItem) (owner, reason string, ok bool) {
	for _, item := range items {
		if item.Kind != "unstable" {
			continue
		}
		owner, reason = v2UnstableMetaStrings(item.Meta)
		return owner, reason, true
	}
	return "", "", false
}

func v2UnstableMetaStrings(meta map[string]any) (owner, reason string) {
	owner, _ = meta["owner"].(string)
	reason, _ = meta["reason"].(string)
	return strings.TrimSpace(owner), strings.TrimSpace(reason)
}

func cmdDefinitionsCheckV2(args []string) error {
	fs := flag.NewFlagSet("definitions check-v2", flag.ExitOnError)
	in := fs.String("in", "", "v2 .vyql file or directory to verify without v1 fallback")
	_ = fs.Parse(args)
	if *in == "" {
		return fmt.Errorf("definitions check-v2 requires -in <file|dir>")
	}
	files, err := vyqlFilesUnder(*in)
	if err != nil {
		return err
	}
	checked, err := checkV2DefinitionFiles(files)
	if err != nil {
		return err
	}
	fmt.Printf("checked %d v2 definition file(s) under %s\n", checked, *in)
	return nil
}

func cmdDefinitionsMigrateV2(args []string) error {
	fs := flag.NewFlagSet("definitions migrate-v2", flag.ExitOnError)
	in := fs.String("in", "", "legacy v1 .vyql file or directory to convert")
	outDir := fs.String("out", "", "output directory for generated v2 .vyql files")
	ledgerPath := fs.String("ledger", "", "optional JSON migration ledger path (default: <out>/migration-ledger.json)")
	_ = fs.Parse(args)
	if *in == "" {
		return fmt.Errorf("definitions migrate-v2 requires -in <file|dir>")
	}
	if *outDir == "" {
		return fmt.Errorf("definitions migrate-v2 requires -out <dir>")
	}
	inputInfo, err := os.Stat(*in)
	if err != nil {
		return err
	}
	files, sidecars, err := migrationInputFilesUnder(*in, inputInfo.IsDir())
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no .vyql files found under %s", *in)
	}
	parsedFiles := make([]v1DefinitionFile, 0, len(files))
	var allDecls []parser.Decl
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		decls, err := parser.Parse(string(raw))
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		parsedFiles = append(parsedFiles, v1DefinitionFile{Path: path, Source: string(raw), Decls: decls})
		allDecls = append(allDecls, decls...)
	}
	kindPlan := parser.InferV2MigrationKindPlan(allDecls)
	generatedEstimate := migrationGeneratedDefinitionEstimate(allDecls, kindPlan) + 1
	allRecords := make([]parser.V2MigrationRecord, 0, generatedEstimate)
	madeDirs := make(map[string]bool, len(files))
	generatedDefinitions := make([]v2GeneratedDefinition, 0, generatedEstimate)
	generatedIndex := make(map[string]int, len(files))
	written := 0
	for _, src := range parsedFiles {
		res := parser.ConvertParsedV1ToV2WithKindPlanAndSource(src.Decls, src.Path, src.Source, kindPlan)
		for _, f := range res.Files {
			dst := filepath.Join(*outDir, migrationOutputPrefix(*in, src.Path, inputInfo.IsDir()), filepath.FromSlash(f.PathHint))
			dir := filepath.Dir(dst)
			if !madeDirs[dir] {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					return err
				}
				madeDirs[dir] = true
			}
			if err := os.WriteFile(dst, []byte(f.Source), 0o644); err != nil {
				return err
			}
			if idx, ok := generatedIndex[dst]; ok {
				generatedDefinitions[idx].Source = f.Source
			} else {
				generatedIndex[dst] = len(generatedDefinitions)
				generatedDefinitions = append(generatedDefinitions, v2GeneratedDefinition{Path: dst, Source: f.Source})
			}
			written++
		}
		allRecords = append(allRecords, res.Ledger...)
	}
	mechanicsPath := filepath.Join(*outDir, "mechanics", "core.vyql")
	if _, ok := generatedIndex[mechanicsPath]; !ok {
		if err := os.MkdirAll(filepath.Dir(mechanicsPath), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(mechanicsPath, []byte(v2CoreMechanicsDefinition), 0o644); err != nil {
			return err
		}
		generatedIndex[mechanicsPath] = len(generatedDefinitions)
		generatedDefinitions = append(generatedDefinitions, v2GeneratedDefinition{Path: mechanicsPath, Source: v2CoreMechanicsDefinition})
		written++
	}
	copied, err := copyMigrationSidecars(*in, *outDir, sidecars, kindPlan)
	if err != nil {
		return err
	}
	sort.Slice(allRecords, func(i, j int) bool {
		if allRecords[i].File != allRecords[j].File {
			return allRecords[i].File < allRecords[j].File
		}
		if allRecords[i].Declaration != allRecords[j].Declaration {
			return allRecords[i].Declaration < allRecords[j].Declaration
		}
		return allRecords[i].Construct < allRecords[j].Construct
	})
	ledger := *ledgerPath
	if ledger == "" {
		ledger = filepath.Join(*outDir, "migration-ledger.json")
	}
	if err := os.MkdirAll(filepath.Dir(ledger), 0o755); err != nil {
		return err
	}
	ledgerBytes, err := json.MarshalIndent(allRecords, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(ledger, append(ledgerBytes, '\n'), 0o644); err != nil {
		return err
	}
	unresolved := 0
	for _, r := range allRecords {
		if !r.Resolved {
			unresolved++
		}
	}
	if unresolved == 0 {
		if _, err := checkV2GeneratedDefinitionSources(generatedDefinitions); err != nil {
			return err
		}
	}
	if copied > 0 {
		fmt.Printf("wrote %d v2 file(s), copied %d sidecar file(s), and %d ledger record(s) to %s\n", written, copied, len(allRecords), *outDir)
	} else {
		fmt.Printf("wrote %d v2 file(s) and %d ledger record(s) to %s\n", written, len(allRecords), *outDir)
	}
	if unresolved > 0 {
		return fmt.Errorf("v2 migration has %d unresolved construct(s); see %s", unresolved, ledger)
	}
	return nil
}

func migrationGeneratedDefinitionEstimate(decls []parser.Decl, kindPlan parser.V2MigrationKindPlan) int {
	estimate := 0
	for _, d := range decls {
		switch x := d.(type) {
		case *parser.AdapterDecl:
			estimate += len(x.Mappings)
			if len(x.Meta) > 0 {
				estimate++
			}
		case *parser.ConceptDecl:
			estimate++
			estimate += len(kindPlan.Aliases[x.QualifiedName()])
		default:
			estimate++
		}
	}
	if estimate < len(decls) {
		return len(decls)
	}
	return estimate
}

func checkV2DefinitionFiles(files []string) (int, error) {
	if len(files) == 0 {
		return 0, fmt.Errorf("no .vyql files found")
	}
	sources := make([]parser.V2Source, 0, len(files))
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			return 0, err
		}
		prog, err := parser.ParseV2(string(raw))
		if err != nil {
			return 0, fmt.Errorf("%s: v2 parse failed: %w", path, err)
		}
		sources = append(sources, parser.V2Source{Name: path, Program: prog})
	}
	return checkV2Sources(sources)
}

func checkV2GeneratedDefinitionSources(files []v2GeneratedDefinition) (int, error) {
	if len(files) == 0 {
		return 0, fmt.Errorf("no .vyql files found")
	}
	sources := make([]parser.V2Source, 0, len(files))
	for _, file := range files {
		prog, err := parser.ParseV2(file.Source)
		if err != nil {
			return 0, fmt.Errorf("%s: v2 parse failed: %w", file.Path, err)
		}
		sources = append(sources, parser.V2Source{Name: file.Path, Program: prog})
	}
	return checkV2Sources(sources)
}

func checkV2Sources(sources []parser.V2Source) (int, error) {
	if err := parser.ValidateV2Corpus(sources); err != nil {
		return 0, fmt.Errorf("v2 corpus validation failed: %w", err)
	}
	if _, err := parser.LowerV2SourcesToRuntime(sources); err != nil {
		return 0, fmt.Errorf("v2 lower failed: %w", err)
	}
	return len(sources), nil
}

func migrationOutputPrefix(root, file string, rootIsDir bool) string {
	if !rootIsDir {
		return ""
	}
	rel, err := filepath.Rel(root, file)
	if err != nil {
		return ""
	}
	ext := filepath.Ext(rel)
	rel = strings.TrimSuffix(rel, ext)
	if rel == "." || rel == "" {
		return ""
	}
	return filepath.FromSlash(filepath.ToSlash(rel))
}

func vyqlFilesUnder(root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		if strings.HasSuffix(root, ".vyql") {
			return []string{root}, nil
		}
		return nil, fmt.Errorf("%s is not a .vyql file", root)
	}
	var files []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".test.vyql") {
			return nil
		}
		if strings.HasSuffix(path, ".vyql") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func migrationInputFilesUnder(root string, rootIsDir bool) ([]string, []string, error) {
	if !rootIsDir {
		if strings.HasSuffix(root, ".vyql") && !strings.HasSuffix(root, ".test.vyql") {
			return []string{root}, nil, nil
		}
		return nil, nil, fmt.Errorf("%s is not a .vyql definition file", root)
	}
	var definitions []string
	var sidecars []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".vyql") && !strings.HasSuffix(path, ".test.vyql") {
			definitions = append(definitions, path)
			return nil
		}
		sidecars = append(sidecars, path)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(definitions)
	sort.Strings(sidecars)
	return definitions, sidecars, nil
}

func copyMigrationSidecars(root, outDir string, files []string, kindPlan parser.V2MigrationKindPlan) (int, error) {
	copied := 0
	for _, src := range files {
		rel, err := filepath.Rel(root, src)
		if err != nil {
			return copied, err
		}
		dst := filepath.Join(outDir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return copied, err
		}
		data, err := os.ReadFile(src)
		if err != nil {
			return copied, err
		}
		if strings.HasSuffix(src, ".test.vyql") {
			data = []byte(convertV2TestSidecar(string(data), kindPlan))
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return copied, err
		}
		copied++
	}
	return copied, nil
}

func convertV2TestSidecar(src string, kindPlan parser.V2MigrationKindPlan) string {
	if len(kindPlan.Aliases) == 0 || !strings.Contains(src, "\n  graph") {
		return src
	}
	lines := strings.Split(src, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		out = append(out, line)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.Contains(trimmed, "{") && !strings.HasPrefix(trimmed, "node ") && !strings.HasPrefix(trimmed, "label ") {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(strings.SplitN(trimmed, "{", 2)[0]))
		if len(fields) < 3 || (fields[0] != "node" && fields[0] != "label") {
			continue
		}
		alias := v2GraphConceptAlias(fields[2], kindPlan)
		if alias == "" {
			continue
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		out = append(out, indent+"label "+fields[1]+" "+alias)
	}
	return strings.Join(out, "\n")
}

func v2GraphConceptAlias(concept string, kindPlan parser.V2MigrationKindPlan) string {
	aliases := kindPlan.Aliases[concept]
	if len(aliases) == 0 {
		return ""
	}
	for _, kind := range []string{"sink", "source", "check", "principal", "privilege", "asset", "exposure", "state", "fact"} {
		if alias := aliases[kind]; alias != "" {
			return alias
		}
	}
	return ""
}

func printDefinitions(cat definitions.Catalog) {
	fmt.Printf("VyQL definitions: %s\n", cat.Root)
	fmt.Printf("loaded: concepts=%d rules=%d adapters=%d reviews=%d\n", cat.Stats.Concepts, cat.Stats.Rules, cat.Stats.Adapters, cat.Stats.Reviews)
	if len(cat.Concepts) > 0 {
		fmt.Printf("\n== concepts (%d shown) ==\n", len(cat.Concepts))
		for _, c := range cat.Concepts {
			parts := []string{c.Name}
			if c.Kind != "" {
				parts = append(parts, "kind="+c.Kind)
			}
			if len(c.CWE) > 0 {
				parts = append(parts, "cwe="+strings.Join(c.CWE, ","))
			}
			if c.Review != "" {
				parts = append(parts, "review="+compactLine(c.Review, 90))
			}
			fmt.Printf("  %s  (%s)\n", strings.Join(parts, " "), c.Source)
		}
	}
	if len(cat.Rules) > 0 {
		fmt.Printf("\n== rules (%d shown) ==\n", len(cat.Rules))
		for _, r := range cat.Rules {
			parts := []string{r.ID}
			if r.Severity != "" {
				parts = append(parts, "severity="+r.Severity)
			}
			if len(r.CWE) > 0 {
				parts = append(parts, "cwe="+strings.Join(r.CWE, ","))
			}
			if len(r.Concepts) > 0 {
				parts = append(parts, "concepts="+strings.Join(r.Concepts, ","))
			}
			fmt.Printf("  %s  (%s)\n", strings.Join(parts, " "), r.Source)
		}
	}
	if len(cat.Adapters) > 0 {
		fmt.Printf("\n== adapters (%d shown) ==\n", len(cat.Adapters))
		for _, m := range cat.Adapters {
			parts := []string{m.Language, m.Kind}
			if m.Pattern != "" {
				parts = append(parts, fmt.Sprintf("%q", m.Pattern))
			}
			if m.Concept != "" {
				parts = append(parts, "-> "+m.Concept)
			}
			if len(m.Packages) > 0 {
				parts = append(parts, "packages="+strings.Join(m.Packages, ","))
			}
			if m.Scope != "" {
				parts = append(parts, "scope="+m.Scope)
			}
			if m.NodeKind != "" {
				parts = append(parts, "node="+m.NodeKind)
			}
			fmt.Printf("  %s  (%s)\n", strings.Join(parts, " "), m.Source)
		}
	}
	if len(cat.Reviews) > 0 {
		fmt.Printf("\n== reviews (%d shown) ==\n", len(cat.Reviews))
		for _, r := range cat.Reviews {
			parts := []string{r.Concept}
			if r.Category != "" {
				parts = append(parts, "category="+r.Category)
			}
			if r.Kind != "" {
				parts = append(parts, "kind="+r.Kind)
			}
			if r.Text != "" {
				parts = append(parts, "text="+compactLine(r.Text, 90))
			}
			fmt.Printf("  %s  (%s)\n", strings.Join(parts, " "), r.Source)
		}
	}
}

func compactLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if max > 0 && len(s) > max {
		return s[:max-1] + "..."
	}
	return s
}
