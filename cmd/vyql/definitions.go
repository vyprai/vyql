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

func cmdDefinitions(args []string) error {
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

func checkV2Sources(sources []parser.V2Source) (int, error) {
	if err := parser.ValidateV2Corpus(sources); err != nil {
		return 0, fmt.Errorf("v2 corpus validation failed: %w", err)
	}
	if _, err := parser.LowerV2SourcesToRuntime(sources); err != nil {
		return 0, fmt.Errorf("v2 lower failed: %w", err)
	}
	return len(sources), nil
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
