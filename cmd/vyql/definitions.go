package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/definitions"
	"github.com/vyprai/vyql/parser"
)

func cmdDefinitions(args []string) error {
	if len(args) > 0 && args[0] == "check-v2" {
		return cmdDefinitionsCheckV2(args[1:])
	}
	if len(args) > 0 && args[0] == "validate" {
		return cmdDefinitionsValidate(args[1:])
	}
	if len(args) > 0 && args[0] == "lint" {
		return cmdDefinitionsLint(args[1:])
	}
	if len(args) > 0 && args[0] == "search" {
		return cmdDefinitionsSearch(args[1:])
	}
	if len(args) > 0 && args[0] == "refs" {
		return cmdDefinitionsRefs(args[1:])
	}
	if len(args) > 0 && args[0] == "explain" {
		return cmdDefinitionsExplain(args[1:])
	}
	if len(args) > 0 && args[0] == "show-policy" {
		return cmdDefinitionsShowPolicy(args[1:])
	}
	if len(args) > 0 && args[0] == "show-mechanic" {
		return cmdDefinitionsShowMechanic(args[1:])
	}
	fs := flag.NewFlagSet("definitions", flag.ExitOnError)
	kind := fs.String("kind", "all", "definition kind: all | concepts | rules | bindings | reviews")
	lang := fs.String("lang", "", "binding language filter, e.g. python, javascript, go")
	query := fs.String("query", "", "case-insensitive substring filter across names, concepts, patterns, packages, CWE, and text")
	max := fs.Int("max", 80, "maximum rows per section")
	format := fs.String("format", "text", "output format: text | json")
	_ = fs.Parse(args)

	// An unrecognised kind selects nothing, and the report then states that zero
	// concepts, rules and bindings are loaded -- which describes a broken
	// installation, not a typo.
	if err := validateDefinitionKind(*kind); err != nil {
		return err
	}

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

type v2PolicyView struct {
	Kind   string            `json:"kind"`
	Name   string            `json:"name"`
	Module string            `json:"module,omitempty"`
	Source string            `json:"source,omitempty"`
	Items  []v2BlockItemView `json:"items"`
}

type v2MechanicView struct {
	Kind       string            `json:"kind"`
	Name       string            `json:"name"`
	Source     string            `json:"source"`
	Capability string            `json:"capability,omitempty"`
	Fields     map[string]any    `json:"fields,omitempty"`
	Items      []v2BlockItemView `json:"items,omitempty"`
}

type v2BlockItemView struct {
	Key   string `json:"key"`
	Value string `json:"value,omitempty"`
}

type v2RefView struct {
	Target string `json:"target"`
	Source string `json:"source"`
	Module string `json:"module,omitempty"`
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Field  string `json:"field,omitempty"`
	Value  string `json:"value,omitempty"`
}

func cmdDefinitionsSearch(args []string) error {
	fs := flag.NewFlagSet("definitions search", flag.ExitOnError)
	kind := fs.String("kind", "all", "definition kind: all | concepts | rules | bindings | reviews | packs")
	lang := fs.String("lang", "", "binding language filter, e.g. python, javascript, go")
	max := fs.Int("max", 80, "maximum rows per section")
	format := fs.String("format", "text", "output format: text | json")
	_ = fs.Parse(args)
	query := strings.Join(fs.Args(), " ")
	if strings.TrimSpace(query) == "" {
		return fmt.Errorf("definitions search requires query text")
	}
	cat, err := definitions.Inspect(definitions.InspectOptions{
		Kind:     *kind,
		Language: *lang,
		Query:    query,
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

func cmdDefinitionsRefs(args []string) error {
	fs := flag.NewFlagSet("definitions refs", flag.ExitOnError)
	in := fs.String("in", datadirRoot(), "v2 .vyql file or directory to inspect")
	format := fs.String("format", "text", "output format: text | json")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("definitions refs requires <definition-or-concept>, e.g. core.SqlParameterization")
	}
	target := strings.TrimSpace(fs.Arg(0))
	files, err := vyqlFilesUnder(*in)
	if err != nil {
		return err
	}
	refs, err := collectV2Refs(files, target)
	if err != nil {
		return err
	}
	switch *format {
	case "json":
		b, err := json.MarshalIndent(refs, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
	case "text":
		printV2Refs(target, refs)
	default:
		return fmt.Errorf("unknown -format %q (use text or json)", *format)
	}
	return nil
}

func cmdDefinitionsShowPolicy(args []string) error {
	fs := flag.NewFlagSet("definitions show-policy", flag.ExitOnError)
	format := fs.String("format", "text", "output format: text | json")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("definitions show-policy requires <kind.name>, e.g. resultIdentity.default")
	}
	kind, name, err := splitDefinitionKindName(fs.Arg(0))
	if err != nil {
		return err
	}
	policy, err := findV2Policy(kind, name)
	if err != nil {
		return err
	}
	switch *format {
	case "json":
		b, err := json.MarshalIndent(policy, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
	case "text":
		printV2PolicyView(policy)
	default:
		return fmt.Errorf("unknown -format %q (use text or json)", *format)
	}
	return nil
}

func cmdDefinitionsShowMechanic(args []string) error {
	fs := flag.NewFlagSet("definitions show-mechanic", flag.ExitOnError)
	format := fs.String("format", "text", "output format: text | json")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("definitions show-mechanic requires <kind.name>, e.g. ruleVerb.taint")
	}
	kind, name, err := splitDefinitionKindName(fs.Arg(0))
	if err != nil {
		return err
	}
	mechanic, err := findV2Mechanic(kind, name)
	if err != nil {
		return err
	}
	switch *format {
	case "json":
		b, err := json.MarshalIndent(mechanic, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
	case "text":
		printV2MechanicView(mechanic)
	default:
		return fmt.Errorf("unknown -format %q (use text or json)", *format)
	}
	return nil
}

func splitDefinitionKindName(raw string) (kind, name string, err error) {
	raw = strings.TrimSpace(raw)
	kind, name, ok := strings.Cut(raw, ".")
	if !ok || kind == "" || name == "" || strings.Contains(name, ".") {
		return "", "", fmt.Errorf("definition id %q must be <kind.name>", raw)
	}
	return kind, name, nil
}

func findV2Policy(kind, name string) (v2PolicyView, error) {
	files, err := vyqlFilesUnder(filepath.Join(datadirRoot(), "policies"))
	if err != nil {
		return v2PolicyView{}, err
	}
	var matches []v2PolicyView
	for _, path := range files {
		prog, err := parseV2File(path)
		if err != nil {
			return v2PolicyView{}, err
		}
		for _, decl := range prog.Decls {
			p, ok := decl.(*parser.V2PolicyDecl)
			if !ok || p.Kind != kind || p.Name != name {
				continue
			}
			matches = append(matches, v2PolicyView{
				Kind: p.Kind, Name: p.Name, Module: p.Module, Source: relPathFromDataRoot(path),
				Items: v2BlockItemsView(p.Items),
			})
		}
	}
	if len(matches) == 0 {
		return v2PolicyView{}, fmt.Errorf("policy %s.%s not found", kind, name)
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].Source < matches[j].Source })
	return matches[0], nil
}

func findV2Mechanic(kind, name string) (v2MechanicView, error) {
	if builtin, ok := builtinV2MechanicView(kind, name); ok {
		return builtin, nil
	}
	files, err := vyqlFilesUnder(datadirRoot())
	if err != nil {
		return v2MechanicView{}, err
	}
	var matches []v2MechanicView
	for _, path := range files {
		prog, err := parseV2File(path)
		if err != nil {
			return v2MechanicView{}, err
		}
		for _, decl := range prog.Decls {
			m, ok := decl.(*parser.V2MechanicDecl)
			if !ok || m.Kind != kind || m.Name != name {
				continue
			}
			matches = append(matches, v2MechanicView{
				Kind: m.Kind, Name: m.Name, Source: relPathFromDataRoot(path),
				Items: v2BlockItemsView(m.Items),
			})
		}
	}
	if len(matches) == 0 {
		return v2MechanicView{}, fmt.Errorf("mechanic %s.%s not found", kind, name)
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].Source < matches[j].Source })
	return matches[0], nil
}

func builtinV2MechanicView(kind, name string) (v2MechanicView, bool) {
	if kind == "ruleVerb" {
		solvers := map[string]string{
			"taint": "dataflow.taint",
			"reach": "graph.reach",
			"grant": "graph.grant",
			"issue": "fact.exists",
			"fact":  "fact.exists",
			"query": "query.semantic",
		}
		if solver := solvers[name]; solver != "" {
			return v2MechanicView{
				Kind: kind, Name: name, Source: "<builtin:go>", Capability: solver,
				Fields: map[string]any{"authored": false},
			}, true
		}
	}
	if kind == "coverage" {
		capabilities := map[string]string{
			"path": "coverage.path", "endpoint": "coverage.endpoint", "sameReceiver": "coverage.sameReceiver",
			"sameScope": "coverage.sameScope", "dominates": "coverage.dominates", "postDominates": "coverage.postDominates",
			"global": "coverage.global",
		}
		if cap := capabilities[name]; cap != "" {
			return v2MechanicView{
				Kind: kind, Name: name, Source: "<builtin:go>", Capability: cap,
				Fields: map[string]any{"authored": false, "requiresAnchor": name != "global"},
			}, true
		}
	}
	return v2MechanicView{}, false
}

func parseV2File(path string) (*parser.V2Program, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	prog, err := parser.ParseV2(string(raw))
	if err != nil {
		return nil, fmt.Errorf("%s: v2 parse failed: %w", path, err)
	}
	return prog, nil
}

func datadirRoot() string {
	return filepath.Clean(datadir.Root())
}

func relPathFromDataRoot(path string) string {
	rel, err := filepath.Rel(datadirRoot(), path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

func v2BlockItemsView(items []parser.V2BlockItem) []v2BlockItemView {
	out := make([]v2BlockItemView, 0, len(items))
	for _, item := range items {
		out = append(out, v2BlockItemView{Key: strings.Join(item.Key, "."), Value: v2BlockValueString(item.Value)})
	}
	return out
}

func v2BlockValueString(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return strconv.Quote(v)
	case int, bool:
		return fmt.Sprint(v)
	case parser.V2RefExpr:
		return v.Name
	case parser.V2LiteralExpr:
		return v2BlockValueString(v.Value)
	case parser.V2CallExpr:
		args := make([]string, 0, len(v.Args))
		for _, arg := range v.Args {
			args = append(args, v2BlockValueString(arg))
		}
		return v.Name + "(" + strings.Join(args, ", ") + ")"
	case parser.V2UnaryExpr:
		return v.Op + " " + v2BlockValueString(v.X)
	case parser.V2BinaryExpr:
		return v2BlockValueString(v.Left) + " " + v.Op + " " + v2BlockValueString(v.Right)
	case parser.V2SequenceExpr:
		parts := make([]string, 0, len(v.Items))
		for _, item := range v.Items {
			parts = append(parts, v2BlockValueString(item))
		}
		return strings.Join(parts, " ")
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			parts = append(parts, v2BlockListValueString(item))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	default:
		return fmt.Sprint(v)
	}
}

func v2BlockListValueString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case parser.V2LiteralExpr:
		return v2BlockListValueString(v.Value)
	default:
		return v2BlockValueString(value)
	}
}

func printV2PolicyView(policy v2PolicyView) {
	fmt.Printf("policy %s.%s\n", policy.Kind, policy.Name)
	if policy.Module != "" {
		fmt.Printf("module: %s\n", policy.Module)
	}
	if policy.Source != "" {
		fmt.Printf("source: %s\n", policy.Source)
	}
	for _, item := range policy.Items {
		fmt.Printf("%s: %s\n", item.Key, item.Value)
	}
}

func printV2MechanicView(mechanic v2MechanicView) {
	fmt.Printf("mechanic %s.%s\n", mechanic.Kind, mechanic.Name)
	fmt.Printf("source: %s\n", mechanic.Source)
	if mechanic.Capability != "" {
		fmt.Printf("capability: %s\n", mechanic.Capability)
	}
	keys := make([]string, 0, len(mechanic.Fields))
	for key := range mechanic.Fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Printf("%s: %v\n", key, mechanic.Fields[key])
	}
	for _, item := range mechanic.Items {
		fmt.Printf("%s: %s\n", item.Key, item.Value)
	}
}

func collectV2Refs(files []string, target string) ([]v2RefView, error) {
	var refs []v2RefView
	for _, path := range files {
		prog, err := parseV2File(path)
		if err != nil {
			return nil, err
		}
		source := relPathFromDataRoot(path)
		for _, use := range prog.Uses {
			if v2RefMatches(target, use.Name) || v2RefMatches(target, use.Alias) {
				refs = append(refs, v2RefView{Target: target, Source: source, Module: prog.Module, Kind: "uses", Name: use.Name, Field: "uses", Value: use.Alias})
			}
		}
		for _, decl := range prog.Decls {
			refs = append(refs, collectV2DeclRefs(source, prog.Module, target, decl)...)
		}
	}
	sort.Slice(refs, func(i, j int) bool {
		a, b := refs[i], refs[j]
		return strings.Join([]string{a.Source, a.Module, a.Kind, a.Name, a.Field, a.Value}, "\x00") <
			strings.Join([]string{b.Source, b.Module, b.Kind, b.Name, b.Field, b.Value}, "\x00")
	})
	return refs, nil
}

func collectV2DeclRefs(source, module, target string, decl parser.V2Decl) []v2RefView {
	addValueRefs := func(kind, name, field string, value any) []v2RefView {
		var refs []v2RefView
		collectV2ValueRefs(target, field, value, func(f, v string) {
			refs = append(refs, v2RefView{Target: target, Source: source, Module: module, Kind: kind, Name: name, Field: f, Value: v})
		})
		return refs
	}
	switch x := decl.(type) {
	case *parser.V2ConceptDecl:
		return addValueRefs("concept", x.Name, "fields", x.Fields)
	case *parser.V2ThreatDecl:
		return addValueRefs("threat", x.Name, "fields", x.Fields)
	case *parser.V2PatternDecl:
		var refs []v2RefView
		for _, item := range x.Items {
			if v2RefMatches(target, item.Name) {
				refs = append(refs, v2RefView{Target: target, Source: source, Module: module, Kind: "pattern", Name: x.Name, Field: item.Kind, Value: item.Name})
			}
			refs = append(refs, addValueRefs("pattern", x.Name, item.Kind, item.Expr)...)
			refs = append(refs, addValueRefs("pattern", x.Name, item.Kind+".meta", item.Meta)...)
		}
		return refs
	case *parser.V2MatcherDecl:
		var refs []v2RefView
		for _, item := range x.Items {
			refs = append(refs, addValueRefs("matcher", x.Name, item.Kind, item.Values)...)
		}
		return refs
	case *parser.V2BindingDecl:
		var refs []v2RefView
		for _, req := range x.Requirements {
			refs = append(refs, addValueRefs("binding", x.Name, "requires."+req.Name, req.Args)...)
		}
		refs = append(refs, collectV2QueryRefs(source, module, "binding", x.Name, target, x.Query.Expr)...)
		refs = append(refs, addValueRefs("binding", x.Name, "query.pattern", x.Query.Pattern)...)
		refs = append(refs, addValueRefs("binding", x.Name, "query.where", x.Query.Where)...)
		for _, out := range x.Outputs {
			refs = append(refs, addValueRefs("binding", x.Name, out.Kind+".concept", out.Concept)...)
			refs = append(refs, addValueRefs("binding", x.Name, out.Kind+".about", out.About)...)
			for _, cov := range out.Covers {
				refs = append(refs, addValueRefs("binding", x.Name, out.Kind+".covers."+cov.Mode, cov.Items)...)
			}
		}
		return refs
	case *parser.V2RuleDecl:
		var refs []v2RefView
		refs = append(refs, addValueRefs("rule", x.Name, "meta", x.Meta)...)
		refs = append(refs, addValueRefs("rule", x.Name, "body.from", x.Body.From.Concept)...)
		refs = append(refs, addValueRefs("rule", x.Name, "body.to", x.Body.To.Concept)...)
		refs = append(refs, addValueRefs("rule", x.Name, "body.issue", x.Body.Issue.Concept)...)
		refs = append(refs, collectV2QueryRefs(source, module, "rule", x.Name, target, x.Body.Query)...)
		for _, cl := range x.Clauses {
			refs = append(refs, addValueRefs("rule", x.Name, cl.Kind+".concept", cl.Concept)...)
			refs = append(refs, addValueRefs("rule", x.Name, cl.Kind+".expr", cl.Expr)...)
			refs = append(refs, addValueRefs("rule", x.Name, cl.Kind+".value", cl.Value)...)
		}
		return refs
	case *parser.V2ReviewDecl:
		refs := addValueRefs("review", x.Concept, "concept", x.Concept)
		return append(refs, addValueRefs("review", x.Concept, "fields", x.Fields)...)
	case *parser.V2ProfileDecl:
		return addValueRefs("profile", x.Name, "fields", x.Fields)
	case *parser.V2PackDecl:
		return addValueRefs("pack", x.Name, "fields", x.Fields)
	case *parser.V2MechanicDecl:
		return addValueRefs("mechanic", x.Kind+"."+x.Name, "items", x.Items)
	case *parser.V2PolicyDecl:
		return addValueRefs("policy", x.Kind+"."+x.Name, "items", x.Items)
	default:
		return nil
	}
}

func collectV2QueryRefs(source, module, kind, name, target string, q *parser.V2QueryExpr) []v2RefView {
	if q == nil {
		return nil
	}
	var refs []v2RefView
	if v2RefMatches(target, q.Family) {
		refs = append(refs, v2RefView{Target: target, Source: source, Module: module, Kind: kind, Name: name, Field: "query.family", Value: q.Family})
	}
	collectV2ValueRefs(target, "query.where", q.Where, func(field, value string) {
		refs = append(refs, v2RefView{Target: target, Source: source, Module: module, Kind: kind, Name: name, Field: field, Value: value})
	})
	for _, step := range q.Steps {
		if v2RefMatches(target, step.Family) {
			refs = append(refs, v2RefView{Target: target, Source: source, Module: module, Kind: kind, Name: name, Field: "query." + step.Relation, Value: step.Family})
		}
		collectV2ValueRefs(target, "query."+step.Relation+".where", step.Where, func(field, value string) {
			refs = append(refs, v2RefView{Target: target, Source: source, Module: module, Kind: kind, Name: name, Field: field, Value: value})
		})
	}
	return refs
}

func collectV2ValueRefs(target, field string, value any, add func(field, value string)) {
	switch v := value.(type) {
	case nil:
	case string:
		if v2RefMatches(target, v) {
			add(field, v)
		}
	case []string:
		for _, item := range v {
			collectV2ValueRefs(target, field, item, add)
		}
	case []any:
		for _, item := range v {
			collectV2ValueRefs(target, field, item, add)
		}
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			collectV2ValueRefs(target, field+"."+key, v[key], add)
		}
	case parser.V2Requirement:
		for _, arg := range v.Args {
			collectV2ValueRefs(target, field+"."+v.Name, arg, add)
		}
	case parser.V2NamedArg:
		collectV2ValueRefs(target, field+"."+v.Name, v.Value, add)
	case parser.V2BlockItem:
		itemField := field
		if len(v.Key) > 0 {
			itemField += "." + strings.Join(v.Key, ".")
		}
		collectV2ValueRefs(target, itemField, v.Value, add)
		for _, child := range v.Block {
			collectV2ValueRefs(target, itemField, child, add)
		}
		for _, child := range v.Items {
			collectV2ValueRefs(target, itemField, child, add)
		}
	case []parser.V2BlockItem:
		for _, item := range v {
			collectV2ValueRefs(target, field, item, add)
		}
	case parser.V2RefExpr:
		collectV2ValueRefs(target, field, v.Name, add)
	case parser.V2LiteralExpr:
		collectV2ValueRefs(target, field, v.Value, add)
	case parser.V2UnaryExpr:
		collectV2ValueRefs(target, field, v.X, add)
	case parser.V2BinaryExpr:
		collectV2ValueRefs(target, field, v.Left, add)
		collectV2ValueRefs(target, field, v.Right, add)
	case parser.V2CallExpr:
		if v2RefMatches(target, v.Name) {
			add(field, v.Name)
		}
		for _, arg := range v.Args {
			collectV2ValueRefs(target, field+"."+v.Name, arg, add)
		}
		for _, arg := range v.NamedArgs {
			collectV2ValueRefs(target, field+"."+v.Name+"."+arg.Name, arg.Expr, add)
		}
	case parser.V2SequenceExpr:
		for _, item := range v.Items {
			collectV2ValueRefs(target, field, item, add)
		}
	}
}

func v2RefMatches(target, value string) bool {
	target = strings.TrimSpace(target)
	value = strings.TrimSpace(value)
	if target == "" || value == "" {
		return false
	}
	return value == target || lastSeg(value) == target || lastSeg(target) == value
}

func lastSeg(value string) string {
	if i := strings.LastIndex(value, "."); i >= 0 {
		return value[i+1:]
	}
	return value
}

func printV2Refs(target string, refs []v2RefView) {
	fmt.Printf("refs %s: %d\n", target, len(refs))
	for _, ref := range refs {
		parts := []string{ref.Kind, ref.Name}
		if ref.Field != "" {
			parts = append(parts, ref.Field)
		}
		if ref.Value != "" {
			parts = append(parts, "="+ref.Value)
		}
		fmt.Printf("  %s  (%s)\n", strings.Join(parts, " "), ref.Source)
	}
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
	in := fs.String("in", "", "v2 .vyql file or directory to verify")
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

func cmdDefinitionsValidate(args []string) error {
	fs := flag.NewFlagSet("definitions validate", flag.ExitOnError)
	in := fs.String("in", datadirRoot(), "v2 .vyql file or directory to verify")
	_ = fs.Parse(args)
	files, err := vyqlFilesUnder(*in)
	if err != nil {
		return err
	}
	checked, err := checkV2DefinitionFiles(files)
	if err != nil {
		return err
	}
	fmt.Printf("validated %d v2 definition file(s) under %s\n", checked, *in)
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
	if _, err := parser.LowerV2DefinitionSources(sources); err != nil {
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
	fmt.Printf("loaded: concepts=%d rules=%d bindings=%d reviews=%d\n", cat.Stats.Concepts, cat.Stats.Rules, cat.Stats.Bindings, cat.Stats.Reviews)
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
	if len(cat.Bindings) > 0 {
		fmt.Printf("\n== bindings (%d shown) ==\n", len(cat.Bindings))
		for _, m := range cat.Bindings {
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
