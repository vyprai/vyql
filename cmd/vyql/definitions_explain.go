package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vyprai/vyql/parser"
)

// explainView is the provenance answer for "where does this label come from".
// It links a concept or binding name to the model concept, the bindings that
// emit it, the rules that consume it, its reviews, and the tests that exercise
// it. This is the v2 surface an external AI caller inspects before suggesting
// new content.
type explainView struct {
	Target   string               `json:"target"`
	Kinds    []string             `json:"kinds"`
	Concept  *explainConceptView  `json:"concept,omitempty"`
	Bindings []explainBindingView `json:"bindings,omitempty"`
	Rules    []explainRuleView    `json:"rules,omitempty"`
	Reviews  []explainReviewView  `json:"reviews,omitempty"`
	Tests    []string             `json:"tests,omitempty"`
}

type explainConceptView struct {
	Name         string   `json:"name"`
	Kind         string   `json:"kind,omitempty"`
	Module       string   `json:"module,omitempty"`
	CWE          []string `json:"cwe,omitempty"`
	Refines      string   `json:"refines,omitempty"`
	VulnerableTo []string `json:"vulnerable_to,omitempty"`
	Neutralizes  []string `json:"neutralizes,omitempty"`
	Source       string   `json:"source"`
}

type explainBindingView struct {
	Name         string            `json:"name"`
	Role         string            `json:"role"`
	Module       string            `json:"module,omitempty"`
	Pattern      string            `json:"pattern,omitempty"`
	Where        string            `json:"where,omitempty"`
	Dependencies []string          `json:"dependencies,omitempty"`
	Requirements []string          `json:"requirements,omitempty"`
	Emits        []explainEmitView `json:"emits,omitempty"`
	Source       string            `json:"source"`
}

type explainEmitView struct {
	Kind     string   `json:"kind"`
	Concept  string   `json:"concept,omitempty"`
	Location string   `json:"location,omitempty"`
	About    string   `json:"about,omitempty"`
	Covers   []string `json:"covers,omitempty"`
}

type explainRuleView struct {
	ID     string   `json:"id,omitempty"`
	Name   string   `json:"name"`
	Module string   `json:"module,omitempty"`
	Fields []string `json:"fields,omitempty"`
	Source string   `json:"source"`
}

type explainReviewView struct {
	Concept string `json:"concept"`
	Source  string `json:"source"`
}

func cmdDefinitionsExplain(args []string) error {
	fs := flag.NewFlagSet("definitions explain", flag.ExitOnError)
	in := fs.String("in", datadirRoot(), "v2 .vyql file or directory to inspect")
	format := fs.String("format", "text", "output format: text | json")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("definitions explain requires <concept-or-binding>, e.g. core.SqlParameterization or cursorExecute")
	}
	target := strings.TrimSpace(fs.Arg(0))
	files, err := vyqlFilesUnder(*in)
	if err != nil {
		return err
	}
	view, err := explainTarget(files, target)
	if err != nil {
		return err
	}
	switch *format {
	case "json":
		b, err := json.MarshalIndent(view, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
	case "text":
		printExplainView(view)
	default:
		return fmt.Errorf("unknown -format %q (use text or json)", *format)
	}
	return nil
}

func explainTarget(files []string, target string) (explainView, error) {
	view := explainView{Target: target}
	kinds := map[string]bool{}
	for _, path := range files {
		prog, err := parseV2File(path)
		if err != nil {
			return explainView{}, err
		}
		source := relPathFromDataRoot(path)
		for _, decl := range prog.Decls {
			switch x := decl.(type) {
			case *parser.V2ConceptDecl:
				if conceptMatchesTarget(target, x) {
					kinds["concept"] = true
					if view.Concept == nil {
						cv := explainConceptFromDecl(x, source)
						view.Concept = &cv
					}
				}
			case *parser.V2BindingDecl:
				if bv, ok := explainBindingFromDecl(target, x, prog.Module, source); ok {
					if bv.Role == "named" {
						kinds["binding"] = true
					}
					view.Bindings = append(view.Bindings, bv)
				}
			case *parser.V2RuleDecl:
				if rv, ok := explainRuleFromDecl(target, x, prog.Module, source); ok {
					view.Rules = append(view.Rules, rv)
				}
			case *parser.V2ReviewDecl:
				if v2RefMatches(target, x.Concept) {
					view.Reviews = append(view.Reviews, explainReviewView{Concept: x.Concept, Source: source})
				}
			}
		}
	}
	tests, err := explainTestRefs(target)
	if err != nil {
		return explainView{}, err
	}
	view.Tests = tests

	if view.Concept == nil && len(view.Bindings) == 0 && len(view.Rules) == 0 && len(view.Reviews) == 0 {
		return explainView{}, fmt.Errorf("no concept, binding, rule, or review references %q", target)
	}

	view.Kinds = sortedKeys(kinds)
	sortExplainView(&view)
	return view, nil
}

func conceptMatchesTarget(target string, c *parser.V2ConceptDecl) bool {
	return v2RefMatches(target, c.Name) || v2RefMatches(target, conceptQualifiedName(c))
}

func conceptQualifiedName(c *parser.V2ConceptDecl) string {
	if c.Module == "" || strings.Contains(c.Name, ".") {
		return c.Name
	}
	return c.Module + "." + c.Name
}

func explainConceptFromDecl(c *parser.V2ConceptDecl, source string) explainConceptView {
	return explainConceptView{
		Name:         conceptQualifiedName(c),
		Kind:         c.Kind,
		Module:       c.Module,
		CWE:          explainFieldStringList(c.Fields, "cwe"),
		Refines:      explainFieldString(c.Fields, "refines"),
		VulnerableTo: explainFieldStringList(c.Fields, "vulnerable_to"),
		Neutralizes:  explainFieldStringList(c.Fields, "neutralizes"),
		Source:       source,
	}
}

func explainBindingFromDecl(target string, b *parser.V2BindingDecl, module, source string) (explainBindingView, bool) {
	named := v2RefMatches(target, b.Name)
	emits := make([]explainEmitView, 0, len(b.Outputs))
	emitsTarget := false
	for _, out := range b.Outputs {
		if v2RefMatches(target, out.Concept) || v2RefMatches(target, out.About) ||
			v2RefMatches(target, out.From) || v2RefMatches(target, out.To) {
			emitsTarget = true
		}
		emits = append(emits, explainEmitFromOutput(out))
	}
	if !named && !emitsTarget {
		return explainBindingView{}, false
	}
	role := "emitter"
	if named {
		role = "named"
	}
	bv := explainBindingView{
		Name:    b.Name,
		Role:    role,
		Module:  module,
		Pattern: b.Query.Pattern,
		Emits:   emits,
		Source:  source,
	}
	if b.Query.Where != nil {
		bv.Where = v2BlockValueString(b.Query.Where)
	}
	for _, req := range b.Requirements {
		rendered := renderRequirement(req)
		if req.Name == "dependency" {
			bv.Dependencies = append(bv.Dependencies, rendered)
		} else {
			bv.Requirements = append(bv.Requirements, rendered)
		}
	}
	return bv, true
}

func explainEmitFromOutput(out parser.V2BindingOutput) explainEmitView {
	ev := explainEmitView{
		Kind:     out.Kind,
		Concept:  out.Concept,
		Location: out.Location,
		About:    out.About,
	}
	for _, cov := range out.Covers {
		ev.Covers = append(ev.Covers, renderCoverage(cov))
	}
	return ev
}

func explainRuleFromDecl(target string, r *parser.V2RuleDecl, module, source string) (explainRuleView, bool) {
	var fields []string
	add := func(field, value string) {
		if v2RefMatches(target, value) {
			fields = append(fields, field+"="+value)
		}
	}
	add("body.from", r.Body.From.Concept)
	add("body.to", r.Body.To.Concept)
	add("body.issue", r.Body.Issue.Concept)
	if r.Body.Query != nil {
		add("query.family", r.Body.Query.Family)
		for _, step := range r.Body.Query.Steps {
			add("query."+step.Relation, step.Family)
		}
	}
	for _, cl := range r.Clauses {
		add(cl.Kind+".concept", cl.Concept)
	}
	if len(fields) == 0 {
		return explainRuleView{}, false
	}
	return explainRuleView{
		ID:     explainFieldString(r.Meta, "id"),
		Name:   r.Name,
		Module: module,
		Fields: fields,
		Source: source,
	}, true
}

// explainTestRefs reports the .test.vyql fixtures that mention the target. These
// are skipped by vyqlFilesUnder, so they are collected separately.
func explainTestRefs(target string) ([]string, error) {
	root := datadirRoot()
	if _, err := os.Stat(root); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	needle := target
	var tests []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".test.vyql") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(raw), needle) {
			tests = append(tests, relPathFromDataRoot(path))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(tests)
	return tests, nil
}

func renderRequirement(req parser.V2Requirement) string {
	if len(req.Args) == 0 {
		return req.Name
	}
	parts := make([]string, 0, len(req.Args))
	for _, arg := range req.Args {
		parts = append(parts, renderRequirementArg(arg))
	}
	return req.Name + "(" + strings.Join(parts, ", ") + ")"
}

func renderRequirementArg(arg any) string {
	switch v := arg.(type) {
	case parser.V2Requirement:
		return renderRequirement(v)
	case parser.V2NamedArg:
		return v.Name + ": " + renderRequirementArg(v.Value)
	default:
		return v2BlockValueString(arg)
	}
}

func renderCoverage(cov parser.V2Coverage) string {
	keys := make([]string, 0, len(cov.Items))
	for key := range cov.Items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+": "+v2BlockValueString(cov.Items[key]))
	}
	if len(parts) == 0 {
		return cov.Mode
	}
	return cov.Mode + " { " + strings.Join(parts, ", ") + " }"
}

func explainFieldString(fields map[string]any, key string) string {
	if v, ok := fields[key].(string); ok {
		return v
	}
	return ""
}

func explainFieldStringList(fields map[string]any, key string) []string {
	switch v := fields[key].(type) {
	case []string:
		return append([]string(nil), v...)
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortExplainView(view *explainView) {
	sort.Slice(view.Bindings, func(i, j int) bool {
		a, b := view.Bindings[i], view.Bindings[j]
		if a.Role != b.Role {
			return a.Role < b.Role
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.Name < b.Name
	})
	sort.Slice(view.Rules, func(i, j int) bool {
		a, b := view.Rules[i], view.Rules[j]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.Name < b.Name
	})
	sort.Slice(view.Reviews, func(i, j int) bool {
		a, b := view.Reviews[i], view.Reviews[j]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.Concept < b.Concept
	})
}

func printExplainView(view explainView) {
	fmt.Printf("explain %s\n", view.Target)
	if len(view.Kinds) > 0 {
		fmt.Printf("resolves to: %s\n", strings.Join(view.Kinds, ", "))
	}
	if view.Concept != nil {
		c := view.Concept
		fmt.Printf("\n== concept ==\n")
		parts := []string{c.Name}
		if c.Kind != "" {
			parts = append(parts, "kind="+c.Kind)
		}
		if len(c.CWE) > 0 {
			parts = append(parts, "cwe="+strings.Join(c.CWE, ","))
		}
		if c.Refines != "" {
			parts = append(parts, "refines="+c.Refines)
		}
		fmt.Printf("  %s  (%s)\n", strings.Join(parts, " "), c.Source)
		if len(c.Neutralizes) > 0 {
			fmt.Printf("  neutralizes: %s\n", strings.Join(c.Neutralizes, ", "))
		}
		if len(c.VulnerableTo) > 0 {
			fmt.Printf("  vulnerable_to: %s\n", strings.Join(c.VulnerableTo, ", "))
		}
	}
	if len(view.Bindings) > 0 {
		fmt.Printf("\n== bindings (%d) ==\n", len(view.Bindings))
		for _, b := range view.Bindings {
			fmt.Printf("  %s [%s]  (%s)\n", b.Name, b.Role, b.Source)
			if b.Pattern != "" {
				fmt.Printf("    pattern: %s\n", b.Pattern)
			}
			if b.Where != "" {
				fmt.Printf("    where: %s\n", b.Where)
			}
			for _, dep := range b.Dependencies {
				fmt.Printf("    depends_on: %s\n", dep)
			}
			for _, req := range b.Requirements {
				fmt.Printf("    requires: %s\n", req)
			}
			for _, e := range b.Emits {
				line := "    " + e.Kind
				if e.Concept != "" {
					line += " " + e.Concept
				}
				if e.Location != "" {
					line += " at " + e.Location
				}
				if e.About != "" {
					line += " about " + e.About
				}
				fmt.Println(line)
				for _, cov := range e.Covers {
					fmt.Printf("      covers %s\n", cov)
				}
			}
		}
	}
	if len(view.Rules) > 0 {
		fmt.Printf("\n== rules (%d) ==\n", len(view.Rules))
		for _, r := range view.Rules {
			head := r.Name
			if r.ID != "" {
				head = r.ID
			}
			fmt.Printf("  %s  (%s)\n", head, r.Source)
			for _, f := range r.Fields {
				fmt.Printf("    %s\n", f)
			}
		}
	}
	if len(view.Reviews) > 0 {
		fmt.Printf("\n== reviews (%d) ==\n", len(view.Reviews))
		for _, r := range view.Reviews {
			fmt.Printf("  %s  (%s)\n", r.Concept, r.Source)
		}
	}
	if len(view.Tests) > 0 {
		fmt.Printf("\n== tests (%d) ==\n", len(view.Tests))
		for _, tst := range view.Tests {
			fmt.Printf("  %s\n", tst)
		}
	}
}
