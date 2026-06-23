package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"strings"

	"github.com/vyprai/vyql/definitions"
)

func cmdDefinitions(args []string) error {
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
