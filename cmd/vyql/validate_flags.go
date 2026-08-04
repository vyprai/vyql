package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vyprai/vyql/ontology"
)

// Filters that match nothing are the dangerous case in a security tool: the
// output is a confident report over an empty set, and "0 sources reach a sink"
// is indistinguishable from "this code is clean". Everything here turns a filter
// that can never match into an error at startup, before a scan runs.

// suggest returns the closest few candidates for a mistyped value, preferring
// ones that share a prefix and falling back to those containing the same letters
// in order. Empty when nothing is close enough to be worth guessing at.
func suggest(candidates []string, typed string) []string {
	typed = strings.ToLower(typed)
	if typed == "" {
		return nil
	}
	type scored struct {
		name  string
		score int
	}
	var out []scored
	for _, c := range candidates {
		lc := strings.ToLower(c)
		// Score against the bare name as well as the package-qualified one, so a
		// typo of the short name still finds the concept it belongs to. Concept
		// names are deliberately absent from this file: they live in VyQL data,
		// and a guard test fails the build if any is written here.
		bare := lc
		if i := strings.LastIndex(lc, "."); i >= 0 {
			bare = lc[i+1:]
		}
		s := commonPrefix(bare, typed)
		if q := commonPrefix(lc, typed); q > s {
			s = q
		}
		if s >= 3 {
			out = append(out, scored{c, s})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].score != out[j].score {
			return out[i].score > out[j].score
		}
		return out[i].name < out[j].name
	})
	var names []string
	for i, s := range out {
		if i == 3 {
			break
		}
		names = append(names, s.name)
	}
	return names
}

func commonPrefix(a, b string) int {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return n
}

// validateConceptFilter rejects a -from/-to value that matches no concept the
// ontology defines. The filter is a substring match, so this asks whether any
// concept could ever contain it -- not whether the name is spelled exactly.
func validateConceptFilter(onto *ontology.Ontology, flagName, sub string) error {
	sub = strings.TrimSpace(sub)
	if sub == "" {
		return nil
	}
	needle := strings.ToLower(sub)
	names := make([]string, 0, 1024)
	for _, c := range onto.AllConcepts() {
		qualified := c.Package + "." + c.Name
		if strings.Contains(strings.ToLower(qualified), needle) {
			return nil
		}
		names = append(names, qualified)
	}
	msg := fmt.Sprintf("-%s %q matches no concept", flagName, sub)
	if s := suggest(names, sub); len(s) > 0 {
		msg += "\n  did you mean: " + strings.Join(s, ", ") + "?"
	}
	return fmt.Errorf("%s\n  list them with: vyql definitions -kind concepts", msg)
}

// definitionKinds is the set -kind accepts. Anything outside it selects nothing,
// and a report of zero concepts, rules and bindings describes a broken
// installation rather than a mistyped flag -- so it is rejected here instead.
var definitionKinds = []string{"all", "concepts", "rules", "bindings", "reviews", "packs"}

func validateDefinitionKind(kind string) error {
	k := strings.ToLower(strings.TrimSpace(kind))
	if k == "" {
		return nil
	}
	for _, valid := range definitionKinds {
		if k == valid {
			return nil
		}
	}
	msg := fmt.Sprintf("unknown -kind %q", kind)
	if s := suggest(definitionKinds, k); len(s) > 0 {
		msg += "\n  did you mean: " + strings.Join(s, ", ") + "?"
	}
	return fmt.Errorf("%s\n  valid kinds: %s", msg, strings.Join(definitionKinds, " | "))
}
