package main

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/ontology"
)

func TestValidateDefinitionKindAcceptsEveryDocumentedKind(t *testing.T) {
	for _, k := range definitionKinds {
		if err := validateDefinitionKind(k); err != nil {
			t.Errorf("validateDefinitionKind(%q) errored: %v", k, err)
		}
	}
	if err := validateDefinitionKind(""); err != nil {
		t.Errorf("empty kind errored: %v", err)
	}
	if err := validateDefinitionKind("CONCEPTS"); err != nil {
		t.Errorf("kind should be case-insensitive: %v", err)
	}
}

// The failure this guards against: an unrecognised kind selects nothing, and a
// report of zero concepts, rules and bindings reads as a broken installation.
func TestValidateDefinitionKindRejectsUnknown(t *testing.T) {
	err := validateDefinitionKind("bogus")
	if err == nil {
		t.Fatal("unknown kind was accepted")
	}
	if !strings.Contains(err.Error(), "concepts") {
		t.Errorf("error %q does not list the valid kinds", err)
	}
}

func TestValidateDefinitionKindSuggestsNearMiss(t *testing.T) {
	err := validateDefinitionKind("concept")
	if err == nil {
		t.Fatal("singular \"concept\" was accepted")
	}
	if !strings.Contains(err.Error(), "did you mean") {
		t.Errorf("error %q offers no suggestion", err)
	}
}

func TestValidateConceptFilterAcceptsEmptyAndRealConcepts(t *testing.T) {
	onto := ontology.Seed()
	if err := validateConceptFilter(onto, "from", ""); err != nil {
		t.Errorf("empty filter errored: %v", err)
	}
	// Take a name from the ontology rather than writing one here: concept names
	// belong in VyQL data, and a guard test fails the build if any is hardcoded
	// in this package.
	all := onto.AllConcepts()
	if len(all) == 0 {
		t.Fatal("ontology loaded no concepts")
	}
	name := all[0].Name
	if err := validateConceptFilter(onto, "from", name); err != nil {
		t.Errorf("validateConceptFilter(%q) errored: %v", name, err)
	}
	// Substring semantics: a prefix of a real name must match.
	if len(name) > 3 {
		if err := validateConceptFilter(onto, "to", name[:3]); err != nil {
			t.Errorf("prefix %q of a real concept was rejected: %v", name[:3], err)
		}
	}
}

func TestValidateConceptFilterRejectsUnmatchable(t *testing.T) {
	onto := ontology.Seed()
	err := validateConceptFilter(onto, "from", "zzzznotaconcept")
	if err == nil {
		t.Fatal("a filter matching no concept was accepted")
	}
	if !strings.Contains(err.Error(), "-from") {
		t.Errorf("error %q does not name the flag", err)
	}
	if !strings.Contains(err.Error(), "definitions -kind concepts") {
		t.Errorf("error %q does not say how to list concepts", err)
	}
}

func TestSuggestPrefersSharedPrefixAndCapsResults(t *testing.T) {
	got := suggest([]string{"alpha", "alphabet", "alpine", "beta", "gamma"}, "alph")
	if len(got) == 0 {
		t.Fatal("no suggestion for a close match")
	}
	if len(got) > 3 {
		t.Errorf("returned %d suggestions, want at most 3", len(got))
	}
	for _, g := range got {
		if !strings.HasPrefix(g, "alp") {
			t.Errorf("suggestion %q does not share a prefix with the input", g)
		}
	}
	// Nothing close enough is better than a misleading guess.
	if s := suggest([]string{"alpha", "beta"}, "zzzz"); len(s) != 0 {
		t.Errorf("suggested %v for an unrelated input", s)
	}
}
