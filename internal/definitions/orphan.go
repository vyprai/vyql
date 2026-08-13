package definitions

import (
	"sort"
	"strings"
	"sync"
)

// Orphan is one sink concept bound in a language where no check bound in that
// same language neutralises the given threat.
//
// A rule over such a sink cannot be cleared. Its `unless` clause names a control
// that nothing in the language emits, so the clause is unsatisfiable however the
// user writes their code, and every match is a false positive by construction.
type Orphan struct {
	Language string
	Sink     string
	Threat   string
}

type ControlScenario string

const (
	// Scenario 1: The control is bound in Go, but not on this path -> code really is missing the control. User should fix the code.
	ScenarioControlBoundInLanguage ControlScenario = "bound_in_language"
	// Scenario 2: The control concept exists, but Go has no binding for it -> code may have the control, but vyql cannot see it. No action required from the user.
	ScenarioControlUnboundInLanguage ControlScenario = "unbound_in_language"
	// Scenario 3: No control concept exists for this threat, in any language -> rule can never be cleared. No action required from the user.
	ScenarioControlMissingFromOntology ControlScenario = "missing_from_ontology"
)

type ControlClassification struct {
	Scenario ControlScenario
	Language string
	Threat   string
	Control  string
	Message  string
}

// crossLanguagePacks bind against every language rather than one, so a check they
// bind counts toward all of them.
var crossLanguagePacks = map[string]bool{
	"library":      true,
	"config":       true,
	"textpattern":  true,
	"sca":          true,
	"pii":          true,
	"auditreview":  true,
	"cryptoreview": true,
}

var (
	shippedCatalogOnce sync.Once
	shippedCatalog     Catalog
)

// ShippedCatalog returns the cached shipped catalog loaded from disk.
func ShippedCatalog() Catalog {
	shippedCatalogOnce.Do(func() {
		cat, err := Inspect(InspectOptions{Kind: "all", Max: 1 << 30})
		if err == nil {
			shippedCatalog = cat
		}
	})
	return shippedCatalog
}

// ClassifyControlDefault classifies a control using the shipped catalog.
func ClassifyControlDefault(language, threat, controlConcept string) ControlClassification {
	return ClassifyControl(ShippedCatalog(), language, threat, controlConcept)
}

// ClassifyControl determines which of the 3 scenarios applies for a given (language, threat, controlConcept)
// and returns a user-facing explanation message:
//
// - Scenario 1: The control is bound in Go (or language L), but not on this path -> code really is missing the control. User should fix code.
// - Scenario 2: The control concept exists, but Go (or language L) has no binding for it -> code may have control, but vyql cannot see it. No action required from user.
// - Scenario 3: No control concept exists for this threat, in any language -> rule can never be cleared. No action required from user.
func ClassifyControl(cat Catalog, language, threat, controlConcept string) ControlClassification {
	if language == "" {
		language = "go"
	}
	language = strings.ToLower(language)

	vulnerableTo := make(map[string][]string)
	neutralizes := make(map[string][]string)
	for _, c := range cat.Concepts {
		if len(c.VulnerableTo) > 0 {
			vulnerableTo[c.Name] = c.VulnerableTo
		}
		if len(c.Neutralizes) > 0 {
			neutralizes[c.Name] = c.Neutralizes
		}
	}

	conceptMatches := func(name, target string) bool {
		if target == "" || name == "" {
			return false
		}
		if name == target {
			return true
		}
		if strings.HasPrefix(target, "core.") || strings.HasPrefix(target, "code.") || strings.HasPrefix(target, "threat.") {
			return name == target
		}
		return strings.HasSuffix(name, "."+target)
	}

	// 1. Check if ANY control concept exists in ontology for this threat / control.
	hasControlConceptInOntology := false
	if controlConcept != "" {
		for _, c := range cat.Concepts {
			if conceptMatches(c.Name, controlConcept) {
				hasControlConceptInOntology = true
				break
			}
		}
	}
	if !hasControlConceptInOntology && threat != "" {
		for _, nList := range neutralizes {
			for _, t := range nList {
				if conceptMatches(t, threat) {
					hasControlConceptInOntology = true
					break
				}
			}
			if hasControlConceptInOntology {
				break
			}
		}
	}

	if !hasControlConceptInOntology {
		return ControlClassification{
			Scenario: ScenarioControlMissingFromOntology,
			Language: language,
			Threat:   threat,
			Control:  controlConcept,
			Message:  "no control concept exists for this threat in any language (rule can never be cleared; no action required from user)",
		}
	}

	// 2. Check if a check binding exists in target language (or cross-language pack).
	hasBindingInLanguage := false
	for _, b := range cat.Bindings {
		if b.Concept == "" || b.Language == "" {
			continue
		}
		if !strings.HasPrefix(b.Kind, "check") {
			continue
		}

		bLang := strings.ToLower(b.Language)
		matchesLang := bLang == language || crossLanguagePacks[bLang]
		if !matchesLang {
			continue
		}

		if controlConcept != "" && conceptMatches(b.Concept, controlConcept) {
			hasBindingInLanguage = true
			break
		}

		if threat != "" {
			for _, t := range neutralizes[b.Concept] {
				if conceptMatches(t, threat) {
					hasBindingInLanguage = true
					break
				}
			}
			if hasBindingInLanguage {
				break
			}
		}
	}

	if !hasBindingInLanguage {
		return ControlClassification{
			Scenario: ScenarioControlUnboundInLanguage,
			Language: language,
			Threat:   threat,
			Control:  controlConcept,
			Message:  "control concept exists, but " + language + " has no binding for it (vyql cannot see it; no action required from user)",
		}
	}

	return ControlClassification{
		Scenario: ScenarioControlBoundInLanguage,
		Language: language,
		Threat:   threat,
		Control:  controlConcept,
		Message:  "control is bound in " + language + ", but not on this path (code really is missing the control; user should fix code)",
	}
}

// OrphanedSinks reports every (language, sink, threat) with no neutralising check
// in that language, sorted so callers can compare the result directly.
func OrphanedSinks(cat Catalog) []Orphan {
	vulnerableTo := make(map[string][]string, len(cat.Concepts))
	neutralizes := make(map[string][]string, len(cat.Concepts))
	for _, c := range cat.Concepts {
		if len(c.VulnerableTo) > 0 {
			vulnerableTo[c.Name] = c.VulnerableTo
		}
		if len(c.Neutralizes) > 0 {
			neutralizes[c.Name] = c.Neutralizes
		}
	}

	languages := map[string]bool{}
	sinks := map[string]map[string]bool{}   // language -> sink concept
	covered := map[string]map[string]bool{} // language -> threat a bound check neutralises
	universal := map[string]bool{}          // threats covered for every language

	for _, b := range cat.Bindings {
		if b.Concept == "" || b.Language == "" {
			continue
		}
		switch {
		case strings.HasPrefix(b.Kind, "sink"):
			// A cross-language pack's sinks belong to no single language, so there is
			// no language whose checks could be expected to cover them.
			if crossLanguagePacks[b.Language] {
				continue
			}
			languages[b.Language] = true
			if sinks[b.Language] == nil {
				sinks[b.Language] = map[string]bool{}
			}
			sinks[b.Language][b.Concept] = true
		case strings.HasPrefix(b.Kind, "check"):
			for _, threat := range neutralizes[b.Concept] {
				if crossLanguagePacks[b.Language] {
					universal[threat] = true
					continue
				}
				if covered[b.Language] == nil {
					covered[b.Language] = map[string]bool{}
				}
				covered[b.Language][threat] = true
			}
		}
	}

	var out []Orphan
	for language := range languages {
		for sink := range sinks[language] {
			for _, threat := range vulnerableTo[sink] {
				if universal[threat] || covered[language][threat] {
					continue
				}
				out = append(out, Orphan{Language: language, Sink: sink, Threat: threat})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Language != out[j].Language {
			return out[i].Language < out[j].Language
		}
		if out[i].Sink != out[j].Sink {
			return out[i].Sink < out[j].Sink
		}
		return out[i].Threat < out[j].Threat
	})
	return out
}
