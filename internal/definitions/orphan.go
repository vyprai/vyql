package definitions

import (
	"sort"
	"strings"
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
