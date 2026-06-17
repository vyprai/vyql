// SCA reference data — popular packages, known malware, advisories, and trusted
// versions — is loaded from updateable JSON under vyql/sca/ at runtime (like the
// MITRE catalogs in package taxonomy), NOT compiled in. Security teams refresh these
// files without rebuilding. docs/11.
package sca

import (
	"encoding/json"
	"sync"

	"github.com/vyprai/vyql/datadir"
)

// advisoryEntry is one vulnerable (version, advisory-id) for a package.
type advisoryEntry struct {
	Version string   `json:"version"`
	ID      string   `json:"id"`
	CWE     []string `json:"cwe,omitempty"`
}

// scaData is the merged, parsed reference set, keyed by ecosystem ("pypi"/"npm").
type scaData struct {
	popular    map[string][]string                   // eco -> popular names
	malware    map[string]map[string][]string        // eco -> name -> bad versions ("*" = all)
	advisories map[string]map[string][]advisoryEntry // eco -> name -> vulnerable versions
	trusted    map[string]map[string][]string        // eco -> name -> known-good versions
}

var (
	dataOnce   sync.Once
	dataCached *scaData
)

// data returns the loaded SCA reference set (parsed once). Missing/empty files are
// tolerated — a category simply contributes no matches.
func data() *scaData {
	dataOnce.Do(func() {
		d := &scaData{
			popular:    map[string][]string{},
			malware:    map[string]map[string][]string{},
			advisories: map[string]map[string][]advisoryEntry{},
			trusted:    map[string]map[string][]string{},
		}
		readJSON("sca/popular.json", &d.popular)
		readJSON("sca/malware.json", &d.malware)
		readJSON("sca/advisories.json", &d.advisories)
		readJSON("sca/trusted.json", &d.trusted)
		dataCached = d
	})
	return dataCached
}

// SetSCADataForTest overrides the loaded reference set (tests inject fixtures so they
// don't depend on the shipped JSON). Pass nil to reset to the on-disk data.
func SetSCADataForTest(popular map[string][]string, malware map[string]map[string][]string,
	advisories map[string]map[string][]advisoryEntry, trusted map[string]map[string][]string) {
	dataOnce.Do(func() {}) // ensure the loader never overwrites the fixture
	dataCached = &scaData{popular: popular, malware: malware, advisories: advisories, trusted: trusted}
}

func readJSON(rel string, into interface{}) {
	if b, err := datadir.Read(rel); err == nil {
		_ = json.Unmarshal(b, into)
	}
}

// popularSet returns the popular-name set for an ecosystem.
func (d *scaData) popularSet(eco string) map[string]bool {
	out := map[string]bool{}
	for _, n := range d.popular[eco] {
		out[n] = true
	}
	return out
}

// versionMatch reports whether v is covered by a bad/known version list. "*" matches any.
func versionMatch(versions []string, v string) bool {
	for _, x := range versions {
		if x == "*" || x == v {
			return true
		}
	}
	return false
}
