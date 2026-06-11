package sca

import (
	"encoding/json"
	"testing"

	"github.com/vyprai/vyql/datadir"
)

// The shipped SCA reference JSON must parse and be non-empty — readJSON swallows
// errors at runtime (so a missing file degrades gracefully), so this guards the data.
func TestShippedSCADataParses(t *testing.T) {
	cases := []struct {
		file string
		into interface{}
	}{
		{"sca/popular.json", &map[string][]string{}},
		{"sca/malware.json", &map[string]map[string][]string{}},
		{"sca/advisories.json", &map[string]map[string][]advisoryEntry{}},
		{"sca/trusted.json", &map[string]map[string][]string{}},
	}
	for _, c := range cases {
		b, err := datadir.Read(c.file)
		if err != nil {
			t.Errorf("%s: %v", c.file, err)
			continue
		}
		if err := json.Unmarshal(b, c.into); err != nil {
			t.Errorf("%s: invalid JSON: %v", c.file, err)
		}
	}
	// popular.json must actually contain ecosystems (catch an empty/renamed file).
	var pop map[string][]string
	b, _ := datadir.Read("sca/popular.json")
	_ = json.Unmarshal(b, &pop)
	if len(pop["pypi"]) == 0 || len(pop["npm"]) == 0 {
		t.Errorf("popular.json missing pypi/npm entries: %v", pop)
	}
}
