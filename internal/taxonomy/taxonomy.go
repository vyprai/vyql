// Package taxonomy embeds the full MITRE CWE and CAPEC catalogs as reference
// data (docs/16). Every CWE (969) and CAPEC (615) entry is queryable by id,
// with hierarchy (ChildOf) and cross-references (CWE<->CAPEC). The analysis
// ontology (package ontology) maps onto this catalog; the catalog itself is the
// complete taxonomy — "encompass all CWE/CAPEC" lives here, while the analysis
// concept vocabulary stays curated (docs/06 reconciliation).
//
// The catalogs live in the standalone `vyql/taxonomy/{cwe,capec}.json` and are
// loaded from disk at runtime (see package datadir) — not embedded in the binary.
// They are generated from the official MITRE comprehensive CSVs; do not
// hand-edit them.
package taxonomy

import (
	"encoding/json"
	"strconv"
	"strings"
	"sync"

	"github.com/vyprai/vyql/internal/datadir"
)

// CWE is one Common Weakness Enumeration entry.
type CWE struct {
	Name        string `json:"name"`
	Abstraction string `json:"abstraction"` // Pillar|Class|Base|Variant|Compound
	Status      string `json:"status"`
	Parents     []int  `json:"parents"` // ChildOf ids
	CAPEC       []int  `json:"capec"`   // related attack patterns
	Desc        string `json:"desc"`
}

// CAPEC is one Common Attack Pattern Enumeration entry.
type CAPEC struct {
	Name        string `json:"name"`
	Abstraction string `json:"abstraction"` // Meta|Standard|Detailed
	Status      string `json:"status"`
	Severity    string `json:"severity"`
	CWEs        []int  `json:"cwes"` // related weaknesses
	Desc        string `json:"desc"`
}

// Catalog holds the loaded CWE + CAPEC catalogs.
type Catalog struct {
	cwe   map[string]CWE
	capec map[string]CAPEC
}

var (
	stdOnce sync.Once
	stdCat  *Catalog
)

// Std returns the embedded catalog (loaded once).
func Std() *Catalog {
	stdOnce.Do(func() {
		c := &Catalog{cwe: map[string]CWE{}, capec: map[string]CAPEC{}}
		_ = json.Unmarshal(datadir.MustRead("taxonomy/cwe.json"), &c.cwe)
		_ = json.Unmarshal(datadir.MustRead("taxonomy/capec.json"), &c.capec)
		stdCat = c
	})
	return stdCat
}

// NormalizeID strips an optional CWE/CAPEC prefix (either "-" or the VyQL "_" form) and
// surrounding space, leaving the bare numeric id. Exported because output formatters were each
// reimplementing it: this package owns what a catalogue id looks like, and a second opinion about
// that is how `CWE_79` and `CWE-79` end up tagged differently in the same document.
func NormalizeID(id string) string { return normalize(id) }

// normalize is the unexported form the rest of this package uses.
func normalize(id string) string {
	id = strings.TrimSpace(id)
	for _, p := range []string{"CWE-", "CWE_", "CAPEC-", "CAPEC_"} {
		id = strings.TrimPrefix(id, p)
	}
	return id
}

// CWE looks up a weakness by id ("CWE-89" or "89").
func (c *Catalog) CWE(id string) (CWE, bool) {
	w, ok := c.cwe[normalize(id)]
	return w, ok
}

// CAPEC looks up an attack pattern by id ("CAPEC-66" or "66").
func (c *Catalog) CAPEC(id string) (CAPEC, bool) {
	p, ok := c.capec[normalize(id)]
	return p, ok
}

func (c *Catalog) HasCWE(id string) bool   { _, ok := c.cwe[normalize(id)]; return ok }
func (c *Catalog) HasCAPEC(id string) bool { _, ok := c.capec[normalize(id)]; return ok }

// Counts returns (numCWE, numCAPEC).
func (c *Catalog) Counts() (int, int) { return len(c.cwe), len(c.capec) }

// CWEAncestors returns the transitive ChildOf ancestors of a CWE id (nearest
// first by BFS), useful for rolling a specific weakness up to its class/pillar.
func (c *Catalog) CWEAncestors(id string) []string {
	id = normalize(id)
	seen := map[string]bool{id: true}
	var out []string
	queue := []string{id}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		w, ok := c.cwe[cur]
		if !ok {
			continue
		}
		for _, p := range w.Parents {
			ps := strconv.Itoa(p)
			if !seen[ps] {
				seen[ps] = true
				out = append(out, ps)
				queue = append(queue, ps)
			}
		}
	}
	return out
}
