// Package pack is the rule-pack manifest + version pinning (docs/05 §module
// System, docs/15). A pack pins the ontology and
// minimum engine versions and declares the concepts it depends on; the compiler
// verifies those concepts resolve against the pinned ontology at build time.
package pack

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/vyprai/vyql/internal/ontology"
)

// Manifest is a pack manifest. Loaded from JSON (no TOML dependency in Go):
//
//	{"pack":{"name":"vypr.rules.injection","version":"2026.06.1",
//	         "ontology":">=1.4 <2.0","engine":">=0.9"},
//	 "depends":{"concepts":["code.HttpInput","code.SqlExecution", …]}}
type Manifest struct {
	Pack struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Ontology string `json:"ontology"`
		Engine   string `json:"engine"`
	} `json:"pack"`
	Depends struct {
		Concepts []string `json:"concepts"`
	} `json:"depends"`
}

// Load parses a manifest from JSON.
func Load(b []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// Validate returns problems ([] = the pack is loadable in this environment):
// the ontology/engine versions must satisfy the pins and every dependency
// concept must resolve (docs/15 — a pack cannot ship referencing a concept
// that doesn't exist).
func (m *Manifest) Validate(onto *ontology.Ontology, ontologyVersion, engineVersion string) []string {
	var problems []string
	if m.Pack.Ontology != "" && m.Pack.Ontology != "*" && !Satisfies(ontologyVersion, m.Pack.Ontology) {
		problems = append(problems, "ontology "+ontologyVersion+" does not satisfy pin '"+m.Pack.Ontology+"'")
	}
	if m.Pack.Engine != "" && m.Pack.Engine != "*" && !Satisfies(engineVersion, m.Pack.Engine) {
		problems = append(problems, "engine "+engineVersion+" does not satisfy pin '"+m.Pack.Engine+"'")
	}
	for _, c := range m.Depends.Concepts {
		if !onto.Exists(c) {
			problems = append(problems, "depends on unknown concept '"+c+"' (not in pinned ontology)")
		}
	}
	return problems
}

// Satisfies reports whether version satisfies a space-separated range spec,
// e.g. ">=1.4 <2.0", ">=0.9", "1.4.0".
func Satisfies(version, spec string) bool {
	v := parseVer(version)
	for _, clause := range strings.Fields(spec) {
		if !clauseOK(v, clause) {
			return false
		}
	}
	return true
}

func parseVer(s string) []int {
	var out []int
	for _, p := range strings.Split(strings.TrimSpace(s), ".") {
		if p == "" {
			continue
		}
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	return out
}

func pad(a, b []int) ([]int, []int) {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for len(a) < n {
		a = append(a, 0)
	}
	for len(b) < n {
		b = append(b, 0)
	}
	return a, b
}

func cmp(a, b []int) int {
	a, b = pad(a, b)
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func clauseOK(v []int, clause string) bool {
	clause = strings.TrimSpace(clause)
	for _, op := range []string{">=", "<=", "<", ">", "=="} {
		if strings.HasPrefix(clause, op) {
			t := parseVer(clause[len(op):])
			c := cmp(v, t)
			switch op {
			case ">=":
				return c >= 0
			case "<=":
				return c <= 0
			case "<":
				return c < 0
			case ">":
				return c > 0
			case "==":
				return c == 0
			}
		}
	}
	return cmp(v, parseVer(clause)) == 0
}
