// Package risk is the derived prioritization layer over findings + graph context
// (docs/17 v1). It computes a context-adjusted priority BAND (P0–P4) from named
// factors, every factor traceable to a graph fact or the finding's own
// derivation — no unexplained point probabilities. `⊕` is monotonic weighted
// band arithmetic (bands are honest about precision; fake decimals are not).
//
// v1 derives factors from fields the engine already populates: rule severity,
// the cross-domain Context lines (exposure + asset, docs/10), negation evidence
// (compensating controls), binding provenance (advisory/CVE → exploit signal),
// and derivation confidence. v2 (FAIR/Monte-Carlo scenarios, docs/17 §v2) is
// partner-gated and deliberately not implemented here.
package risk

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/findings"
)

// Factor is one named contribution to a finding's priority, with its witness.
type Factor struct {
	Name    string
	Weight  int
	Witness string
}

// Score is the derived priority of a finding: a band plus the factor breakdown.
type Score struct {
	RuleID  string
	Band    string // P0 (most urgent) .. P4
	Total   int
	Factors []Factor
}

// model is the tunable priority configuration, loaded from vyql/risk.json
// (docs/17 — weights/bands are content, not engine code).
type model struct {
	Severity map[string]int `json:"severity"`
	Factors  struct {
		Exposure                 int `json:"exposure"`
		ExposureRuntimeConfirmed int `json:"exposure_runtime_confirmed"`
		AssetProximity           int `json:"asset_proximity"`
		ExploitLikelihood        int `json:"exploit_likelihood"`
		ControlPressure          int `json:"control_pressure"`
		ConfidenceLow            int `json:"confidence_low"`
		ConfidenceMedium         int `json:"confidence_medium"`
	} `json:"factors"`
	Bands []struct {
		Band string `json:"band"`
		Min  int    `json:"min"`
	} `json:"bands"`
}

var (
	modelOnce sync.Once
	cfg       model
)

func conf() model {
	modelOnce.Do(func() {
		if err := json.Unmarshal(datadir.MustRead("risk.json"), &cfg); err != nil {
			panic("risk: invalid risk.json: " + err.Error())
		}
	})
	return cfg
}

func (m model) severityWeight(sev string) int {
	if w, ok := m.Severity[sev]; ok {
		return w
	}
	return m.Severity["default"]
}

// Prioritize computes the docs/17 v1 priority for a finding. The combination
// is monotonic: a stronger factor never lowers urgency (never increases the band
// number). Each emitted factor carries a witness; zero-weight factors are omitted
// from the breakdown except severity (always shown as the base).
func Prioritize(f *findings.Finding) Score {
	m := conf()
	var factors []Factor
	total := 0
	add := func(name string, w int, witness string) {
		factors = append(factors, Factor{Name: name, Weight: w, Witness: witness})
		total += w
	}

	// severity — the intrinsic badness of the weakness class (rule metadata).
	add("severity", m.severityWeight(strings.ToLower(f.Severity)), "severity: "+orUnset(f.Severity))

	// exposure — reach(INTERNET, subject)?, confirmed by runtime if observed.
	for _, c := range f.Context {
		if strings.Contains(c, "internet-reachable") {
			w := m.Factors.Exposure
			if strings.Contains(c, "confirmed by runtime") {
				w = m.Factors.ExposureRuntimeConfirmed
			}
			add("exposure", w, "exposure: "+c)
			break
		}
	}

	// asset_proximity — sink/subject near sensitive data (holds_asset_kind).
	for _, c := range f.Context {
		if strings.Contains(c, "holds [") {
			add("asset_proximity", m.Factors.AssetProximity, "asset: "+c)
			break
		}
	}

	// exploit_likelihood — advisory/CVE on the subject (SCA signal). EPSS/KEV
	// membership would refine this; absent that feed it is a binary signal.
	for _, b := range f.Bindings {
		if strings.Contains(b.LabelProvenance, "CVE") || strings.Contains(b.LabelProvenance, "advisory") {
			add("exploit_likelihood", m.Factors.ExploitLikelihood, "exploit: "+b.LabelProvenance)
			break
		}
	}

	// control_pressure — a compensating control on a sibling path reduces
	// priority (the weakness is partially mitigated in practice).
	for _, ne := range f.NegationEvidence {
		if !ne.Satisfied && strings.Contains(ne.Detail, "sibling path") {
			add("control_pressure", m.Factors.ControlPressure, "control: near-miss "+ne.Clause)
			break
		}
	}

	// confidence_discount — low derivation confidence lowers priority.
	switch strings.ToLower(f.Confidence) {
	case "low":
		add("confidence_discount", m.Factors.ConfidenceLow, "confidence: low")
	case "medium":
		add("confidence_discount", m.Factors.ConfidenceMedium, "confidence: medium")
	}

	return Score{RuleID: f.RuleID, Band: m.band(total), Total: total, Factors: factors}
}

// band maps a combined score to a priority band (the highest band whose min the
// score meets), monotonic: higher score => lower band number => more urgent.
func (m model) band(total int) string {
	for _, b := range m.Bands {
		if total >= b.Min {
			return b.Band
		}
	}
	if len(m.Bands) > 0 {
		return m.Bands[len(m.Bands)-1].Band
	}
	return "P4"
}

// PrioritizeAll scores findings and returns them most-urgent first (stable by
// rule id within a band).
func PrioritizeAll(fs []*findings.Finding) []Score {
	out := make([]Score, 0, len(fs))
	for _, f := range fs {
		out = append(out, Prioritize(f))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Total != out[j].Total {
			return out[i].Total > out[j].Total
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

// Render produces the docs/17 banded breakdown (band, rule, factor lines with
// witnesses).
func (s Score) Render() string {
	var b strings.Builder
	b.WriteString(s.Band + "  " + s.RuleID + "\n")
	for _, f := range s.Factors {
		b.WriteString("    " + f.Witness + "\n")
	}
	return b.String()
}

func orUnset(s string) string {
	if s == "" {
		return "unset"
	}
	return s
}
