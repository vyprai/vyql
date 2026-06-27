// Package risk is the derived prioritization layer over findings + graph context.
// It computes a context-adjusted priority BAND (P0-P4) from the authored
// `policy priority default` v2 declaration. Every factor remains traceable to a
// graph fact or the finding's own derivation; Go supplies the primitive
// predicates, while weights and bands are VyQL content.
package risk

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/parser"
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

type model struct {
	Severity map[string]int
	Factors  map[string]priorityFactor
	Bands    []struct {
		Band string
		Min  int
	}
}

type priorityFactor struct {
	Weight int
	When   parser.V2Expr
}

var (
	modelOnce sync.Once
	cfg       model
)

func conf() model {
	modelOnce.Do(func() {
		var err error
		cfg, err = loadPriorityPolicy()
		if err != nil {
			panic("risk: invalid policy priority default: " + err.Error())
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

func (m model) factorWeight(name string) int {
	return m.Factors[name].Weight
}

// Prioritize computes priority from the loaded v2 priority policy. The
// combination is monotonic for positive factors: a stronger factor never lowers
// urgency. Each emitted factor carries a witness; zero-weight factors are
// omitted from the breakdown except severity, which is always shown as the base.
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
			name := "exposure"
			if strings.Contains(c, "confirmed by runtime") {
				name = "runtimeExposure"
			}
			add(name, m.factorWeight(name), "exposure: "+c)
			break
		}
	}

	// asset_proximity — sink/subject near sensitive data (holds_asset_kind).
	for _, c := range f.Context {
		if strings.Contains(c, "holds [") {
			add("assetProximity", m.factorWeight("assetProximity"), "asset: "+c)
			break
		}
	}

	// exploit_likelihood — advisory/CVE on the subject (SCA signal). EPSS/KEV
	// membership would refine this; absent that feed it is a binary signal.
	for _, b := range f.Bindings {
		if strings.Contains(b.LabelProvenance, "CVE") || strings.Contains(b.LabelProvenance, "advisory") {
			add("exploitLikelihood", m.factorWeight("exploitLikelihood"), "exploit: "+b.LabelProvenance)
			break
		}
	}

	// control_pressure — a compensating control on a sibling path reduces
	// priority (the weakness is partially mitigated in practice).
	for _, ne := range f.NegationEvidence {
		if !ne.Satisfied && strings.Contains(ne.Detail, "sibling path") {
			add("controlPressure", m.factorWeight("controlPressure"), "control: near-miss "+ne.Clause)
			break
		}
	}

	// confidence_discount — low derivation confidence lowers priority.
	switch strings.ToLower(f.Confidence) {
	case "low":
		add("confidenceLow", m.factorWeight("confidenceLow"), "confidence: low")
	case "medium":
		add("confidenceMedium", m.factorWeight("confidenceMedium"), "confidence: medium")
	}

	return Score{RuleID: f.RuleID, Band: m.band(total), Total: total, Factors: factors}
}

func loadPriorityPolicy() (model, error) {
	files, err := datadir.ReadVYQLDir("mechanics")
	if err != nil {
		return model{}, err
	}
	raw := make([]parser.V2DefinitionSource, 0, len(files))
	for _, file := range files {
		raw = append(raw, parser.V2DefinitionSource{Name: file.Name, Source: string(file.Data)})
	}
	decls, err := parser.ParseV2DefinitionSources(raw)
	if err != nil {
		return model{}, err
	}
	var policy *parser.V2PolicyDecl
	for _, decl := range decls {
		p, ok := decl.(*parser.V2PolicyDecl)
		if !ok || p.Kind != "priority" || p.Name != "default" {
			continue
		}
		if policy != nil {
			return model{}, fmt.Errorf("duplicate policy priority default")
		}
		policy = p
	}
	if policy == nil {
		return model{}, fmt.Errorf("missing policy priority default")
	}
	return modelFromPriorityPolicy(policy)
}

func modelFromPriorityPolicy(policy *parser.V2PolicyDecl) (model, error) {
	out := model{Severity: map[string]int{}, Factors: map[string]priorityFactor{}}
	for _, item := range policy.Items {
		switch {
		case len(item.Key) == 2 && item.Key[0] == "score" && item.Key[1] == "severity":
			for _, score := range item.Block {
				if len(score.Key) != 1 {
					return model{}, fmt.Errorf("malformed severity score key %s", strings.Join(score.Key, "."))
				}
				n, ok := v2PolicyInt(score.Value)
				if !ok {
					return model{}, fmt.Errorf("severity score %s must be an integer", score.Key[0])
				}
				out.Severity[score.Key[0]] = n
			}
		case len(item.Key) == 2 && item.Key[0] == "factor":
			weight, ok := v2PolicyBlockInt(item.Block, "weight")
			if !ok {
				return model{}, fmt.Errorf("factor %s requires integer weight", item.Key[1])
			}
			when, _ := v2PolicyBlockExpr(item.Block, "when")
			out.Factors[item.Key[1]] = priorityFactor{Weight: weight, When: when}
		case len(item.Key) == 1 && item.Key[0] == "bands":
			bands, ok := item.Value.([]any)
			if !ok {
				return model{}, fmt.Errorf("bands must be a list")
			}
			for i, raw := range bands {
				block, ok := raw.([]parser.V2BlockItem)
				if !ok {
					return model{}, fmt.Errorf("bands[%d] must be a block", i)
				}
				band, ok := v2PolicyBlockString(block, "band")
				if !ok {
					return model{}, fmt.Errorf("bands[%d] requires band", i)
				}
				min, ok := v2PolicyBlockInt(block, "min")
				if !ok {
					return model{}, fmt.Errorf("bands[%d] requires integer min", i)
				}
				out.Bands = append(out.Bands, struct {
					Band string
					Min  int
				}{Band: band, Min: min})
			}
		}
	}
	if len(out.Severity) == 0 {
		return model{}, fmt.Errorf("missing score severity")
	}
	if _, ok := out.Severity["default"]; !ok {
		return model{}, fmt.Errorf("score severity requires default")
	}
	for _, factor := range []string{"exposure", "runtimeExposure", "assetProximity", "exploitLikelihood", "controlPressure", "confidenceLow", "confidenceMedium"} {
		if _, ok := out.Factors[factor]; !ok {
			return model{}, fmt.Errorf("missing factor %s", factor)
		}
	}
	if len(out.Bands) == 0 {
		return model{}, fmt.Errorf("missing bands")
	}
	return out, nil
}

func v2PolicyBlockInt(items []parser.V2BlockItem, key string) (int, bool) {
	for _, item := range items {
		if len(item.Key) == 1 && item.Key[0] == key {
			return v2PolicyInt(item.Value)
		}
	}
	return 0, false
}

func v2PolicyBlockString(items []parser.V2BlockItem, key string) (string, bool) {
	for _, item := range items {
		if len(item.Key) != 1 || item.Key[0] != key {
			continue
		}
		lit, ok := item.Value.(parser.V2LiteralExpr)
		if !ok {
			return "", false
		}
		s, ok := lit.Value.(string)
		return s, ok
	}
	return "", false
}

func v2PolicyBlockExpr(items []parser.V2BlockItem, key string) (parser.V2Expr, bool) {
	for _, item := range items {
		if len(item.Key) != 1 || item.Key[0] != key {
			continue
		}
		expr, ok := item.Value.(parser.V2Expr)
		return expr, ok
	}
	return nil, false
}

func v2PolicyInt(raw any) (int, bool) {
	lit, ok := raw.(parser.V2LiteralExpr)
	if !ok {
		return 0, false
	}
	n, ok := lit.Value.(int)
	return n, ok
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
