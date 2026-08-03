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
	Severity    map[string]int
	Factors     map[string]priorityFactor
	FactorOrder []string
	Bands       []struct {
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
	return prioritizeWithModel(f, conf())
}

func prioritizeWithModel(f *findings.Finding, m model) Score {
	var factors []Factor
	total := 0
	add := func(name string, w int, witness string) {
		if w == 0 && name != "severity" {
			return
		}
		factors = append(factors, Factor{Name: name, Weight: w, Witness: witness})
		total += w
	}

	// severity — the intrinsic badness of the weakness class (rule metadata).
	add("severity", m.severityWeight(strings.ToLower(f.Severity)), "severity: "+orUnset(f.Severity))

	facts := priorityFactsForFinding(f)
	for _, name := range m.FactorOrder {
		factor := m.Factors[name]
		ok, witnesses := evalPriorityBool(factor.When, facts)
		if !ok {
			continue
		}
		add(name, factor.Weight, priorityWitness(witnesses, name))
	}

	return Score{RuleID: f.RuleID, Band: m.band(total), Total: total, Factors: factors}
}

func loadPriorityPolicy() (model, error) {
	files, err := datadir.ReadVYQLDir("policies")
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
			when, ok := v2PolicyBlockExpr(item.Block, "when")
			if !ok {
				return model{}, fmt.Errorf("factor %s requires when", item.Key[1])
			}
			if err := validatePriorityRuntimeExpr(when); err != nil {
				return model{}, fmt.Errorf("factor %s when: %w", item.Key[1], err)
			}
			out.Factors[item.Key[1]] = priorityFactor{Weight: weight, When: when}
			out.FactorOrder = append(out.FactorOrder, item.Key[1])
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

type priorityFact struct {
	Bool    bool
	Scalar  string
	Number  int
	HasNum  bool
	Witness string
}

type priorityFactSet map[string]priorityFact

func priorityFactsForFinding(f *findings.Finding) priorityFactSet {
	out := priorityFactSet{
		"finding.confidence":   {Bool: f.Confidence != "", Scalar: strings.ToLower(f.Confidence), Witness: "confidence: " + orUnset(strings.ToLower(f.Confidence))},
		"finding.bindingCount": {Bool: len(f.Bindings) > 0, Number: len(f.Bindings), HasNum: true, Scalar: fmt.Sprint(len(f.Bindings)), Witness: fmt.Sprintf("bindings: %d", len(f.Bindings))},
		"finding.contextCount": {Bool: len(f.Context) > 0, Number: len(f.Context), HasNum: true, Scalar: fmt.Sprint(len(f.Context)), Witness: fmt.Sprintf("context entries: %d", len(f.Context))},
	}
	for _, c := range f.Context {
		lower := strings.ToLower(c)
		if _, ok := out["context.internetReachable"]; !ok && strings.Contains(lower, "internet-reachable") {
			out["context.internetReachable"] = priorityFact{Bool: true, Witness: "exposure: " + c}
		}
		if _, ok := out["context.runtimeConfirmed"]; !ok && strings.Contains(lower, "confirmed by runtime") {
			out["context.runtimeConfirmed"] = priorityFact{Bool: true, Witness: "runtime: " + c}
		}
		if _, ok := out["context.holdsAsset"]; !ok && strings.Contains(lower, "holds [") {
			out["context.holdsAsset"] = priorityFact{Bool: true, Witness: "asset: " + c}
		}
	}
	for _, b := range f.Bindings {
		lower := strings.ToLower(b.LabelProvenance)
		if _, ok := out["finding.exploitSignal"]; !ok && (strings.Contains(lower, "cve") || strings.Contains(lower, "advisory")) {
			out["finding.exploitSignal"] = priorityFact{Bool: true, Witness: "exploit: " + b.LabelProvenance}
			break
		}
	}
	for _, ne := range f.NegationEvidence {
		if _, ok := out["finding.nearMissControl"]; ok {
			break
		}
		if !ne.Satisfied && strings.Contains(strings.ToLower(ne.Detail), "sibling path") {
			out["finding.nearMissControl"] = priorityFact{Bool: true, Witness: "control: near-miss " + ne.Clause}
		}
	}
	return out
}

func evalPriorityBool(expr parser.V2Expr, facts priorityFactSet) (bool, []string) {
	switch x := expr.(type) {
	case nil:
		return false, nil
	case parser.V2LiteralExpr:
		b, ok := x.Value.(bool)
		return ok && b, nil
	case parser.V2RefExpr:
		fact := facts[x.Name]
		if !fact.Bool {
			return false, nil
		}
		return true, compactWitnesses(fact.Witness)
	case parser.V2UnaryExpr:
		if x.Op != "not" {
			return false, nil
		}
		ok, _ := evalPriorityBool(x.X, facts)
		return !ok, nil
	case parser.V2BinaryExpr:
		switch x.Op {
		case "and":
			leftOK, leftWitnesses := evalPriorityBool(x.Left, facts)
			if !leftOK {
				return false, nil
			}
			rightOK, rightWitnesses := evalPriorityBool(x.Right, facts)
			if !rightOK {
				return false, nil
			}
			return true, append(leftWitnesses, rightWitnesses...)
		case "or":
			leftOK, leftWitnesses := evalPriorityBool(x.Left, facts)
			rightOK, rightWitnesses := evalPriorityBool(x.Right, facts)
			switch {
			case leftOK && rightOK:
				return true, append(leftWitnesses, rightWitnesses...)
			case leftOK:
				return true, leftWitnesses
			case rightOK:
				return true, rightWitnesses
			default:
				return false, nil
			}
		case "==", "!=":
			left, leftOK, leftWitnesses := evalPriorityScalar(x.Left, facts)
			right, rightOK, rightWitnesses := evalPriorityScalar(x.Right, facts)
			if !leftOK || !rightOK {
				return false, nil
			}
			matches := left == right
			if x.Op == "!=" {
				matches = !matches
			}
			if !matches {
				return false, nil
			}
			return true, append(leftWitnesses, rightWitnesses...)
		case ">=", "<=", ">", "<":
			left, leftOK, leftWitnesses := evalPriorityNumber(x.Left, facts)
			right, rightOK, rightWitnesses := evalPriorityNumber(x.Right, facts)
			if !leftOK || !rightOK {
				return false, nil
			}
			var matches bool
			switch x.Op {
			case ">=":
				matches = left >= right
			case "<=":
				matches = left <= right
			case ">":
				matches = left > right
			case "<":
				matches = left < right
			}
			if !matches {
				return false, nil
			}
			return true, append(leftWitnesses, rightWitnesses...)
		default:
			return false, nil
		}
	default:
		return false, nil
	}
}

func evalPriorityScalar(expr parser.V2Expr, facts priorityFactSet) (string, bool, []string) {
	switch x := expr.(type) {
	case parser.V2LiteralExpr:
		switch v := x.Value.(type) {
		case string:
			return strings.ToLower(v), true, nil
		case int:
			return fmt.Sprint(v), true, nil
		case bool:
			return fmt.Sprint(v), true, nil
		default:
			return "", false, nil
		}
	case parser.V2RefExpr:
		if fact, ok := facts[x.Name]; ok {
			if fact.Scalar != "" {
				return fact.Scalar, true, compactWitnesses(fact.Witness)
			}
			return fmt.Sprint(fact.Bool), true, compactWitnesses(fact.Witness)
		}
		if isPriorityLiteralRef(x.Name) {
			return strings.ToLower(x.Name), true, nil
		}
		return "", false, nil
	default:
		return "", false, nil
	}
}

func evalPriorityNumber(expr parser.V2Expr, facts priorityFactSet) (int, bool, []string) {
	switch x := expr.(type) {
	case parser.V2LiteralExpr:
		n, ok := x.Value.(int)
		return n, ok, nil
	case parser.V2RefExpr:
		if fact, ok := facts[x.Name]; ok && fact.HasNum {
			return fact.Number, true, compactWitnesses(fact.Witness)
		}
		return 0, false, nil
	default:
		return 0, false, nil
	}
}

func isPriorityLiteralRef(ref string) bool {
	switch ref {
	case "low", "medium", "high", "critical", "info":
		return true
	default:
		return false
	}
}

func compactWitnesses(witnesses ...string) []string {
	out := make([]string, 0, len(witnesses))
	seen := map[string]bool{}
	for _, witness := range witnesses {
		witness = strings.TrimSpace(witness)
		if witness == "" || seen[witness] {
			continue
		}
		seen[witness] = true
		out = append(out, witness)
	}
	return out
}

func priorityWitness(witnesses []string, name string) string {
	witnesses = compactWitnesses(witnesses...)
	if len(witnesses) == 0 {
		return "policy factor: " + name
	}
	return strings.Join(witnesses, "; ")
}

func validatePriorityRuntimeExpr(expr parser.V2Expr) error {
	switch x := expr.(type) {
	case parser.V2LiteralExpr:
		return nil
	case parser.V2RefExpr:
		if isPriorityRuntimeRef(x.Name) || isPriorityLiteralRef(x.Name) {
			return nil
		}
		return fmt.Errorf("unsupported reference %q", x.Name)
	case parser.V2UnaryExpr:
		if x.Op != "not" {
			return fmt.Errorf("unsupported unary operator %q", x.Op)
		}
		return validatePriorityRuntimeExpr(x.X)
	case parser.V2BinaryExpr:
		switch x.Op {
		case "and", "or", "==", "!=", ">=", "<=", ">", "<":
		default:
			return fmt.Errorf("unsupported binary operator %q", x.Op)
		}
		if err := validatePriorityRuntimeExpr(x.Left); err != nil {
			return err
		}
		return validatePriorityRuntimeExpr(x.Right)
	default:
		return fmt.Errorf("unsupported expression %T", expr)
	}
}

func isPriorityRuntimeRef(ref string) bool {
	switch ref {
	case "context.internetReachable",
		"context.runtimeConfirmed",
		"context.holdsAsset",
		"finding.exploitSignal",
		"finding.nearMissControl",
		"finding.confidence",
		"finding.bindingCount",
		"finding.contextCount":
		return true
	default:
		return false
	}
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
