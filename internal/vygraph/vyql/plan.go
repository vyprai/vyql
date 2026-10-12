package vyql

import (
	"fmt"
	"sort"

	"github.com/vyprai/vyql/internal/vygraph/solver"
)

// SolverRegistry is how Run receives its solvers: a map from verb name to the
// opaque implementation. The planner never inspects inside a solver call.
type SolverRegistry map[string]solver.Solver

// Program is a compiled knowledge base: every file validated, every predicate
// assigned a stratum, rules and queries ready to evaluate.
type Program struct {
	KB      *KB
	Strata  [][]string
	Queries map[string]*QueryDecl // bare and module-qualified names
	Rules   []RuleDecl
}

// Result is one emitted finding or signal.
type Result struct {
	RuleID     string
	Source     string
	Target     string
	Confidence float64
	Stream     EmitKind
	Proof      *solver.Proof
}

// Output carries the two streams, kept distinct end to end: findings are
// asserted with proof trees; signals are ranked review-queue items.
type Output struct {
	Findings []Result
	Signals  []Result
}

// Compile validates every file against the knowledge base, stratifies the
// predicate graph (an unless/not cycle is a compile error here), and lowers the
// module into an executable program.
func Compile(kb *KB) (*Program, error) {
	var errs []error
	for _, f := range kb.Files {
		errs = append(errs, Validate(f, kb.Knowledge)...)
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("compile: %v", errs)
	}
	strata, err := Stratify(BuildDepGraph(kb.Files))
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	p := &Program{KB: kb, Strata: strata, Queries: map[string]*QueryDecl{}}
	for _, f := range kb.Files {
		for i := range f.Queries {
			q := &f.Queries[i]
			p.Queries[q.Name] = q
			p.Queries[f.Module+"."+q.Name] = q
		}
		p.Rules = append(p.Rules, f.Rules...)
	}
	return p, nil
}

// Render writes a canonical text form: streams separated, entries sorted by
// (rule id, target, witness hash), proof rendered. Two runs over identical
// (graph, knowledge) must render byte-identically.
func (o *Output) Render() string {
	render := func(rs []Result) string {
		type line struct {
			r    Result
			hash string
		}
		var ls []line
		for _, r := range rs {
			h := ""
			if r.Proof != nil {
				h = hashOf(r.Proof.Render())
			}
			ls = append(ls, line{r, h})
		}
		sort.Slice(ls, func(i, j int) bool {
			if ls[i].r.RuleID != ls[j].r.RuleID {
				return ls[i].r.RuleID < ls[j].r.RuleID
			}
			if ls[i].r.Target != ls[j].r.Target {
				return ls[i].r.Target < ls[j].r.Target
			}
			return ls[i].hash < ls[j].hash
		})
		out := ""
		for _, l := range ls {
			out += fmt.Sprintf("%s %s %s->%s conf=%.2f witness=%s\n",
				streamName(l.r.Stream), l.r.RuleID, l.r.Source, l.r.Target, l.r.Confidence, l.hash)
		}
		return out
	}
	return "findings:\n" + render(o.Findings) + "signals:\n" + render(o.Signals)
}

func streamName(s EmitKind) string {
	if s == EmitSignal {
		return "signal"
	}
	return "finding"
}

// hashOf is a stable FNV-1a digest rendered as hex — deterministic across runs
// and machines, which is what byte-identical output requires.
func hashOf(s string) string {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return fmt.Sprintf("%016x", h)
}
