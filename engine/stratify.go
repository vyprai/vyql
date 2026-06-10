package engine

import (
	"fmt"
	"sort"
)

// StratError is raised when a rule set is not stratifiable.
type StratError struct{ Msg string }

func (e StratError) Error() string { return e.Msg }

// Dep is a predicate dependency: Head depends on Body with sign "pos"|"neg".
type Dep struct {
	Head, Body, Sign string
}

// Stratify checks that no cycle in the predicate dependency graph passes through
// a negative (`unless`) edge — the compile-time guarantee that makes `unless`
// well-defined and incremental evaluation sound (docs/05 §negation). Returns
// strata in evaluation order, or a StratError naming the offending cycle.
// (Tarjan SCC; port of poc/vyql/stratify.py.)
func Stratify(preds []string, deps []Dep) ([][]string, error) {
	adj := map[string][]string{}
	for _, p := range preds {
		adj[p] = nil
	}
	for _, d := range deps {
		adj[d.Head] = append(adj[d.Head], d.Body)
		if _, ok := adj[d.Body]; !ok {
			adj[d.Body] = nil
		}
	}

	index := map[string]int{}
	low := map[string]int{}
	onstack := map[string]bool{}
	var stack []string
	var sccs [][]string
	counter := 0

	var strongconnect func(v string)
	strongconnect = func(v string) {
		index[v] = counter
		low[v] = counter
		counter++
		stack = append(stack, v)
		onstack[v] = true
		for _, w := range adj[v] {
			if _, ok := index[w]; !ok {
				strongconnect(w)
				if low[w] < low[v] {
					low[v] = low[w]
				}
			} else if onstack[w] && index[w] < low[v] {
				low[v] = index[w]
			}
		}
		if low[v] == index[v] {
			var comp []string
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onstack[w] = false
				comp = append(comp, w)
				if w == v {
					break
				}
			}
			sccs = append(sccs, comp)
		}
	}
	for _, p := range preds {
		if _, ok := index[p]; !ok {
			strongconnect(p)
		}
	}

	compOf := map[string]int{}
	for i, comp := range sccs {
		for _, p := range comp {
			compOf[p] = i
		}
	}
	for _, d := range deps {
		if d.Sign == "neg" && compOf[d.Head] == compOf[d.Body] {
			return nil, StratError{fmt.Sprintf(
				"negative dependency cycle: '%s' depends on NOT '%s' but they are mutually recursive (same SCC) — rule set is not stratifiable",
				d.Head, d.Body)}
		}
	}

	// sccs are in reverse-topological order (callees first)
	strata := make([][]string, len(sccs))
	for i, comp := range sccs {
		sort.Strings(comp)
		strata[i] = comp
	}
	return strata, nil
}

// checkRulesetStratified runs the (currently trivial) whole-rule-set check. With
// the present language surface `unless` negates over EDB control labels, not over
// other rules' derivations, so the inter-rule graph has no negative edges. Wired
// in so cyclic negation is rejected once user-defined derived predicates land.
func checkRulesetStratified(compiled []*CompiledRule) error {
	preds := make([]string, len(compiled))
	for i, cr := range compiled {
		preds[i] = cr.Rule.QualifiedName()
	}
	_, err := Stratify(preds, nil)
	return err
}
