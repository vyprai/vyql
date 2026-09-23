package vyql

import (
	"fmt"
	"sort"
	"strings"
)

// DepEdge is a dependency between predicates, marked negative when it passes
// through negation (an `unless` suppressor or a `not` in a where clause).
type DepEdge struct {
	To       string
	Negative bool
}

// DepGraph is the predicate dependency graph the stratification checker orders.
// Predicates are query names, rule ids, and the suppressor discharge relations
// (`sanitized_by:C`, `guarded_by:C`, `closed_by:C`, `anchored`). Solver verbs are
// opaque calls and contribute no edges.
type DepGraph struct {
	Nodes []string
	Edges map[string][]DepEdge
}

// BuildDepGraph collects the predicate graph from parsed files. A call in a
// where clause names another query: a positive use directly, a negative use
// under `not` (conservatively: negation propagates into the whole sub-expression).
// An `unless` suppressor is a negative edge into its discharge relation, which is
// a leaf predicate.
func BuildDepGraph(files []*File) *DepGraph {
	g := &DepGraph{Edges: map[string][]DepEdge{}}
	add := func(n string) {
		for _, existing := range g.Nodes {
			if existing == n {
				return
			}
		}
		g.Nodes = append(g.Nodes, n)
	}

	queryNames := map[string]string{} // bare or module-qualified -> node id
	for _, f := range files {
		for _, q := range f.Queries {
			add(q.Name)
			queryNames[q.Name] = q.Name
			queryNames[f.Module+"."+q.Name] = q.Name
		}
	}
	for _, f := range files {
		for _, r := range f.Rules {
			id := r.Meta.ID
			if id == "" {
				id = r.Name
			}
			add(id)
		}
	}

	var walk func(e Expr, negated bool, from string)
	walk = func(e Expr, negated bool, from string) {
		switch x := e.(type) {
		case *Call:
			if target, ok := queryNames[x.Name]; ok {
				g.Edges[from] = append(g.Edges[from], DepEdge{To: target, Negative: negated})
			}
			for _, a := range x.Args {
				walk(a, negated, from)
			}
		case *Not:
			walk(x.X, !negated, from)
		case *BinOp:
			walk(x.L, negated, from)
			walk(x.R, negated, from)
		}
	}

	for _, f := range files {
		for _, q := range f.Queries {
			if q.Body.Where != nil {
				walk(q.Body.Where, false, q.Name)
			}
			for _, alt := range q.Alts {
				if alt.Where != nil {
					walk(alt.Where, false, q.Name)
				}
			}
		}
		for _, r := range f.Rules {
			id := r.Meta.ID
			if id == "" {
				id = r.Name
			}
			if r.Body.Where != nil {
				walk(r.Body.Where, false, id)
			}
			if u := r.Body.Unless; u != nil {
				dis := "anchored"
				if u.Kind != "anchored" {
					dis = u.Kind + ":" + u.Concept
				}
				add(dis)
				g.Edges[id] = append(g.Edges[id], DepEdge{To: dis, Negative: true})
			}
		}
	}
	sort.Strings(g.Nodes)
	return g
}

// Stratify orders predicates so each is evaluated only after everything it
// negatively depends on is fully computed. Positive recursion is allowed (the
// members share a stratum and evaluate to a least fixpoint); a cycle through a
// negative edge is a compile error naming the cycle.
func Stratify(g *DepGraph) ([][]string, error) {
	negOf := map[string]map[string]bool{} // from -> to -> negative
	for from, es := range g.Edges {
		for _, e := range es {
			if negOf[from] == nil {
				negOf[from] = map[string]bool{}
			}
			negOf[from][e.To] = e.Negative
		}
	}

	const (
		white = 0
		grey  = 1
		black = 2
	)
	color := map[string]int{}
	var stack []string
	var cycleErr error

	var dfs func(n string)
	dfs = func(n string) {
		if cycleErr != nil {
			return
		}
		color[n] = grey
		stack = append(stack, n)
		for _, e := range g.Edges[n] {
			switch color[e.To] {
			case grey:
				idx := 0
				for i, s := range stack {
					if s == e.To {
						idx = i
						break
					}
				}
				neg := e.Negative // the back edge closing the cycle
				for i := idx; i < len(stack)-1 && !neg; i++ {
					neg = negOf[stack[i]][stack[i+1]]
				}
				if neg {
					cyc := append(append([]string{}, stack[idx:]...), e.To)
					cycleErr = fmt.Errorf(
						"unstratifiable negation: cycle %s passes through a negative edge (unless/not)",
						strings.Join(cyc, " -> "))
					return
				}
			case white:
				dfs(e.To)
				if cycleErr != nil {
					return
				}
			}
		}
		stack = stack[:len(stack)-1]
		color[n] = black
	}
	for _, n := range g.Nodes {
		if color[n] == white {
			dfs(n)
		}
		if cycleErr != nil {
			return nil, cycleErr
		}
	}

	// Fixpoint stratum assignment: a positive dependency may share a stratum
	// (positive recursion is one stratum); a negative dependency forces a
	// strictly later one. Negative cycles are excluded above, so this terminates.
	s := map[string]int{}
	changed := true
	for rounds := 0; changed && rounds <= len(g.Nodes)+2; rounds++ {
		changed = false
		for _, p := range g.Nodes {
			cand := 0
			for _, e := range g.Edges[p] {
				v := s[e.To]
				if e.Negative {
					v++
				}
				if v > cand {
					cand = v
				}
			}
			if cand > s[p] {
				s[p] = cand
				changed = true
			}
		}
	}
	maxStr := 0
	for _, v := range s {
		if v > maxStr {
			maxStr = v
		}
	}
	strata := make([][]string, maxStr+1)
	for _, n := range g.Nodes {
		strata[s[n]] = append(strata[s[n]], n)
	}
	for i := range strata {
		sort.Strings(strata[i])
	}
	return strata, nil
}
