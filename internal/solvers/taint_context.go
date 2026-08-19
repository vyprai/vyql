package solvers

import (
	"sort"
	"strings"

	"github.com/vyprai/vyql/internal/usg"
)

// CallString represents a bounded call context of length up to k (e.g. k=2).
type CallString []string

// Push appends a call site to the call string, bounding its length to maxK.
func (cs CallString) Push(callSite string, maxK int) CallString {
	if maxK <= 0 {
		return nil
	}
	res := append(CallString(nil), cs...)
	if len(res) >= maxK {
		res = res[len(res)-maxK+1:]
	}
	return append(res, callSite)
}

// Pop returns the innermost call site and the parent call string.
func (cs CallString) Pop() (string, CallString) {
	if len(cs) == 0 {
		return "", nil
	}
	return cs[len(cs)-1], cs[:len(cs)-1]
}

// Key formats the call string for map keying.
func (cs CallString) Key() string {
	return strings.Join(cs, "->")
}

// ContextTaintFlow represents a taint finding with its context-sensitive witness path.
type ContextTaintFlow struct {
	SourceID string
	SinkID   string
	Kind     string
	Path     []string
}

// ContextTaintNode represents a graph vertex qualified by its calling context.
type ContextTaintNode struct {
	NodeID  string
	Context string
}

// FindContextSensitiveTaintFlows computes on-demand taint reachability from sourceConcepts
// to sinkConcepts using bounded call-string context sensitivity (k=2), preventing taint
// from leaking across unrelated call sites via shared helper functions.
func FindContextSensitiveTaintFlows(
	store usg.Store,
	sourceConcepts, sinkConcepts, killControls map[string]bool,
	maxK int,
) ([]ContextTaintFlow, error) {
	if maxK <= 0 {
		maxK = 2
	}

	sourceNodes := map[string]bool{}
	for c := range sourceConcepts {
		ids, err := store.NodesWithConcept(c)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			sourceNodes[id] = true
		}
	}

	sinkNodes := map[string]bool{}
	for c := range sinkConcepts {
		ids, err := store.NodesWithConcept(c)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			sinkNodes[id] = true
		}
	}

	if len(sourceNodes) == 0 || len(sinkNodes) == 0 {
		return nil, nil
	}

	fast, isFast := store.(interface {
		LabelsOf(nodeID string) []usg.Label
		RangeOutEdges(src, edgeType string, fn func(dst string) bool)
	})

	labelsOf := func(id string) []usg.Label {
		if isFast {
			return fast.LabelsOf(id)
		}
		ls, _ := store.Labels(id)
		return ls
	}

	isKill := func(id string) bool {
		for _, l := range labelsOf(id) {
			if l.Detail["advisory"] == "true" {
				continue
			}
			if killControls[l.Concept] {
				return true
			}
		}
		return false
	}

	type queueItem struct {
		nodeID  string
		context CallString
		path    []string
	}

	var queue []queueItem
	visited := make(map[ContextTaintNode]bool)

	// Seed with sources under empty context
	var srcs []string
	for s := range sourceNodes {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)

	for _, s := range srcs {
		initItem := queueItem{
			nodeID:  s,
			context: nil,
			path:    []string{s},
		}
		queue = append(queue, initItem)
		visited[ContextTaintNode{NodeID: s, Context: ""}] = true
	}

	var results []ContextTaintFlow

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		if isKill(curr.nodeID) {
			continue
		}

		if sinkNodes[curr.nodeID] {
			results = append(results, ContextTaintFlow{
				SourceID: curr.path[0],
				SinkID:   curr.nodeID,
				Kind:     "UNTRUSTED_DATA",
				Path:     curr.path,
			})
		}

		node, ok, _ := store.GetNode(curr.nodeID)
		if !ok {
			continue
		}

		// Check outgoing edges
		edges, _ := store.OutEdges(curr.nodeID, "")
		for _, e := range edges {
			if e.Type != "FLOWS" && e.Type != "CALLS" && e.Type != "RETURNS" {
				continue
			}

			nextContext := curr.context
			if e.Type == "CALLS" {
				nextContext = curr.context.Push(curr.nodeID, maxK)
			} else if e.Type == "RETURNS" {
				if len(curr.context) > 0 {
					topCall, parentContext := curr.context.Pop()
					// Verify that return target matches the call site
					if e.Dst != topCall && !strings.HasPrefix(e.Dst, topCall) {
						// Unrealizable return path: suppress
						continue
					}
					nextContext = parentContext
				}
			}

			cnode := ContextTaintNode{
				NodeID:  e.Dst,
				Context: nextContext.Key(),
			}

			if !visited[cnode] {
				visited[cnode] = true
				nextPath := make([]string, len(curr.path)+1)
				copy(nextPath, curr.path)
				nextPath[len(curr.path)] = e.Dst

				queue = append(queue, queueItem{
					nodeID:  e.Dst,
					context: nextContext,
					path:    nextPath,
				})
			}
		}

		_ = node
	}

	return results, nil
}
