package solvers

import (
	"sort"

	"github.com/vyprai/vyql/internal/usg"
)

// FunctionSummary models the intra-procedural input/output transfer functions
// and sanitization effects of a function in isolation.
type FunctionSummary struct {
	FuncID        string                  `json:"func_id"`
	ParamToReturn map[int]bool            `json:"param_to_return"`
	ParamToParam  map[int][]int           `json:"param_to_param,omitempty"`
	ParamToField  map[int]map[string]bool `json:"param_to_field,omitempty"`
	FieldToReturn map[string]bool         `json:"field_to_return,omitempty"`
	KilledThreats map[int]map[string]bool `json:"killed_threats,omitempty"` // param index -> set of killed threat concepts
}

// NewFunctionSummary creates an initialized FunctionSummary.
func NewFunctionSummary(funcID string) *FunctionSummary {
	return &FunctionSummary{
		FuncID:        funcID,
		ParamToReturn: make(map[int]bool),
		ParamToParam:  make(map[int][]int),
		ParamToField:  make(map[int]map[string]bool),
		FieldToReturn: make(map[string]bool),
		KilledThreats: make(map[int]map[string]bool),
	}
}

// ComputeFunctionSummary traces intra-procedural flow paths from each parameter
// to the return node and other parameters, identifying whether taint reaches the return
// or is killed along the way by neutralizing controls.
func ComputeFunctionSummary(store usg.Store, funcID string, paramIDs []string, retID string, killControls map[string]bool) *FunctionSummary {
	summary := NewFunctionSummary(funcID)
	if store == nil {
		return summary
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

	isKill := func(id string) (bool, string) {
		for _, l := range labelsOf(id) {
			if l.Detail["advisory"] == "true" {
				continue
			}
			if killControls != nil && killControls[l.Concept] {
				return true, l.Concept
			}
		}
		return false, ""
	}

	forEachSucc := func(id string, fn func(string)) {
		if isFast {
			fast.RangeOutEdges(id, "FLOWS", func(dst string) bool { fn(dst); return true })
		} else {
			edges, _ := store.OutEdges(id, "FLOWS")
			for _, e := range edges {
				fn(e.Dst)
			}
		}
	}

	paramIndexMap := make(map[string]int, len(paramIDs))
	for i, pid := range paramIDs {
		if pid != "" {
			paramIndexMap[pid] = i
		}
	}

	// Trace flow from each parameter individually
	for i, pid := range paramIDs {
		if pid == "" {
			continue
		}

		visited := make(map[string]bool)
		killedOnPath := make(map[string]bool)
		queue := []string{pid}
		visited[pid] = true

		for len(queue) > 0 {
			curr := queue[0]
			queue = queue[1:]

			if killed, concept := isKill(curr); killed {
				if summary.KilledThreats[i] == nil {
					summary.KilledThreats[i] = make(map[string]bool)
				}
				summary.KilledThreats[i][concept] = true
				killedOnPath[curr] = true
				// Do not propagate live taint through kill control
				continue
			}

			if retID != "" && curr == retID {
				summary.ParamToReturn[i] = true
			}

			if targetIdx, ok := paramIndexMap[curr]; ok && targetIdx != i {
				summary.ParamToParam[i] = append(summary.ParamToParam[i], targetIdx)
			}

			forEachSucc(curr, func(dst string) {
				if !visited[dst] {
					visited[dst] = true
					queue = append(queue, dst)
				}
			})
		}

		if len(summary.ParamToParam[i]) > 0 {
			sort.Ints(summary.ParamToParam[i])
		}
	}

	return summary
}
