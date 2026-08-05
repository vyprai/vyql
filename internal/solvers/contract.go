package solvers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// SolverContractVersion is the version of the shared solver contract
// (docs/03 §engine, docs/08 §"shared solver contract"). Every solver honours
// the same contract so the engine treats them uniformly and proof trees can be
// reconstructed regardless of which solver produced a flow.
const SolverContractVersion = "0.1.0"

// Result is the minimal contract surface every solver result must expose: a
// source endpoint, a sink/target endpoint, and a witness sufficient to rebuild
// a proof tree. The concrete TaintFlow/ReachPath/AssumePath satisfy it.
type Result interface {
	Source() string // source_id or principal_id
	Target() string // sink_id or target_id
	Witness() []string
}

func (f TaintFlow) Source() string    { return f.SourceID }
func (f TaintFlow) Target() string    { return f.SinkID }
func (f TaintFlow) Witness() []string { return f.Path }

func (p ReachPath) Source() string { return p.SourceID }
func (p ReachPath) Target() string { return p.TargetID }
func (p ReachPath) Witness() []string {
	w := make([]string, 0, len(p.Hops)+1)
	for i, h := range p.Hops {
		if i == 0 {
			w = append(w, h.From)
		}
		w = append(w, h.To)
	}
	return w
}

func (p AssumePath) Source() string { return p.SourceID }
func (p AssumePath) Target() string { return p.TargetID }
func (p AssumePath) Witness() []string {
	w := make([]string, 0, len(p.Steps)+1)
	for i, s := range p.Steps {
		if i == 0 {
			w = append(w, s.From)
		}
		w = append(w, s.To)
	}
	return w
}

// ValidateResult returns the contract violations for one result ([] = ok).
func ValidateResult(r Result) []string {
	var errs []string
	if r.Source() == "" {
		errs = append(errs, "missing source endpoint")
	}
	if r.Target() == "" {
		errs = append(errs, "missing sink/target endpoint")
	}
	if len(r.Witness()) == 0 {
		errs = append(errs, "missing witness")
	}
	return errs
}

// ValidateResults validates a slice of results, prefixing each violation.
func ValidateResults[T Result](results []T) []string {
	var errs []string
	for i, r := range results {
		for _, e := range ValidateResult(r) {
			errs = append(errs, fmt.Sprintf("result[%d]: %s", i, e))
		}
	}
	return errs
}

// CacheFingerprint is a stable key over a solver call's inputs; solvers cache
// against this and invalidate when a graph delta intersects the recorded
// dependency. The cache is an optimization, never the source of truth.
func CacheFingerprint(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "::")))
	return hex.EncodeToString(sum[:])[:16]
}

// StubSolver is a trivial conforming solver: it connects each bound source to
// each bound sink with a one-hop witness. It exists so the contract test has
// something to assert conformance against, independent of the real solvers.
type StubSolver struct{}

func (StubSolver) Name() string    { return "stub" }
func (StubSolver) Version() string { return SolverContractVersion }

// Solve connects every source to every sink with a one-hop witness.
func (StubSolver) Solve(sourceIDs, sinkIDs []string) []TaintFlow {
	var out []TaintFlow
	for _, s := range sourceIDs {
		for _, k := range sinkIDs {
			out = append(out, TaintFlow{SourceID: s, SinkID: k, Path: []string{s, k}})
		}
	}
	return out
}
