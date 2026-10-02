package solver

import "strings"

// Proof is a rebuilt proof tree. It is derived from a Result's witness — never stored on
// the graph and never produced any other way.
type Proof struct {
	Source string
	Target string
	Steps  []Step
}

// ProofTree rebuilds a proof from a result's witness. A result with no witness yields
// nil: a finding with no rebuildable witness is not a finding.
func ProofTree(r Result) *Proof {
	w := r.Witness()
	if len(w) == 0 {
		return nil
	}
	return &Proof{Source: r.Source(), Target: r.Target(), Steps: w}
}

func (p *Proof) Render() string {
	var b strings.Builder
	if p.Source != "" {
		b.WriteString(p.Source)
	} else {
		b.WriteString("(absent)")
	}
	for _, s := range p.Steps {
		b.WriteString("\n  → ")
		b.WriteString(s.To)
		if s.Via != "" {
			b.WriteString(" [" + s.Via + "]")
		}
		if s.Note != "" {
			b.WriteString(" " + s.Note)
		}
	}
	return b.String()
}
