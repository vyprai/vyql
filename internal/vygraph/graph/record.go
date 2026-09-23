package graph

// Layer is the stratum a node belongs to. Namespace and layer are
// orthogonal: code.Call is low, code.Entrypoint is high.
type Layer uint8

const (
	LayerLow Layer = iota
	LayerHigh
)

func (l Layer) String() string {
	if l == LayerHigh {
		return "high"
	}
	return "low"
}
