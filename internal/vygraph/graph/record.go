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

// Build is Axis A of provenance — how the record was built.
// The listed order matches the design table; conflict resolution's full
// "(build tier, then trust tier)" lexicographic ordering arrives with lift/relate in
// Phase 2, when competing producers exist. Phase 1a orders merges by Trust and records
// Build as data.
type Build uint8

const (
	BuildParsed    Build = iota // emitted by a frontend / the generic parser
	BuildLifted                 // a high-level node built by a lift
	BuildRelated                // a high-level edge built by a relate
	BuildResolved               // produced by import/type resolution
	BuildLabeled                // a concept attached by a VyQL binding
	BuildMined                  // inferred by a solver (deviation, a summary)
	BuildGenerated              // machine-generated, quarantined
)

// Trust is Axis B of provenance — how far the knowledge is trusted, on the promotion
// ladder. Ordering is load-bearing: a higher tier
// wins a field conflict, and generated knowledge stays subordinate.
type Trust uint8

const (
	TrustGenerated Trust = iota // machine-generated, unvalidated
	TrustValidated              // scored on the corpus
	TrustReviewed               // human-reviewed
	TrustTrusted                // shipped with the knowledge base
)

// Provenance records how a record came to exist (Build) and at what trust tier
// (Trust). Every Node, Edge and Label carries one.
type Provenance struct {
	Producer string // producing module: frontend, binding, lift, or learner id
	Build    Build
	Trust    Trust
}

// Node is a typed vertex. Type is namespaced; Layer says which stratum it belongs to.
// A node has exactly ONE type and may carry MANY labels — structure is a type, meaning
// is a label.
type Node struct {
	ID        string
	Type      string
	Layer     Layer
	Fields    Fields
	Subsystem string // workspace partition
	Prov      Provenance
}

// Edge is a typed directed relation with its own typed fields.
type Edge struct {
	ID     string
	Type   string
	From   string
	To     string
	Fields Fields
	Prov   Provenance
}

// EdgeBacks is the reserved edge type joining a high-level node to the low-level node
// that backs it. Solvers needing dataflow run over the low graph but are invoked by
// high-level rules, and bridge by following this edge.
const EdgeBacks = "backs"

// Label attaches a concept to a node or edge. Labels are keyed
// (Target, Concept, Provenance): the same concept from two sources is two labels whose
// confidences compose.
type Label struct {
	Target     string // a Node or Edge id
	Concept    string
	Confidence float64
	Prov       Provenance
}
