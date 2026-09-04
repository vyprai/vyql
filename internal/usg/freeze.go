package usg

import "math"

// packedAdj is a compressed-sparse-row adjacency table. During graph construction we use
// [][]int32 because appending one edge is cheap. Once construction is complete, CSR removes
// two slice headers per node (out and reverse) and one allocation per non-empty row while
// keeping traversal allocation-free.
type packedAdj struct {
	offsets []uint32
	nodes   []int32
}

type packedLabels struct {
	offsets []uint32
	labels  []Label
}

func packAdj(rows [][]int32) (packedAdj, bool) {
	total := uint64(0)
	for _, row := range rows {
		total += uint64(len(row))
	}
	if !packedLengthOK(total) {
		// A uint32 offset cannot represent this graph. Leave its mutable representation intact;
		// such a table alone is already larger than a practical --max-ram scan.
		return packedAdj{}, false
	}
	p := packedAdj{
		offsets: make([]uint32, len(rows)+1),
		nodes:   make([]int32, 0, int(total)),
	}
	for i, row := range rows {
		p.nodes = append(p.nodes, row...)
		p.offsets[i+1] = uint32(len(p.nodes))
	}
	return p, true
}

func (p packedAdj) at(i int32) []int32 {
	if i < 0 || int(i)+1 >= len(p.offsets) {
		return nil
	}
	return p.nodes[p.offsets[i]:p.offsets[i+1]]
}

func (p packedAdj) unpack() [][]int32 {
	if p.offsets == nil {
		return nil
	}
	rows := make([][]int32, len(p.offsets)-1)
	for i := range rows {
		row := p.at(int32(i))
		if len(row) != 0 {
			rows[i] = append([]int32(nil), row...)
		}
	}
	return rows
}

func packLabelRows(rows [][]Label) (packedLabels, bool) {
	total := uint64(0)
	for _, row := range rows {
		total += uint64(len(row))
	}
	if !packedLengthOK(total) {
		return packedLabels{}, false
	}
	p := packedLabels{
		offsets: make([]uint32, len(rows)+1),
		labels:  make([]Label, 0, int(total)),
	}
	for i, row := range rows {
		p.labels = append(p.labels, row...)
		p.offsets[i+1] = uint32(len(p.labels))
	}
	return p, true
}

func packedLengthOK(total uint64) bool {
	// Offsets use uint32, while make's capacity is int. Check both bounds before
	// converting so 32-bit builds cannot wrap a valid uint32 into a negative int.
	return total <= math.MaxUint32 && total <= uint64(^uint(0)>>1)
}

func (p packedLabels) at(i int32) []Label {
	if i < 0 || int(i)+1 >= len(p.offsets) {
		return nil
	}
	return p.labels[p.offsets[i]:p.offsets[i+1]]
}

func (p packedLabels) unpack() [][]Label {
	if p.offsets == nil {
		return nil
	}
	rows := make([][]Label, len(p.offsets)-1)
	for i := range rows {
		row := p.at(int32(i))
		if len(row) != 0 {
			rows[i] = append([]Label(nil), row...)
		}
	}
	return rows
}

// Freeze compacts completed stores that support a frozen representation. Store remains the
// stable public contract; callers that build hand-written stores do not need to know about it.
// A subsequent mutation is still supported: compact stores transparently restore mutable rows.
func Freeze(s Store) {
	if f, ok := s.(interface{ Freeze() }); ok {
		f.Freeze()
	}
}
