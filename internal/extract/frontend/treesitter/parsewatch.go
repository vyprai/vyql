package treesitter

import (
	"sync/atomic"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

// The parse bound: one tree-sitter parse may not take the process past the
// scan's resident-memory stop, the same figure the whole-process watch ends the
// scan at. A parse that would cross it is cancelled through tree-sitter's own
// progress callback and the file is declined — the same outcome as a file that
// cannot be read — instead of ending the scan with no report at all.
//
// The bound exists because a parse's cost is not proportional to its file. The
// Perl grammar reading prose amplifies a few hundred kilobytes into gigabytes
// of error-recovery memory, and dense real modules are not far behind it (a
// 217KB core module peaked at 3.7GB), so the cost of ONE file has no ceiling
// any partition scheme can budget for: a group holding a single such file is
// already over the limit, and the scan dies however the target is divided. The
// claim check at ReadsAsPerl declines prose before the parse; this bound holds
// the line for everything that check cannot see — a shebang claiming a
// non-program, two markers in a document that quotes code, a genuine module
// whose grammar state runs away.
//
// The progress callback is the mechanism tree-sitter itself ships for exactly
// this (it replaced the cancellation flag the binding deprecated): the parser
// calls it on the parse's own thread every hundred parse operations, and a
// callback that returns true cancels the parse, which then yields no tree. So
// the resident reading is taken where the memory is being spent, with no
// sampler racing the parse and no watch left running once it has ended.
//
// It is armed by the Perl frontend, the grammar measured to run away; the hook
// in the shared parse loop is inert for the languages that do not ask for it.

// parseStop is the resident-memory stop one parse must respect: the scan's own
// safety threshold, published by the command that armed the process-wide
// memory watch. 0 means no ceiling is in force, and parses run unbounded —
// exactly what the scan did before the bound existed, for the scans that never
// asked for a ceiling.
var parseStop int64

// SetParseStop publishes the resident-memory stop a single parse must respect
// (0 disables the bound). It is the whole-process stop, not a per-parse
// allowance: a parse is halted only when the process is about to cross it.
func SetParseStop(n int64) { parseStop = n }

// ParseStop reports the resident-memory stop a single parse must respect
// (0 = disabled).
func ParseStop() int64 { return parseStop }

const (
	// parseWatchMargin is the room below the stop where a parse is already too
	// close. A cancel is not instant — the callback returns between parse
	// operations, and the tree the parse had built to that point is released
	// only after it returns — so the halt has to land before the stop, with
	// room for the pages in flight. The margin is deliberately the same order
	// as the whole-process watch's own reserve.
	parseWatchMargin = 256 << 20
	// parseWatchGrowthFloor is how much resident memory must have appeared
	// since the parse started before it can be the one halted. A process
	// sitting near the stop for reasons of its own — a collector-squeezed heap
	// — must not have every remaining file declined for memory its own parse
	// never asked for; a parse costing less than this cannot be distinguished
	// from that case and is allowed to finish.
	parseWatchGrowthFloor = 64 << 20
)

// boundParse is the parse the Perl frontend runs in place of the plain one: the
// same input handling Parse itself performs, with the resident-memory bound
// observed from tree-sitter's progress callback. It returns no tree when the
// bound cancelled the parse, and reports whether the bound was what halted it.
//
// With no stop in force — or no resident reading on this platform — this is the
// plain parse, and the bound never declines a file.
func boundParse(p *tree_sitter.Parser, src []byte) (*tree_sitter.Tree, bool) {
	stop := atomic.LoadInt64(&parseStop)
	if stop <= 0 {
		return p.Parse(src, nil), false
	}
	base := parseResidentBytes()
	var halted bool
	tree := p.ParseWithOptions(
		func(offset int, _ tree_sitter.Point) []byte {
			if offset < len(src) {
				return src[offset:]
			}
			return nil
		},
		nil,
		&tree_sitter.ParseOptions{
			ProgressCallback: func(_ tree_sitter.ParseState) bool {
				// The reading is process-wide, so it counts whatever the
				// process gained while this parse ran — a sibling worker's
				// parse as much as this one's. That is deliberate: near the
				// stop the total is what the ceiling sees, and a scan that
				// close is halted or it dies, whichever parses are the cause.
				rss := parseResidentBytes()
				if rss > stop-parseWatchMargin && rss-base > parseWatchGrowthFloor {
					halted = true
					return true // true cancels the parse
				}
				return false
			},
		})
	return tree, halted
}
