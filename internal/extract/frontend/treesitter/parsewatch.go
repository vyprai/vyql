package treesitter

import (
	"sync"
	"sync/atomic"
	"time"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

// The parse bound: one tree-sitter parse may not take the process past the
// scan's resident-memory stop, the same figure the whole-process watch ends the
// scan at. A parse that would cross it is halted through tree-sitter's
// cancellation flag and the file is declined — the same outcome as a file that
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
	// parseWatchEvery is how often the watch samples resident memory while a
	// parse runs. An order finer than the process watch's 100ms, because this
	// one has to land BEFORE the stop: the parse it halts may be growing
	// resident memory at gigabytes per second.
	parseWatchEvery = 15 * time.Millisecond
	// parseWatchMargin is the room below the stop where a parse is already too
	// close. A halt is not instant — the flag is read every few hundred parse
	// operations, and one sample interval of growth lands after it is set —
	// and the measured overshoot at this cadence is under 100MB, so the margin
	// holds the halt inside the stop with room to spare.
	parseWatchMargin = 256 << 20
	// parseWatchGrowthFloor is how much resident memory must have appeared
	// since the parse was armed before it can be the one halted. A process
	// sitting near the stop for reasons of its own — a collector-squeezed heap
	// — must not have every remaining file declined for memory its own parse
	// never asked for; a parse costing less than this cannot be distinguished
	// from that case and is allowed to finish.
	parseWatchGrowthFloor = 64 << 20
)

// armParseWatch bounds one parse of p by the published stop. It returns the
// func that disarms the watch — waiting for the sampler to finish, so no
// sample lands after the parse it was watching has moved on to the next file —
// and reports whether this bound is what halted the parse.
//
// With no stop in force — or no resident reading on this platform — the parse
// runs unbounded, exactly as it did before the bound existed, and the disarm
// reports false.
func armParseWatch(p *tree_sitter.Parser) func() bool {
	stop := atomic.LoadInt64(&parseStop)
	if stop <= 0 {
		return func() bool { return false }
	}
	// The parser reads this flag every few hundred parse operations; storing
	// one word is all the halting costs the parse itself.
	var flag uintptr
	p.SetCancellationFlag(&flag)
	base := parseResidentBytes()
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		t := time.NewTicker(parseWatchEvery)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				// A tick and a disarm can both be ready, and select chooses
				// between them at random, so ask again before sampling.
				select {
				case <-done:
					return
				default:
				}
				rss := parseResidentBytes()
				// The growth is read from this parse's arm time, so it counts
				// whatever the process gained while the parse ran — a sibling
				// worker's parse as much as this one's. That is deliberate:
				// near the stop the total is what the ceiling sees, and a
				// scan that close is halted or it dies, whichever parses are
				// the cause.
				if rss > stop-parseWatchMargin && rss-base > parseWatchGrowthFloor {
					atomic.StoreUintptr(&flag, 1)
					return
				}
			}
		}
	}()
	var once sync.Once
	return func() bool {
		once.Do(func() { close(done) })
		<-stopped
		return atomic.LoadUintptr(&flag) != 0
	}
}
