// Package timing is the per-phase wall-clock log used for local performance work.
//
// It lives here rather than in the command because the phases worth timing are pipeline
// phases — extract, lower, bindings — and those run under internal/extract. One switch and
// one output format across every stage means two marks from different packages are
// comparable in the same stderr stream.
package timing

import (
	"fmt"
	"os"
	"time"
)

// on enables the log. Read once, at init: the phases are hot enough that re-reading the
// environment per mark would show up in what it is measuring.
var on = os.Getenv("VYQL_TIMING") != ""

// Timer accumulates elapsed time since the previous mark and since its own start.
type Timer struct {
	last  time.Time
	start time.Time
}

func New() *Timer {
	now := time.Now()
	return &Timer{last: now, start: now}
}

// Mark prints the elapsed wall time of the phase since the previous mark (when timing is on).
func (t *Timer) Mark(phase string) {
	if !on {
		return
	}
	now := time.Now()
	fmt.Fprintf(os.Stderr, "[timing] %-10s %7.1fms (total %7.1fms)\n",
		phase, float64(now.Sub(t.last))/1e6, float64(now.Sub(t.start))/1e6)
	t.last = now
}
