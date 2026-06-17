package main

import (
	"fmt"
	"os"
	"time"
)

// timingOn enables per-phase wall-clock logging to stderr when $VYQL_TIMING is set. A
// diagnostic for the incremental fast path — off by default, zero cost.
var timingOn = os.Getenv("VYQL_TIMING") != ""

type timer struct {
	last  time.Time
	start time.Time
}

func newTimer() *timer {
	now := time.Now()
	return &timer{last: now, start: now}
}

// mark prints the elapsed wall time of the phase since the previous mark (when timing is on).
func (t *timer) mark(phase string) {
	if !timingOn {
		return
	}
	now := time.Now()
	fmt.Fprintf(os.Stderr, "[timing] %-10s %7.1fms (total %7.1fms)\n",
		phase, float64(now.Sub(t.last))/1e6, float64(now.Sub(t.start))/1e6)
	t.last = now
}
