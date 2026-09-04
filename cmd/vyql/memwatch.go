package main

import (
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"
)

const memoryWatchInterval = 100 * time.Millisecond

// memoryStopThreshold leaves room between the last sample and the real ceiling.
// A watcher that fires AT the ceiling is already too late: one allocation burst,
// a C parse tree, or the kernel's accounting lag can cross the cgroup limit before
// cleanups run. The reserve is intentionally conservative; a slower scan or a
// clean failure is preferable to an OOM kill.
func memoryStopThreshold(limit int64) int64 {
	if limit <= 0 {
		return 0
	}
	reserve := limit / 8
	if reserve < 256<<20 {
		reserve = 256 << 20
	}
	if reserve > 2<<30 {
		reserve = 2 << 30
	}
	if quarter := limit / 4; reserve > quarter {
		reserve = quarter
	}
	return limit - reserve
}

func boundedMemoryCeiling(avail uint64) int64 {
	if avail > uint64(math.MaxInt64) {
		return math.MaxInt64
	}
	return int64(avail)
}

// memWatch samples resident memory and hands the first reading above limit to
// onExceed. The stop func ends the sampling.
//
// A heap ceiling cannot do this job on its own: it makes the collector work
// harder, but the graph a scan builds is live memory that no amount of
// collection releases, so a large enough tree grows past any ceiling. What ends
// such a scan otherwise is the kernel: no diagnostic, no exit status, and a
// truncated report on stdout.
//
// A reading of zero means the platform could not report resident memory. It is
// never treated as a crossing, and never as proof of headroom either.
//
// stop waits for the sampler to finish before it returns, so once it has
// returned no further reading is taken. Returning early would leave a sample
// already in flight to land afterwards, and a caller that stops the watch to
// take the resource down cannot act on "probably no longer running".
func memWatch(limit int64, every time.Duration, resident func() int64, onExceed func(int64)) (stop func()) {
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				// A tick and a stop can both be ready, and select chooses
				// between them at random, so ask again before sampling.
				select {
				case <-done:
					return
				default:
				}
				if rss := resident(); rss > limit {
					onExceed(rss)
					return
				}
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() { close(done) })
		<-stopped
	}
}

// watchResidentMemory arms memWatch on the real process against limit. The scan
// ends with the standard "could not complete" status, after the cleanups have
// run, so an interrupted graph store does not survive the failure.
//
// ceiling is how the message names the limit. It is the user's own spelling of
// -max-ram where there is one, because a message that answers "8GB" with
// "7.5 GiB" reads like a different number.
func watchResidentMemory(limit int64, ceiling string) (stop func()) {
	if limit <= 0 {
		return func() {}
	}
	stopAt := memoryStopThreshold(limit)
	return memWatch(stopAt, memoryWatchInterval, residentBytes, func(rss int64) {
		fmt.Fprintf(os.Stderr,
			"vyql: the scan reached %s of resident memory, at the safety threshold below %s; stopping\n"+
				"      exclude unwanted files with -exclude, or raise the ceiling\n",
			humanBytes(rss), ceiling)
		runCleanups()
		os.Exit(exitFailed)
	})
}

// armMemoryWatch starts the resident-memory watch for a scan and returns the func
// that ends it.
//
// With --max-ram, the ceiling is the figure the user named: they asked for a
// bound, so passing it is a failure of the scan, not of the machine.
//
// Without it, the ceiling is what the machine or the cgroup allows, less a
// margin, which costs nothing: a scan that reaches it is a scan the kernel is
// about to end anyway. The difference is who pays. The OOM killer chooses by
// oom_score rather than by who caused the pressure, so on a shared box it can
// take an unrelated process instead. Stopping first keeps the failure where it
// belongs, and leaves a message behind.
func armMemoryWatch(maxRAM string) func() {
	if v := strings.TrimSpace(maxRAM); v != "" {
		if n, err := parseBytes(v); err == nil && n > 0 {
			return watchResidentMemory(n, "-max-ram "+v)
		}
	}
	if avail := memoryCeilingBytes(); avail > 0 {
		limit := boundedMemoryCeiling(avail)
		return watchResidentMemory(limit, humanBytes(limit)+", what this machine allows")
	}
	return func() {}
}
