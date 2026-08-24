package main

import (
	"testing"
	"time"
)

func TestMemWatchFiresOnceThePollCrossesTheCeiling(t *testing.T) {
	readings := make(chan int64, 4)
	fired := make(chan int64, 1)
	stop := memWatch(1000, time.Millisecond, func() int64 { return <-readings }, func(rss int64) {
		fired <- rss
	})
	defer stop()

	readings <- 400
	readings <- 999
	readings <- 1001
	select {
	case got := <-fired:
		if got != 1001 {
			t.Errorf("fired with %d, want the reading that crossed, 1001", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the watch never fired above the ceiling")
	}
}

func TestMemWatchStaysQuietBelowTheCeiling(t *testing.T) {
	fired := make(chan int64, 1)
	stop := memWatch(1000, time.Millisecond, func() int64 { return 999 }, func(rss int64) {
		fired <- rss
	})
	defer stop()

	select {
	case got := <-fired:
		t.Errorf("fired at %d, below the 1000 ceiling", got)
	case <-time.After(50 * time.Millisecond):
	}
}

// A reading of zero means resident memory could not be determined on this
// platform. It must never be read as "well under the ceiling", and never as a
// crossing.
func TestMemWatchIgnoresAnUnknownReading(t *testing.T) {
	fired := make(chan int64, 1)
	stop := memWatch(1, time.Millisecond, func() int64 { return 0 }, func(rss int64) {
		fired <- rss
	})
	defer stop()

	select {
	case got := <-fired:
		t.Errorf("fired on an unknown reading of %d", got)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestMemWatchStops(t *testing.T) {
	calls := make(chan struct{}, 100)
	stop := memWatch(1000, time.Millisecond, func() int64 {
		select {
		case calls <- struct{}{}:
		default:
		}
		return 10
	}, func(int64) {})
	time.Sleep(20 * time.Millisecond)
	stop()
	drain(calls)
	time.Sleep(20 * time.Millisecond)
	if len(calls) != 0 {
		t.Errorf("%d polls after stop, want none", len(calls))
	}
}

func drain(c chan struct{}) {
	for {
		select {
		case <-c:
		default:
			return
		}
	}
}

func TestResidentBytesReportsSomethingOrNothing(t *testing.T) {
	// Either the platform can read its own resident size, or it says so with a
	// zero. A negative or absurd figure means the units are wrong.
	got := residentBytes()
	if got < 0 {
		t.Fatalf("residentBytes() = %d", got)
	}
	if got > 0 && got < 1<<20 {
		t.Errorf("residentBytes() = %d, under a megabyte: the reading is not in bytes", got)
	}
}
