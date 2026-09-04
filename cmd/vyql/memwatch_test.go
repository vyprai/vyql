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

// stop is the caller's guarantee that nothing is still reading, so the test
// holds a reading inside the callback and stops the watch while it is in
// flight. A stop that returns early leaves that reading to land afterwards.
func TestMemWatchTakesNoReadingOnceStopReturns(t *testing.T) {
	entered := make(chan struct{}, 1)
	readings := make(chan struct{}, 1024)
	stop := memWatch(1000, time.Millisecond, func() int64 {
		select {
		case entered <- struct{}{}:
		default:
		}
		time.Sleep(30 * time.Millisecond)
		select {
		case readings <- struct{}{}:
		default:
		}
		return 10
	}, func(rss int64) {
		t.Errorf("fired at %d, below the 1000 ceiling", rss)
	})

	<-entered // a reading is in flight
	stop()
	drain(readings)

	// Whatever was in flight finished before stop returned, so nothing may
	// arrive now however long we wait.
	time.Sleep(100 * time.Millisecond)
	if n := len(readings); n != 0 {
		t.Errorf("%d readings landed after stop returned, want none", n)
	}
}

// Calling it twice must not panic on a closed channel, and the second call must
// still return rather than block on a sampler that has already gone.
func TestMemWatchStopIsRepeatable(t *testing.T) {
	stop := memWatch(1000, time.Millisecond, func() int64 { return 10 }, func(int64) {})
	stop()
	stop()
}

func TestMemoryStopThresholdLeavesBoundedHeadroom(t *testing.T) {
	tests := []struct {
		limit int64
		want  int64
	}{
		{limit: 1 << 30, want: 768 << 20},
		{limit: 4 << 30, want: 3584 << 20},
		{limit: 64 << 30, want: 62 << 30},
	}
	for _, tt := range tests {
		if got := memoryStopThreshold(tt.limit); got != tt.want {
			t.Errorf("memoryStopThreshold(%d) = %d, want %d", tt.limit, got, tt.want)
		}
	}
	if got := memoryStopThreshold(0); got != 0 {
		t.Errorf("memoryStopThreshold(0) = %d, want 0", got)
	}
}

func TestBoundedMemoryCeilingDoesNotWrapUint64(t *testing.T) {
	if got := boundedMemoryCeiling(^uint64(0)); got <= 0 {
		t.Fatalf("boundedMemoryCeiling(MaxUint64) = %d, want a positive bound", got)
	}
	if got := boundedMemoryCeiling(4 << 30); got != 4<<30 {
		t.Errorf("boundedMemoryCeiling(4 GiB) = %d, want %d", got, int64(4<<30))
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
