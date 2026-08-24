package main

import "testing"

const procStatus = `Name:	vyql
VmPeak:	48856104 kB
VmSize:	43321964 kB
VmRSS:	31655336 kB
RssAnon:	30655336 kB
RssFile:	123456 kB
RssShmem:	876544 kB
Threads:	17
`

// The figure that matters is what the kernel cannot take back: anonymous pages
// plus shared memory. Mapped files are resident and reclaimable, so a scan must
// not be stopped over them.
func TestResidentFromStatusCountsAnonAndSharedOnly(t *testing.T) {
	want := int64(30655336+876544) * 1024
	if got := residentFromStatus(procStatus); got != want {
		t.Errorf("residentFromStatus = %d, want %d", got, want)
	}
}

// A kernel older than 4.5 reports neither breakdown field.
func TestResidentFromStatusFallsBackToVmRSS(t *testing.T) {
	const old = "Name:\tvyql\nVmRSS:\t   4096 kB\nThreads:\t2\n"
	if got := residentFromStatus(old); got != 4096*1024 {
		t.Errorf("residentFromStatus = %d, want %d", got, 4096*1024)
	}
}

func TestResidentFromStatusIsZeroWithNothingToRead(t *testing.T) {
	if got := residentFromStatus("Name:\tvyql\n"); got != 0 {
		t.Errorf("residentFromStatus = %d, want 0", got)
	}
}
