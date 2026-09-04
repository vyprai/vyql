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

// The hard ceiling covers the complete resident set, including file-backed
// pages that the kernel has not reclaimed yet.
func TestResidentFromStatusCountsCompleteRSS(t *testing.T) {
	want := int64(31655336) * 1024
	if got := residentFromStatus(procStatus); got != want {
		t.Errorf("residentFromStatus = %d, want %d", got, want)
	}
}

func TestResidentFromStatusReadsVmRSS(t *testing.T) {
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
