package main

import (
	"os"
	"strconv"
	"strings"
)

// residentBytes reports the memory this process cannot give back, or 0 when it
// cannot be read.
//
// That is anonymous pages plus shared-memory pages, not the whole resident set.
// File-backed pages, such as badger's mapped tables, are resident but
// reclaimable, so counting them would stop a scan over memory the kernel can
// take away by itself. Shared-memory pages are counted because tmpfs is where they come from
// and the kernel cannot reclaim those.
//
// RssAnon and RssShmem arrive in /proc/self/status on Linux 4.5 and later. An
// older kernel reports neither, and there VmRSS is the only figure available.
func residentBytes() int64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	return residentFromStatus(string(b))
}

func residentFromStatus(status string) int64 {
	var anon, shmem, vmRSS int64
	var haveAnon, haveShmem bool
	for _, line := range strings.Split(status, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch name {
		case "RssAnon":
			anon, haveAnon = kilobytesOf(rest), true
		case "RssShmem":
			shmem, haveShmem = kilobytesOf(rest), true
		case "VmRSS":
			vmRSS = kilobytesOf(rest)
		}
	}
	if haveAnon || haveShmem {
		return anon + shmem
	}
	return vmRSS
}

// kilobytesOf parses a "  1234 kB" field into bytes.
func kilobytesOf(field string) int64 {
	f := strings.Fields(field)
	if len(f) == 0 {
		return 0
	}
	kb, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil {
		return 0
	}
	return kb * 1024
}
