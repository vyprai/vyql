package main

import (
	"os"
	"strconv"
	"strings"
)

// residentBytes reports the process's complete resident set, or 0 when it
// cannot be read. File-backed pages are reclaimable, but they still count
// toward RSS and cgroup accounting until the kernel reclaims them. A user who
// supplied -max-ram asked for a process ceiling, so excluding those pages would
// make the flag an optimistic estimate rather than a bound.
func residentBytes() int64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	return residentFromStatus(string(b))
}

func residentFromStatus(status string) int64 {
	for _, line := range strings.Split(status, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if ok && name == "VmRSS" {
			return kilobytesOf(rest)
		}
	}
	return 0
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
