package main

import (
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
)

// init sets a soft heap limit (GOMEMLIMIT) at ~80% of physical RAM unless the user already set
// one. Go's default is unlimited, so scanning a huge repo (e.g. the Linux kernel) can let RSS
// balloon past physical memory and OOM/swap. A soft limit makes the GC work harder as the heap
// approaches it — bounding RSS at the cost of more GC near the ceiling — so large scans complete
// instead of being killed. Small scans never approach the limit, so they are unaffected.
func init() {
	if os.Getenv("GOMEMLIMIT") != "" {
		return // explicit override wins
	}
	if phys := physicalRAMBytes(); phys > 0 {
		debug.SetMemoryLimit(int64(float64(phys) * 0.80))
	}
}

// physicalRAMBytes returns total physical memory, or 0 if it can't be determined.
func physicalRAMBytes() uint64 {
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
		if err != nil {
			return 0
		}
		n, _ := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
		return n
	case "linux":
		b, err := os.ReadFile("/proc/meminfo")
		if err != nil {
			return 0
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				f := strings.Fields(line)
				if len(f) >= 2 {
					kb, _ := strconv.ParseUint(f[1], 10, 64)
					return kb * 1024
				}
			}
		}
	}
	return 0
}
