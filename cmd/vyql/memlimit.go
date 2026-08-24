package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
)

// init sets a soft heap limit (GOMEMLIMIT) at ~80% of the memory this process may use, unless the
// user already set one. Go's default is unlimited, so scanning a huge repo can let RSS balloon
// past what is available and OOM or swap. A soft limit makes the GC work harder as the heap
// approaches it — bounding RSS at the cost of more GC near the ceiling — so large scans complete
// instead of being killed. Small scans never approach the limit, so they are unaffected.
func init() {
	if os.Getenv("GOMEMLIMIT") != "" {
		return // explicit override wins
	}
	if avail := memoryCeilingBytes(); avail > 0 {
		debug.SetMemoryLimit(int64(float64(avail) * 0.80))
	}
}

// memoryCeilingBytes reports how much memory this process may actually use, or 0 if it cannot be
// determined.
func memoryCeilingBytes() uint64 {
	return memoryCeilingOf(physicalRAMBytes(), cgroupMemoryMax("/"))
}

// memoryCeilingOf picks between what the machine has and what this process's cgroup allows. The
// smaller one is the real ceiling: a container capped at 4 GiB on a 128 GiB host has 4 GiB, and
// budgeting against the host figure there means being killed at 3% of the budget. Either figure
// may be 0, meaning "not known"; two unknowns give 0.
func memoryCeilingOf(phys, group uint64) uint64 {
	switch {
	case phys == 0:
		return group
	case group == 0:
		return phys
	case group < phys:
		return group
	default:
		return phys
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

// cgroupMemoryMax returns the memory limit of the cgroup this process is in, or 0 when there is
// none. root is the filesystem root to read under, so the resolution can be tested against a
// directory tree rather than the machine's own.
//
// A scan run by a CI job, a container or a systemd unit is usually capped well below the host's
// memory, and the cap is what it will be killed at.
func cgroupMemoryMax(root string) uint64 {
	if n := cgroupV2Max(root); n > 0 {
		return n
	}
	return readCgroupBytes(filepath.Join(root, "sys", "fs", "cgroup", "memory", "memory.limit_in_bytes"))
}

// cgroupV2Max walks from the process's own group up to the root, taking the first group that names
// a limit. A group that inherits its parent's limit writes "max" in its own file, so stopping at
// the first file found would read no limit where one applies.
func cgroupV2Max(root string) uint64 {
	b, err := os.ReadFile(filepath.Join(root, "proc", "self", "cgroup"))
	if err != nil {
		return 0
	}
	rel := ""
	for _, line := range strings.Split(string(b), "\n") {
		// The unified hierarchy is the entry with an empty controller list: "0::<path>".
		if strings.HasPrefix(line, "0::") {
			rel = strings.TrimPrefix(line, "0::")
			break
		}
	}
	if rel == "" {
		return 0
	}
	dir := filepath.Join(root, "sys", "fs", "cgroup", filepath.Clean("/"+rel))
	base := filepath.Join(root, "sys", "fs", "cgroup")
	for {
		if n := readCgroupBytes(filepath.Join(dir, "memory.max")); n > 0 {
			return n
		}
		if dir == base || len(dir) <= len(base) {
			return 0
		}
		dir = filepath.Dir(dir)
	}
}

// readCgroupBytes parses one cgroup limit file. "max" is v2's word for no limit; v1 has no word
// and writes a sentinel close to the maximum signed 64-bit page count instead, which read
// literally would claim the machine has petabytes.
func readCgroupBytes(path string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(b))
	if s == "" || s == "max" {
		return 0
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n == 0 || n >= 1<<62 {
		return 0
	}
	return n
}
