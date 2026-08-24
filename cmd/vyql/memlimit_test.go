package main

import (
	"path/filepath"
	"testing"
)

func TestCgroupMemoryMaxReadsTheGroupTheProcessIsIn(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proc", "self", "cgroup"), "0::/user.slice/scan.scope\n")
	writeFile(t, filepath.Join(root, "sys", "fs", "cgroup", "user.slice", "scan.scope", "memory.max"), "4294967296\n")

	if got := cgroupMemoryMax(root); got != 4294967296 {
		t.Errorf("cgroupMemoryMax = %d, want 4294967296", got)
	}
}

// A group with no limit of its own inherits the nearest ancestor that has one.
func TestCgroupMemoryMaxClimbsToTheNearestLimit(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proc", "self", "cgroup"), "0::/user.slice/scan.scope\n")
	writeFile(t, filepath.Join(root, "sys", "fs", "cgroup", "user.slice", "scan.scope", "memory.max"), "max\n")
	writeFile(t, filepath.Join(root, "sys", "fs", "cgroup", "user.slice", "memory.max"), "2147483648\n")

	if got := cgroupMemoryMax(root); got != 2147483648 {
		t.Errorf("cgroupMemoryMax = %d, want 2147483648", got)
	}
}

func TestCgroupMemoryMaxFallsBackToVersionOne(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "sys", "fs", "cgroup", "memory", "memory.limit_in_bytes"), "1073741824\n")

	if got := cgroupMemoryMax(root); got != 1073741824 {
		t.Errorf("cgroupMemoryMax = %d, want 1073741824", got)
	}
}

// cgroup v1 writes an enormous sentinel rather than a word when there is no
// limit. Read literally it would claim the machine has petabytes.
func TestCgroupMemoryMaxRejectsTheUnlimitedSentinel(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "sys", "fs", "cgroup", "memory", "memory.limit_in_bytes"),
		"9223372036854771712\n")

	if got := cgroupMemoryMax(root); got != 0 {
		t.Errorf("cgroupMemoryMax = %d, want 0 for an unlimited group", got)
	}
}

func TestCgroupMemoryMaxIsZeroWithNothingToRead(t *testing.T) {
	if got := cgroupMemoryMax(t.TempDir()); got != 0 {
		t.Errorf("cgroupMemoryMax = %d, want 0", got)
	}
}

// The scan must budget against whichever is smaller: a container capped at 4 GiB
// on a 128 GiB host has 4 GiB, and 80% of the host figure is not a limit at all.
func TestMemoryCeilingTakesTheSmallerOfHostAndGroup(t *testing.T) {
	if got := memoryCeilingOf(128<<30, 4<<30); got != 4<<30 {
		t.Errorf("memoryCeilingOf = %d, want the group limit %d", got, 4<<30)
	}
	if got := memoryCeilingOf(8<<30, 64<<30); got != 8<<30 {
		t.Errorf("memoryCeilingOf = %d, want the host figure %d", got, 8<<30)
	}
	if got := memoryCeilingOf(8<<30, 0); got != 8<<30 {
		t.Errorf("memoryCeilingOf = %d, want the host figure when the group is unlimited", got)
	}
	if got := memoryCeilingOf(0, 4<<30); got != 4<<30 {
		t.Errorf("memoryCeilingOf = %d, want the group limit when the host figure is unknown", got)
	}
}
