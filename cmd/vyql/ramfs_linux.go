package main

import "syscall"

// Filesystem magic numbers for the two kernel filesystems that live in memory.
// From linux/magic.h; they are part of the kernel ABI and do not change.
const (
	tmpfsMagic = 0x01021994
	ramfsMagic = 0x858458f6
)

// ramBacked reports whether path is on a filesystem held in memory. A path that
// cannot be inspected reports false: the check exists to warn, and a failed
// stat is not evidence of anything.
func ramBacked(path string) bool {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return false
	}
	switch int64(st.Type) {
	case tmpfsMagic, ramfsMagic:
		return true
	}
	return false
}
