//go:build darwin

package main

import "syscall"

// residentBytes reports this process's resident high-water mark on Darwin.
// getrusage exposes bytes on Darwin (Linux reports KiB, which is why this lives
// in a platform file). A high-water mark is deliberately conservative for a
// hard ceiling: memory that crossed the safety threshold must not be treated as
// harmless merely because the allocator happened to return some of it before
// the next sample.
func residentBytes() int64 {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0
	}
	return usage.Maxrss
}
