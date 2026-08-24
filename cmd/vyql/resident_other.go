//go:build !linux

package main

// residentBytes reports this process's resident set size. Only the Linux build
// can read it without cgo, so elsewhere it reports 0, meaning "not known", and
// the memory watch stays disarmed rather than acting on a guess.
func residentBytes() int64 { return 0 }
