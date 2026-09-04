//go:build !linux && !darwin

package main

// residentBytes reports this process's resident set size. Platforms without a
// native implementation report 0, meaning "not known", and the memory watch
// stays disarmed rather than acting on a guess.
func residentBytes() int64 { return 0 }
