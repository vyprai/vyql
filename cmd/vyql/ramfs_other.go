//go:build !linux

package main

// ramBacked reports whether path is on a filesystem held in memory. Only Linux
// mounts a memory filesystem where a temporary directory normally lands, so
// elsewhere the answer is always no.
func ramBacked(string) bool { return false }
