//go:build linux

package treesitter

/*
#include <malloc.h>
*/
import "C"

import (
	"fmt"
	"os"
)

// parseResidentBytes reports the process's resident set, or 0 when it cannot
// be read. /proc/self/statm is the cheapest complete reading Linux offers; its
// second field is pages. File-backed pages are counted, for the same reason
// the process-wide watch counts them: the stop is a ceiling on the process,
// and a page the kernel has not reclaimed yet is still resident.
func parseResidentBytes() int64 {
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	var size, resident int64
	if n, _ := fmt.Sscanf(string(b), "%d %d", &size, &resident); n < 2 {
		return 0
	}
	return resident * int64(os.Getpagesize())
}

// trimResidentAlloc returns the allocator's free pages to the OS. A halted
// parse's tree is freed when the parser is reset, but glibc keeps large free
// blocks in its arenas, so the resident set stays at the parse's peak and the
// rest of the scan — whose budget counted those pages as released — is
// squeezed by memory nothing is using any more. Only the halt path calls this:
// it walks free lists, a cost no ordinary parse should pay.
func trimResidentAlloc() { C.malloc_trim(0) }
