//go:build !linux

package treesitter

// parseResidentBytes reports the process's resident set, or 0 where this
// platform has no reading to give. A reading of zero never halts a parse — the
// same rule the process-wide watch follows — so on these platforms the parse
// bound is inert and parses run as they did before it existed.
func parseResidentBytes() int64 { return 0 }

// trimResidentAlloc has nothing to return on this platform; the parse bound is
// inert here anyway (parseResidentBytes is 0), so it is never reached.
func trimResidentAlloc() {}
