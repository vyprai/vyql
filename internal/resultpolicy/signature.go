package resultpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// SigHop is one hop of a finding's witness, reduced to the identity that
// survives benign churn: the concept label, plus the callee path when the hop
// is a call. Line numbers, files and node ids are deliberately absent — they
// change under edits the verdict should outlive (docs/adr/0004).
type SigHop struct {
	Concept string
	Callee  string // empty when the hop is not a call (variables, parameters)
}

// sigJoiner separates hops and the concept from the callee inside a hop. A
// printable separator would let a crafted concept or path containing it
// collide two different hop sequences; unit separators do not occur in
// concept names or callee paths.
const (
	sigHopSep   = "\x1f"
	sigFieldSep = "\x1e"
	sigTruncHex = 16
)

// PathSignature is to the taint path what Fingerprint is to the finding: a
// short, stable identity, one implementation in this package (the guard in
// identity_surfaces_test.go keeps it that way). A baseline entry that carries
// signatures suppresses only a finding whose path still hashes to one of them;
// the same fingerprint with a new signature re-fires as drifted and goes back
// to verification.
//
// Callers resolve hops from the witness against the store at finding-build
// time; this function is pure so every caller that starts from the same hops
// derives the same string.
func PathSignature(hops []SigHop) string {
	if len(hops) == 0 {
		return ""
	}
	parts := make([]string, 0, len(hops))
	for _, h := range hops {
		if h.Callee == "" {
			parts = append(parts, h.Concept)
			continue
		}
		parts = append(parts, h.Concept+sigFieldSep+h.Callee)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, sigHopSep)))
	return hex.EncodeToString(sum[:])[:sigTruncHex]
}
