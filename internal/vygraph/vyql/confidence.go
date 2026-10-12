package vyql

// Confidence is the v3 fidelity ladder:
// signal < possibility < low < medium < high. A rule's emitted confidence is
// min(rule floor, match fidelity), then clamped by mechanism.
type Confidence uint8

const (
	ConfSignal Confidence = iota
	ConfPossibility
	ConfLow
	ConfMedium
	ConfHigh
)

func (c Confidence) String() string {
	switch c {
	case ConfSignal:
		return "signal"
	case ConfPossibility:
		return "possibility"
	case ConfLow:
		return "low"
	case ConfMedium:
		return "medium"
	case ConfHigh:
		return "high"
	}
	return "invalid"
}

// ParseConfidence parses a ladder word.
func ParseConfidence(s string) (Confidence, bool) {
	switch s {
	case "signal":
		return ConfSignal, true
	case "possibility":
		return ConfPossibility, true
	case "low":
		return ConfLow, true
	case "medium":
		return ConfMedium, true
	case "high":
		return ConfHigh, true
	}
	return 0, false
}

// FidelityCap bounds a match by how its binding was resolved: syntactic matches
// cap at medium, resolved/semantic matches at high.
func FidelityCap(fidelity string) Confidence {
	if fidelity == "resolved" {
		return ConfHigh
	}
	return ConfMedium
}

// CapLowLevelType is the clamp applied to a rule that names a low-level NIR type
// or traverses backs: the same quarantine as the escape hatch, at medium.
const CapLowLevelType = ConfMedium

var severities = map[string]bool{
	"info": true, "low": true, "medium": true, "high": true, "critical": true,
}
