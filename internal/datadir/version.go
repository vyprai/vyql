package datadir

import (
	"strconv"
	"strings"
)

// CompareVersions compares two bare semver strings (X.Y.Z, optional leading "v").
// It returns -1 if a < b, 0 if a == b, and 1 if a > b.
// Malformed versions sort as less than any well-formed version, and equal to
// each other only when both are malformed in the same way after normalisation.
func CompareVersions(a, b string) int {
	pa, oka := parseSemver(a)
	pb, okb := parseSemver(b)
	if !oka && !okb {
		if a == b {
			return 0
		}
		if a < b {
			return -1
		}
		return 1
	}
	if !oka {
		return -1
	}
	if !okb {
		return 1
	}
	for i := 0; i < 3; i++ {
		if pa[i] < pb[i] {
			return -1
		}
		if pa[i] > pb[i] {
			return 1
		}
	}
	return 0
}

// NeedsUpdate reports whether remote is a newer free-channel version than local.
// An empty local version always needs an update when remote is well-formed.
func NeedsUpdate(local, remote string) bool {
	if strings.TrimSpace(remote) == "" {
		return false
	}
	if strings.TrimSpace(local) == "" {
		return true
	}
	return CompareVersions(local, remote) < 0
}

func parseSemver(v string) ([3]int, bool) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		if p == "" {
			return [3]int{}, false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return [3]int{}, false
			}
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}
