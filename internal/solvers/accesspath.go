package solvers

import (
	"strings"
)

// MaxAccessPathDepth is the maximum field dereference depth before smashing
// access paths to prevent combinatorial state growth (docs/08 §precision).
const MaxAccessPathDepth = 3

// FieldAccessPath represents a bounded field dereference path (e.g. `user.profile.address`).
type FieldAccessPath struct {
	BaseNode string
	Fields   []string
	Smashed  bool
}

// NewFieldAccessPath creates an empty access path rooted at baseNode.
func NewFieldAccessPath(baseNode string) FieldAccessPath {
	return FieldAccessPath{
		BaseNode: baseNode,
		Fields:   nil,
		Smashed:  false,
	}
}

// Extend returns a new access path appending the given field name. If the field
// depth exceeds MaxAccessPathDepth, the access path is marked as smashed.
func (ap FieldAccessPath) Extend(field string) FieldAccessPath {
	if ap.Smashed {
		return ap
	}

	newFields := make([]string, len(ap.Fields)+1)
	copy(newFields, ap.Fields)
	newFields[len(ap.Fields)] = field

	if len(newFields) > MaxAccessPathDepth {
		return FieldAccessPath{
			BaseNode: ap.BaseNode,
			Fields:   newFields[:MaxAccessPathDepth],
			Smashed:  true,
		}
	}

	return FieldAccessPath{
		BaseNode: ap.BaseNode,
		Fields:   newFields,
		Smashed:  false,
	}
}

// String serializes the access path to a canonical string.
func (ap FieldAccessPath) String() string {
	if len(ap.Fields) == 0 {
		return ap.BaseNode
	}
	s := ap.BaseNode + "." + strings.Join(ap.Fields, ".")
	if ap.Smashed {
		s += ".*"
	}
	return s
}

// Matches reports whether two access paths refer to overlapping memory locations.
func (ap FieldAccessPath) Matches(other FieldAccessPath) bool {
	if ap.BaseNode != other.BaseNode {
		return false
	}

	if ap.Smashed || other.Smashed {
		minLen := len(ap.Fields)
		if len(other.Fields) < minLen {
			minLen = len(other.Fields)
		}
		for i := 0; i < minLen; i++ {
			if ap.Fields[i] != other.Fields[i] {
				return false
			}
		}
		return true
	}

	if len(ap.Fields) != len(other.Fields) {
		return false
	}

	for i := range ap.Fields {
		if ap.Fields[i] != other.Fields[i] {
			return false
		}
	}

	return true
}
