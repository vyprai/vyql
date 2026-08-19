package lowering

import (
	"strings"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// TypeKind represents abstract types recognized during branch narrowing.
type TypeKind uint8

const (
	TypeUnknown TypeKind = iota
	TypeNumber
	TypeString
	TypeBoolean
	TypeObject
	TypeNull
)

// NullabilityKind represents abstract nullability states.
type NullabilityKind uint8

const (
	NullabilityUnknown NullabilityKind = iota
	NullabilityNonNull
	NullabilityNull
)

// NarrowedFact represents the narrowed type domain for a variable on a branch.
type NarrowedFact struct {
	VarName     string
	Type        TypeKind
	Nullability NullabilityKind
	IsNumeric   bool
	IsUUID      bool
}

// InferTypeNarrowing analyzes a condition expression to extract type and nullability
// constraints on variables for the true branch.
func InferTypeNarrowing(cond nir.Expr) (NarrowedFact, bool) {
	if cond == nil {
		return NarrowedFact{}, false
	}

	switch c := cond.(type) {
	case nir.BinOp:
		// typeof x === "number" or typeof x === "string"
		if c.Op == "===" || c.Op == "==" {
			if call, ok := c.Left.(nir.Call); ok && call.Method == "typeof" && len(call.Args) > 0 {
				if nm, ok := call.Args[0].(nir.Name); ok {
					if lit, ok := c.Right.(nir.Const); ok {
						val := unquoteLit(lit.Value)
						switch val {
						case "number":
							return NarrowedFact{
								VarName:     nm.ID,
								Type:        TypeNumber,
								Nullability: NullabilityNonNull,
								IsNumeric:   true,
							}, true
						case "string":
							return NarrowedFact{
								VarName:     nm.ID,
								Type:        TypeString,
								Nullability: NullabilityNonNull,
							}, true
						case "boolean":
							return NarrowedFact{
								VarName:     nm.ID,
								Type:        TypeBoolean,
								Nullability: NullabilityNonNull,
							}, true
						}
					}
				}
			}

			// x != null or x !== null
		} else if c.Op == "!=" || c.Op == "!==" {
			if nm, ok := c.Left.(nir.Name); ok {
				if lit, ok := c.Right.(nir.Const); ok {
					val := unquoteLit(lit.Value)
					if val == "null" || val == "undefined" || val == "nil" || val == "None" {
						return NarrowedFact{
							VarName:     nm.ID,
							Nullability: NullabilityNonNull,
						}, true
					}
				}
			}
		}

	case nir.Call:
		// isNumeric(x), isNumber(x), is_numeric(x), isUUID(x)
		methodLower := strings.ToLower(c.Method)
		if (strings.Contains(methodLower, "isnumeric") || strings.Contains(methodLower, "isnumber") || strings.Contains(methodLower, "is_numeric") || strings.Contains(methodLower, "isint") || strings.Contains(methodLower, "isinteger")) && len(c.Args) > 0 {
			if nm, ok := c.Args[0].(nir.Name); ok {
				return NarrowedFact{
					VarName:     nm.ID,
					Type:        TypeNumber,
					Nullability: NullabilityNonNull,
					IsNumeric:   true,
				}, true
			}
		}

		if (strings.Contains(methodLower, "isuuid") || strings.Contains(methodLower, "is_uuid")) && len(c.Args) > 0 {
			if nm, ok := c.Args[0].(nir.Name); ok {
				return NarrowedFact{
					VarName:     nm.ID,
					Type:        TypeString,
					Nullability: NullabilityNonNull,
					IsUUID:      true,
				}, true
			}
		}
	}

	return NarrowedFact{}, false
}
