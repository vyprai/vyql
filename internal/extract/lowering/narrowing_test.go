package lowering

import (
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

func TestInferTypeNarrowingTypeOfNumber(t *testing.T) {
	cond := nir.BinOp{
		Op: "===",
		Left: nir.Call{
			Method: "typeof",
			Args:   []nir.Expr{nir.Name{ID: "userId", Loc: "test.js:2"}},
			Loc:    "test.js:2",
		},
		Right: nir.Const{Value: `"number"`, Loc: "test.js:2"},
		Loc:   "test.js:2",
	}

	fact, ok := InferTypeNarrowing(cond)
	if !ok {
		t.Fatal("expected successful type narrowing")
	}
	if fact.VarName != "userId" {
		t.Errorf("expected varName 'userId', got %q", fact.VarName)
	}
	if fact.Type != TypeNumber || !fact.IsNumeric {
		t.Errorf("expected TypeNumber and IsNumeric=true, got type=%v", fact.Type)
	}
	if fact.Nullability != NullabilityNonNull {
		t.Errorf("expected NonNull nullability, got %v", fact.Nullability)
	}
}

func TestInferTypeNarrowingNullCheck(t *testing.T) {
	cond := nir.BinOp{
		Op:    "!=",
		Left:  nir.Name{ID: "item", Loc: "test.go:3"},
		Right: nir.Const{Value: "nil", Loc: "test.go:3"},
		Loc:   "test.go:3",
	}

	fact, ok := InferTypeNarrowing(cond)
	if !ok {
		t.Fatal("expected successful nullability narrowing")
	}
	if fact.VarName != "item" {
		t.Errorf("expected varName 'item', got %q", fact.VarName)
	}
	if fact.Nullability != NullabilityNonNull {
		t.Errorf("expected NonNull nullability, got %v", fact.Nullability)
	}
}

func TestInferTypeNarrowingValidationPredicates(t *testing.T) {
	cond := nir.Call{
		Method: "isUUID",
		Args:   []nir.Expr{nir.Name{ID: "token", Loc: "test.ts:4"}},
		Loc:    "test.ts:4",
	}

	fact, ok := InferTypeNarrowing(cond)
	if !ok {
		t.Fatal("expected successful predicate narrowing")
	}
	if fact.VarName != "token" {
		t.Errorf("expected varName 'token', got %q", fact.VarName)
	}
	if !fact.IsUUID {
		t.Errorf("expected IsUUID=true")
	}
}
