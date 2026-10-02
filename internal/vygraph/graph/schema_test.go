package graph

import "testing"

func TestFieldsRoundTripByKind(t *testing.T) {
	var f Fields
	f.Set("name", Str("web"))
	f.Set("privileged", Bool(true))
	f.Set("ports", List(KindInt, Int(80), Int(443)))

	if v, ok := f.Get("name"); !ok || v.Kind != KindString || v.S != "web" {
		t.Fatalf("name = %+v, ok=%v", v, ok)
	}
	if v, ok := f.Get("privileged"); !ok || v.Kind != KindBool || !v.B {
		t.Fatalf("privileged = %+v, ok=%v", v, ok)
	}
	if v, ok := f.Get("ports"); !ok || v.Kind != KindList || len(v.L) != 2 || v.L[0].I != 80 {
		t.Fatalf("ports = %+v, ok=%v", v, ok)
	}
	if _, ok := f.Get("absent"); ok {
		t.Fatal("Get on a missing field must report ok=false")
	}
}

func TestSchemaRejectsWrongKind(t *testing.T) {
	ts := &TypeSchema{
		Type:  "iac.Container",
		Layer: LayerHigh,
		Fields: []FieldSpec{
			{Name: "name", Kind: KindString},
			{Name: "privileged", Kind: KindBool},
		},
		Key: []string{"name"},
	}
	var f Fields
	f.Set("name", Str("web"))
	f.Set("privileged", Str("true")) // string where bool is declared

	if err := ts.Validate(f); err == nil {
		t.Fatal("a string in a bool field must be a validation error, not a silent miss")
	}
}

func TestSchemaRejectsUndeclaredFieldAndBadEnum(t *testing.T) {
	ts := &TypeSchema{
		Type:  "code.DataAccess",
		Layer: LayerHigh,
		Fields: []FieldSpec{
			{Name: "table", Kind: KindString},
			{Name: "op", Kind: KindEnum, Enum: []string{"read", "write"}},
		},
		Key: []string{"table", "op"},
	}
	var undeclared Fields
	undeclared.Set("table", Str("users"))
	undeclared.Set("nope", Str("x"))
	if err := ts.Validate(undeclared); err == nil {
		t.Fatal("an undeclared field must be rejected")
	}

	var badEnum Fields
	badEnum.Set("table", Str("users"))
	badEnum.Set("op", Str("drop"))
	if err := ts.Validate(badEnum); err == nil {
		t.Fatal("an out-of-set enum value must be rejected")
	}
}

func TestSchemasRegisterRejectsDuplicateAndUnknownKey(t *testing.T) {
	s := NewSchemas()
	ts := &TypeSchema{Type: "code.Call", Layer: LayerLow,
		Fields: []FieldSpec{{Name: "callee", Kind: KindString}}, Key: []string{"callee"}}
	if err := s.Register(ts); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := s.Register(ts); err == nil {
		t.Fatal("registering the same type twice must error")
	}
	bad := &TypeSchema{Type: "code.Bad", Layer: LayerLow,
		Fields: []FieldSpec{{Name: "a", Kind: KindString}}, Key: []string{"missing"}}
	if err := s.Register(bad); err == nil {
		t.Fatal("a Key naming an undeclared field must error")
	}
}
