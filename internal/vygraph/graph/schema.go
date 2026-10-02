package graph

import "fmt"

// FieldSpec declares one field of a node or edge type.
type FieldSpec struct {
	Name string
	Kind Kind
	Elem Kind     // element kind when Kind == KindList
	Enum []string // permitted values when Kind == KindEnum
}

// TypeSchema declares a node or edge type: its stratum, its typed fields, and the
// fields forming its identity key. Two producers writing the same keyed values resolve
// to one record.
type TypeSchema struct {
	Type   string
	Layer  Layer
	Fields []FieldSpec
	Key    []string
}

func (ts *TypeSchema) spec(name string) (FieldSpec, bool) {
	for _, f := range ts.Fields {
		if f.Name == name {
			return f, true
		}
	}
	return FieldSpec{}, false
}

// Validate checks every field against the declared schema. An undeclared field, a kind
// mismatch, or an out-of-set enum value is an error — never a silent miss.
func (ts *TypeSchema) Validate(f Fields) error {
	var err error
	f.Each(func(name string, v Value) bool {
		spec, ok := ts.spec(name)
		if !ok {
			err = fmt.Errorf("%s: undeclared field %q", ts.Type, name)
			return false
		}
		if v.Kind != spec.Kind {
			err = fmt.Errorf("%s.%s: declared %s, got %s", ts.Type, name, spec.Kind, v.Kind)
			return false
		}
		switch spec.Kind {
		case KindEnum:
			if !contains(spec.Enum, v.S) {
				err = fmt.Errorf("%s.%s: %q not in enum %v", ts.Type, name, v.S, spec.Enum)
				return false
			}
		case KindList:
			for i, e := range v.L {
				if e.Kind != spec.Elem {
					err = fmt.Errorf("%s.%s[%d]: declared %s, got %s", ts.Type, name, i, spec.Elem, e.Kind)
					return false
				}
			}
		}
		return true
	})
	return err
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// Schemas is the type registry. Populated from VyQL data at load time; the engine ships
// with none of its own.
type Schemas struct{ byType map[string]*TypeSchema }

func NewSchemas() *Schemas { return &Schemas{byType: map[string]*TypeSchema{}} }

func (s *Schemas) Register(ts *TypeSchema) error {
	if _, dup := s.byType[ts.Type]; dup {
		return fmt.Errorf("type %q already registered", ts.Type)
	}
	for _, k := range ts.Key {
		if _, ok := ts.spec(k); !ok {
			return fmt.Errorf("type %q: key field %q is not declared", ts.Type, k)
		}
	}
	s.byType[ts.Type] = ts
	return nil
}

func (s *Schemas) Lookup(t string) (*TypeSchema, bool) {
	ts, ok := s.byType[t]
	return ts, ok
}
