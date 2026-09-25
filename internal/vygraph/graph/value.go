// Package graph is the VyGraph generic typed property-graph VM. It hard-codes three
// record kinds and nothing about security: no concept, CWE, rule or technology
// name appears here. Meaning arrives as data, via Labels.
package graph

import "fmt"

// Kind is a field's declared type. Predicates evaluate against the declared kind, so a
// mismatch is an error rather than a silent string comparison.
type Kind uint8

const (
	KindString Kind = iota
	KindInt
	KindBool
	KindEnum
	KindList
)

func (k Kind) String() string {
	switch k {
	case KindString:
		return "string"
	case KindInt:
		return "int"
	case KindBool:
		return "bool"
	case KindEnum:
		return "enum"
	case KindList:
		return "list"
	}
	return "invalid"
}

// Value is one typed field value. It is a struct rather than an interface so a node's
// fields cost no per-value allocation — a map per node was the dominant per-node memory
// cost measured in the v2 engine.
type Value struct {
	Kind Kind
	S    string
	I    int64
	B    bool
	L    []Value // populated when Kind == KindList
	Elem Kind    // element kind when Kind == KindList
}

func Str(s string) Value { return Value{Kind: KindString, S: s} }
func Int(i int64) Value  { return Value{Kind: KindInt, I: i} }
func Bool(b bool) Value  { return Value{Kind: KindBool, B: b} }

func List(elem Kind, vs ...Value) Value {
	return Value{Kind: KindList, Elem: elem, L: vs}
}

// Fields is a small ordered record. Slice-backed, not a map: most nodes carry a handful
// of fields, and a map per node is both slower and far larger.
type Fields struct {
	names []string
	vals  []Value
}

// Set assigns name, replacing any existing value.
func (f *Fields) Set(name string, v Value) {
	for i, n := range f.names {
		if n == name {
			f.vals[i] = v
			return
		}
	}
	f.names = append(f.names, name)
	f.vals = append(f.vals, v)
}

func (f Fields) Get(name string) (Value, bool) {
	for i, n := range f.names {
		if n == name {
			return f.vals[i], true
		}
	}
	return Value{}, false
}

func (f Fields) Len() int { return len(f.names) }

// Each iterates the fields in insertion order.
func (f Fields) Each(fn func(name string, v Value) bool) {
	for i, n := range f.names {
		if !fn(n, f.vals[i]) {
			return
		}
	}
}

func (v Value) String() string {
	switch v.Kind {
	case KindString, KindEnum:
		return v.S
	case KindInt:
		return fmt.Sprintf("%d", v.I)
	case KindBool:
		return fmt.Sprintf("%t", v.B)
	case KindList:
		return fmt.Sprintf("list<%s>(%d)", v.Elem, len(v.L))
	}
	return "?"
}
