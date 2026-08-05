package pack

import (
	"testing"

	"github.com/vyprai/vyql/internal/ontology"
)

func TestSatisfies(t *testing.T) {
	cases := []struct {
		ver, spec string
		want      bool
	}{
		{"1.4.0", ">=1.4 <2.0", true},
		{"2.0.0", ">=1.4 <2.0", false},
		{"1.3.9", ">=1.4 <2.0", false},
		{"0.9.0", ">=0.9", true},
		{"0.8.0", ">=0.9", false},
		{"1.4.0", "1.4.0", true},
		{"1.4.1", "1.4.0", false},
	}
	for _, c := range cases {
		if got := Satisfies(c.ver, c.spec); got != c.want {
			t.Fatalf("Satisfies(%q, %q) = %v, want %v", c.ver, c.spec, got, c.want)
		}
	}
}

func TestManifestValidate(t *testing.T) {
	onto := ontology.Seed()

	// valid manifest
	good := `{"pack":{"name":"vypr.rules.injection","version":"2026.06.1","ontology":">=1.0 <2.0","engine":">=0.1"},
	          "depends":{"concepts":["code.HttpInput","code.SqlExecution"]}}`
	m, err := Load([]byte(good))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if p := m.Validate(onto, "1.4.0", "0.1.0"); len(p) != 0 {
		t.Fatalf("valid pack should validate, got %v", p)
	}

	// unknown concept -> problem
	bad := `{"pack":{"name":"x","version":"1.0.0"},"depends":{"concepts":["code.NotAConcept"]}}`
	m2, _ := Load([]byte(bad))
	if p := m2.Validate(onto, "1.4.0", "0.1.0"); len(p) == 0 {
		t.Fatal("unknown concept should be a problem")
	}

	// incompatible ontology pin -> problem
	pin := `{"pack":{"name":"x","version":"1.0.0","ontology":">=2.0"},"depends":{"concepts":[]}}`
	m3, _ := Load([]byte(pin))
	if p := m3.Validate(onto, "1.4.0", "0.1.0"); len(p) == 0 {
		t.Fatal("incompatible ontology pin should be a problem")
	}
}
