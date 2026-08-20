package datadir

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"v1.0.0", "1.0.0", 0},
		{"0.0.1", "0.0.2", -1},
		{"0.1.0", "0.0.9", 1},
		{"1.0.0", "0.9.9", 1},
		{"1.2.3", "1.10.0", -1},
		{"", "1.0.0", -1},
	}
	for _, c := range cases {
		got := CompareVersions(c.a, c.b)
		if got != c.want {
			t.Fatalf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestNeedsUpdate(t *testing.T) {
	if !NeedsUpdate("", "1.0.0") {
		t.Fatal("empty local needs update")
	}
	if NeedsUpdate("1.0.0", "1.0.0") {
		t.Fatal("same version does not need update")
	}
	if !NeedsUpdate("1.0.0", "1.0.1") {
		t.Fatal("patch bump needs update")
	}
	if NeedsUpdate("1.1.0", "1.0.9") {
		t.Fatal("newer local does not need update")
	}
}
