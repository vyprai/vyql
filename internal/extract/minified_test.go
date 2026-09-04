package extract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeProbe(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "f.js")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write probe file: %v", err)
	}
	return path
}

// The one rule the gate follows: lines that average minifiedLineAverage bytes
// or more are machine output, however the file is named. Written code —
// hand-written or generated-but-formatted — measures an order of magnitude
// below that, and bundles measure orders of magnitude above it.
func TestMinifiedBundleShape(t *testing.T) {
	longLine := strings.Repeat("e['k']=function(n){return n+i*(n-i)};", 1200) // ~40KB, no newline
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"single-line bundle", longLine, true},
		{"license header then one line", "/*! lib v1 (c) 2024 */\n/*! MIT */\n" + longLine, true},
		{"formatted source", strings.Repeat("function f(n) {\n\treturn n + 1;\n}\n", 900), false},
		{"dense but line-broken", strings.Repeat("e['k']=function(n){return n+i*(n-i)};\n", 900), false},
		{"below the size floor", longLine[:4<<10], false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeProbe(t, tc.body)
			if got := minifiedBundle(path, int64(len(tc.body))); got != tc.want {
				t.Errorf("minifiedBundle = %v, want %v", got, tc.want)
			}
		})
	}
}

// A file that cannot be read is not machine output; deciding it was would drop
// it without evidence.
func TestMinifiedBundleUnreadableFileIsNotMinified(t *testing.T) {
	if minifiedBundle(filepath.Join(t.TempDir(), "absent.js"), 64<<10) {
		t.Error("a file that cannot be read must not be reported as minified")
	}
}
