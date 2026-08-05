package frontend

import "testing"

func TestSafeJSPathComponentRegex(t *testing.T) {
	tests := []struct {
		name string
		lit  string
		want bool
	}{
		{
			name: "devcert patched literal string allowlist",
			lit:  `/^(a-zA-Z0-9|\.){1,64}$/`,
			want: true,
		},
		{
			name: "alnum char class with escaped dot",
			lit:  `/^[a-zA-Z0-9\._-]{1,64}$/`,
			want: true,
		},
		{
			name: "wildcard dot admits any path character",
			lit:  `/^(.|\.){1,64}$/`,
			want: false,
		},
		{
			name: "slash in allowlist can preserve traversal separators",
			lit:  `/^[a-zA-Z0-9\/.-]+$/`,
			want: false,
		},
		{
			name: "substring regex is not a guard",
			lit:  `/[a-zA-Z0-9]+/`,
			want: false,
		},
		{
			name: "unknown escape is rejected",
			lit:  `/^[a-zA-Z0-9\s]+$/`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safeJSPathComponentRegex(tt.lit); got != tt.want {
				t.Fatalf("safeJSPathComponentRegex(%q) = %v, want %v", tt.lit, got, tt.want)
			}
		})
	}
}
