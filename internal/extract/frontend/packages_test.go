package frontend

import (
	"slices"
	"testing"
)

func TestGeneratedPackageCandidateStems(t *testing.T) {
	deps := map[string]bool{
		"github.com/gin-gonic/gin/binding":           true,
		"@angular/core/testing":                      true,
		"org.springframework.security.crypto.bcrypt": true,
		"yaml": true,
	}

	got := generatedPackageCandidateStems(deps)
	want := []string{
		"@angular_core",
		"@angular_core_testing",
		"github.com",
		"github.com_gin-gonic",
		"github.com_gin-gonic_gin",
		"github.com_gin-gonic_gin_binding",
		"org.springframework",
		"org.springframework.security",
		"org.springframework.security.crypto",
		"org.springframework.security.crypto.bcrypt",
		"pyyaml",
		"yaml",
	}

	if !slices.Equal(got, want) {
		t.Fatalf("generated package candidates:\n got %v\nwant %v", got, want)
	}
}
