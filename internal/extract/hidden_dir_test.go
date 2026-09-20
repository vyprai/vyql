package extract_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract"
)

// The walk tests pin that the tree walk lists source under .claude; this pins
// the scan itself — the counted walk under the scan's pruner, the language
// bucketing, the frontend routing — because that pipeline is what a
// whole-repository scan runs. A project ships executable source in its skill
// scripts (.claude/skills/*/scripts/*.py), and a scan that never parses them
// can say nothing about a fix landing there.
func TestAllAnalysesSkillSourceUnderDotClaude(t *testing.T) {
	root := t.TempDir()
	skillPath := filepath.Join(root, ".claude", "skills", "ui-styling", "scripts", "tailwind_config_gen.py")
	appPath := filepath.Join(root, "app.py")
	for _, path := range []string{skillPath, appPath} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		src := "import json\n\n\ndef shape(q):\n    return json.dumps({'tailwind': q})\n"
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	prog, _, _, st, err := extract.All([]string{root}, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	// Module.File is the path the frontend was given, relative to the scan
	// root, so the skill script's module carries its .claude path.
	var skill bool
	for _, m := range prog.Modules {
		if strings.HasSuffix(filepath.ToSlash(m.File), ".claude/skills/ui-styling/scripts/tailwind_config_gen.py") {
			skill = true
		}
	}
	if !skill {
		t.Fatalf("scan lowered no module for the skill script under .claude: %d modules", len(prog.Modules))
	}
	if st.Files["python"] != 2 {
		t.Fatalf("scan routed %d python files, want the app and the skill script", st.Files["python"])
	}
}
