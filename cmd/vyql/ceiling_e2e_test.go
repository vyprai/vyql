package main

// A whole-repository scan under a RAM ceiling must finish and report, not die at
// the memory safety stop with an empty report. These cases run the built binary
// rather than the in-process scan path, because the stop is a process watchdog:
// it ends the process, and the empty report it leaves behind is only observable
// from outside.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/datadir"
)

// ceilingFixture writes a dense multi-package Python repository: several
// packages, each holding modules of many same-shaped handlers, every handler
// reading a caller-supplied field and passing an assembled command to a
// module-level runner, and every handler carrying its own string literals. That
// is the shape whose module literal mass grows with its function count — the
// Python lowering whose graph once grew quadratically enough to end a bounded
// whole-repository scan before any finding was emitted.
func ceilingFixture(t *testing.T, modules, handlers int) string {
	t.Helper()
	root := t.TempDir()
	for m := 0; m < modules; m++ {
		var b strings.Builder
		pkg := fmt.Sprintf("pkg%d", m/4)
		fmt.Fprintf(&b, "\"\"\"Module %d of package %s: %d device handlers.\"\"\"\n\n", m, pkg, handlers)
		fmt.Fprintf(&b, "import subprocess\n\n")
		fmt.Fprintf(&b, "DEVICE_ANNOTATION_%d = %q\n\n\n", m, fmt.Sprintf("org.example.device.%s.%d", pkg, m))
		b.WriteString(runScriptFunc(m))
		cls := fmt.Sprintf("Surface%d", m)
		fmt.Fprintf(&b, "\n\nclass %s:\n\n", cls)
		fmt.Fprintf(&b, "    label = %q\n\n", fmt.Sprintf("device surface %d", m))
		b.WriteString("    def __init__(self, method_args=None):\n" +
			"        self.method_args = method_args if method_args is not None else {\"serial\": \"\"}\n\n" +
			"    def read_setting(self, key):\n" +
			"        return self.method_args.get(key, \"default\")\n\n")
		for i := 0; i < handlers; i++ {
			b.WriteString(handlerMethod(m, i))
		}
		dir := filepath.Join(root, pkg)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(dir, fmt.Sprintf("surface_%d.py", m))
		if err := os.WriteFile(file, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func runScriptFunc(m int) string {
	return fmt.Sprintf(`def run_script_%d(script, args):
    """Run an assembled script, the way a daemon's macro runner does."""
    proc = subprocess.Popen(script + args, shell=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proc.communicate()
`, m)
}

func handlerMethod(m, i int) string {
	return fmt.Sprintf(`    def handler_%d_%d(self, request):
        """Handler %d: read the caller's field and run a macro with it."""
        key_%d = "setting.key.%d.%d"
        message_%d = "handler %d of module %d adjusts the device surface"
        data = request.get('field_%d')
        script = "echo " + data
        self.method_args[key_%d] = message_%d
        run_script_%d(script, [message_%d])
        return message_%d

`, m, i, i, i, m, i, i, i, m, i, i, i, m, i, i)
}

// TestBoundedWholeRepositoryScanEmitsFindingsUnderItsCeiling pins the behaviour
// a whole-repository scan owes its ceiling: it completes and reports its
// findings. Dense multi-package Python once ended such a scan at the memory
// safety stop before the first rule ran — an empty report from a ceiling the
// scan easily afforded — because the Python context re-carriage made the graph
// quadratic in functions-per-module and the disk-backed store's resident
// overhead rode alongside it. The scan below runs the real binary under the
// mandated ceiling pair (--max-ram 4GB --cache off); before those two fixes it
// stopped at 3.3 GiB of resident memory with no report, and the same invocation
// now finishes well inside both the ceiling and the wall clock a scan is given.
func TestBoundedWholeRepositoryScanEmitsFindingsUnderItsCeiling(t *testing.T) {
	root, ok := datadir.Lookup()
	if !ok {
		t.Skip("no vyql data directory; the ceiling scan needs the shipped definitions")
	}

	repo := ceilingFixture(t, 12, 60)
	cmd := exec.Command(vyqlBinary(t), "scan",
		"-data", root,
		"-fail-on", "none",
		"--max-ram", "4GB",
		"--cache", "off",
		repo)
	cmd.Env = append(os.Environ(), "VYQL_HOME=")
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		var exit *exec.ExitError
		if ok := asExitError(err, &exit); ok {
			t.Fatalf("the bounded whole-repository scan ended with exit %d before reporting:\n%s",
				exit.ExitCode(), tailOf(output, 800))
		}
		t.Fatalf("run the bounded scan: %v\n%s", err, tailOf(output, 800))
	}
	if strings.Contains(output, "safety threshold") {
		t.Fatalf("the scan reached the memory safety stop under its ceiling:\n%s",
			tailOf(output, 800))
	}
	if n := strings.Count(output, "DynamicCommandExec"); n == 0 {
		t.Fatalf("the completed scan reported no dynamic-command finding; every module's runner is one:\n%s",
			tailOf(output, 800))
	}
}

// tailOf returns the last cut bytes of a scan's output, for the failure message
// that has to carry what the scan said for itself.
func tailOf(s string, cut int) string {
	if len(s) <= cut {
		return s
	}
	return "..." + s[len(s)-cut:]
}
