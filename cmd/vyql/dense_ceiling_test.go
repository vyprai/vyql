package main

// A bounded scan of ordinary source must finish and report, not die at the memory
// safety stop with an empty report. These cases run the built binary rather than
// the in-process scan path, because the stop is a process watchdog: it ends the
// process, and the empty report it leaves behind is only observable from outside.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/datadir"
)

// denseOrdinaryFixture writes the shape this gap was calibrated on: one ordinary
// Python module of two thousand six-line functions — no construct beyond a
// getter, a guard and a delegated call, nothing a frontend could decline — plus
// one module carrying a complete taint path so the scan that survives has
// something to report. The rank that reported the gap measured this exact shape
// ("a synthetic file of 2000 six-line functions aborts the same way"): scanned
// as one graph under the mandated ceiling it was stopped at the memory safety
// threshold before any rule ran, with a zero-byte report.
func denseOrdinaryFixture(t *testing.T, functions int) string {
	t.Helper()
	root := t.TempDir()
	var b strings.Builder
	b.WriteString("from typing import Any\n\n\n")
	for i := 0; i < functions; i++ {
		fmt.Fprintf(&b, "def handler_%d(request: Any) -> Any:\n", i)
		fmt.Fprintf(&b, "    value = request.get(\"field_%d\")\n", i)
		b.WriteString("    if not value:\n")
		b.WriteString("        return None\n")
		fmt.Fprintf(&b, "    return delegate_%d(value)\n", i)
		b.WriteString("\n")
	}
	if err := os.WriteFile(filepath.Join(root, "dense.py"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	taint := "import os\n" +
		"from typing import Any\n" +
		"\n" +
		"\n" +
		"def run_command(request: Any) -> Any:\n" +
		"    cmd = request.GET.get(\"cmd\")\n" +
		"    return os.system(\"echo \" + cmd)\n"
	if err := os.WriteFile(filepath.Join(root, "taint.py"), []byte(taint), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestBoundedScanOfDenseOrdinarySourceReportsUnderItsCeiling pins the behaviour a
// bounded scan of a large ordinary-source target owes its ceiling: it completes and
// reports its findings. A target the ceiling easily holds as one graph was stopped at
// the memory safety threshold before the first rule ran — an empty report from a
// ceiling the target fit — because the ceiling armed the disk-backed graph store, and
// that store's resident cost sits on top of a structural core that never leaves RAM in
// either store. The scan below runs the real binary under the mandated ceiling pair
// (--max-ram 4GB --cache off); before the store decision (holdOneGraphInRAM) and the
// Python module-context economy landed, it stopped at 3.3 GiB of resident memory with
// a zero-byte report, and the same invocation now finishes with findings — which is
// the whole behaviour: a scan that survived its ceiling but reported nothing would
// leave the fidelity check that compares an isolated spec against a repository scan
// with nothing to compare.
func TestBoundedScanOfDenseOrdinarySourceReportsUnderItsCeiling(t *testing.T) {
	root, ok := datadir.Lookup()
	if !ok {
		t.Skip("no vyql data directory; the ceiling scan needs the shipped definitions")
	}

	repo := denseOrdinaryFixture(t, 2000)
	cmd := exec.Command(vyqlBinary(t), "scan",
		"-data", root,
		"-fail-on", "none",
		"--max-ram", "4GB",
		"--cache", "off",
		"-format", "sarif",
		repo)
	cmd.Env = append(os.Environ(), "VYQL_HOME=")
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		var exit *exec.ExitError
		if ok := asExitError(err, &exit); ok {
			t.Fatalf("the bounded scan of dense ordinary source ended with exit %d before reporting:\n%s",
				exit.ExitCode(), denseScanTail(output, 800))
		}
		t.Fatalf("run the bounded scan: %v\n%s", err, denseScanTail(output, 800))
	}
	if strings.Contains(output, "safety threshold") {
		t.Fatalf("the scan reached the memory safety stop under its ceiling:\n%s",
			denseScanTail(output, 800))
	}
	if n := strings.Count(output, "VYQL-INJ-"); n == 0 {
		t.Fatalf("the completed scan reported no injection finding; taint.py carries a complete path:\n%s",
			denseScanTail(output, 800))
	}
}

// denseScanTail returns the last cut bytes of a scan's output, for the failure
// message that has to carry what the scan said for itself.
func denseScanTail(s string, cut int) string {
	if len(s) <= cut {
		return s
	}
	return "..." + s[len(s)-cut:]
}
