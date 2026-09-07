package main

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract"
	"github.com/vyprai/vyql/internal/findings"
)

// scanFixtureFindings runs the CLI scan path and returns the whole findings, so a
// test can assert WHERE a rule fired and not only that it did.
func scanFixtureFindings(t *testing.T, dir string) []*findings.Finding {
	t.Helper()
	allRules, err := loadRules("")
	if err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	fs, _, _, err := scanPathsWithProfileDemand([]string{dir}, allRules, "", true, extract.Options{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return fs
}

// sinkLines returns the sink locations at which ruleID fired, as "file:line".
func sinkLines(fs []*findings.Finding, ruleID string) []string {
	var out []string
	for _, f := range fs {
		if f.RuleID != ruleID {
			continue
		}
		loc := ""
		for _, b := range f.Bindings {
			if b.Loc != "" {
				loc = b.Loc // last binding is the sink
			}
		}
		out = append(out, loc)
	}
	return out
}

func hasLineSuffix(locs []string, suffix string) bool {
	for _, l := range locs {
		if strings.HasSuffix(l, suffix) {
			return true
		}
	}
	return false
}

// `pathlib.Path.write_bytes` is bound as a sink AT THE RECEIVER: the path being
// written is the receiver, and the argument is the file's CONTENT. Attacker-controlled
// content written to a constant path is not path traversal — the path the sink is
// about is a literal.
//
// The sink label sits on the call node (that is where the finding is reported), and a
// call node also carries the taint of every argument, so before the receiver anchor was
// recorded the content's taint alone reported VYQL-PATH-001 here.
func TestReceiverSinkIgnoresTaintFromArgument(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"requirements.txt": "flask\n",
		"app.py": "from pathlib import Path\n" +
			"from flask import Flask, request\n" +
			"\n" +
			"app = Flask(__name__)\n" +
			"BLOB = Path(\"/var/lib/app/blob.bin\")\n" +
			"\n" +
			"@app.route(\"/store\", methods=[\"POST\"])\n" +
			"def store():\n" +
			"    payload = request.get_data()\n" +
			"    BLOB.write_bytes(payload)\n" +
			"    return \"ok\"\n",
	})

	locs := sinkLines(scanFixtureFindings(t, dir), "VYQL-PATH-001")
	if len(locs) != 0 {
		t.Fatalf("traversal reported for tainted CONTENT written to a constant path: %v", locs)
	}
}

// The recall the receiver binding exists for: taint that reaches the RECEIVER is the
// traversal this sink is about, and must still be reported.
func TestReceiverSinkStillFiresOnTaintedReceiver(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"requirements.txt": "flask\n",
		"app.py": "from pathlib import Path\n" +
			"from flask import Flask, request\n" +
			"\n" +
			"app = Flask(__name__)\n" +
			"\n" +
			"@app.route(\"/fetch\")\n" +
			"def fetch():\n" +
			"    target = Path(request.args[\"name\"])\n" +
			"    return target.read_bytes()\n",
	})

	locs := sinkLines(scanFixtureFindings(t, dir), "VYQL-PATH-001")
	if !hasLineSuffix(locs, "app.py:9") {
		t.Fatalf("traversal into a tainted receiver was not reported: %v", locs)
	}
}
