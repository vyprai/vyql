package pipeline

import (
	"os"
	"path/filepath"
	"testing"
)

// The control mechanism: pipes.quote between source and sink must silence.
func TestControlSuppresses(t *testing.T) {
	dir := t.TempDir()
	vuln := `import flask
from db import session

@flask.route("/users")
def list_users(req):
    q = req.args.get("q")
    rows = session.execute("SELECT * FROM users WHERE name = " + q)
    return rows
`
	fixed := `import flask
from db import session

@flask.route("/users")
def list_users(req):
    q = req.args.get("q")
    rows = session.execute("SELECT * FROM users WHERE name = :name", {"name": q})
    return rows
`
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(vuln), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Run(dir, "testdata/kb", Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("vuln findings:\n%s", res.Output.Render())
	if len(res.Output.Findings) == 0 {
		t.Fatal("vuln side must fire")
	}

	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(fixed), 0o644); err != nil {
		t.Fatal(err)
	}
	res2, err := Run(dir, "testdata/kb", Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("fixed findings:\n%s", res2.Output.Render())
	if len(res2.Output.Findings) != 0 {
		t.Fatal("shlex.quote on the flow must suppress")
	}
}
