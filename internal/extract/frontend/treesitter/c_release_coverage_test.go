package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/solvers"
	"github.com/vyprai/vyql/internal/usg"
)

// cReleaseCoverage lowers one C source and answers, for the call named by
// acquire and the call named by release, whether the release covers every path
// out of the function. The structural answer is returned beside it: the two
// disagree exactly where the shape this pins lives.
func cReleaseCoverage(t *testing.T, src, acquire, release string) (structural, covered bool) {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "server.c")
	if err := os.WriteFile(file, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	acquireID := cCallNode(t, g, acquire)
	releaseID := cCallNode(t, g, release)
	return solvers.PostDominates(g, releaseID, acquireID),
		solvers.PostDominatesCovered(g, solvers.NewExitIndex(g), []string{releaseID}, acquireID)
}

// cCallNode returns the id of the one call node whose callee path is path.
func cCallNode(t *testing.T, g usg.Store, path string) string {
	t.Helper()
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var found string
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != path {
			continue
		}
		if found != "" {
			t.Fatalf("%s is called more than once, so the test cannot name one site", path)
		}
		found = n.ID
	}
	if found == "" {
		t.Fatalf("no call to %s in the lowered graph", path)
	}
	return found
}

// CVE-2025-0726, NetX Duo's HTTP server: fx_file_open succeeds, a later write
// fails, and the error branch returns with the file still open. The close
// written at the end of the body follows the open in the enclosing region --
// the structural relation the region/order encoding can see -- and runs on no
// path that branch takes.
func TestCEarlyReturnAfterAWriteFailsLeavesTheFileOpen(t *testing.T) {
	structural, covered := cReleaseCoverage(t, `
UINT put_process(NX_WEB_HTTP_SERVER *server_ptr, NX_PACKET *packet_ptr)
{
UINT status;

    status = fx_file_open(server_ptr -> media_ptr, &(server_ptr -> file), server_ptr -> resource, FX_OPEN_FOR_WRITE);
    if (status != NX_SUCCESS)
    {
        response_send(server_ptr, 500);
        return;
    }

    status = fx_file_write(&(server_ptr -> file), packet_ptr -> prepend_ptr, 16);
    if (status != NX_SUCCESS)
    {
        response_send(server_ptr, 500);
        return;
    }

    fx_file_close(&(server_ptr -> file));
}
`, "fx_file_open", "fx_file_close")
	if !structural {
		t.Fatal("the close follows the open in the enclosing region, so the structural relation holds")
	}
	if covered {
		t.Error("the branch that returns when the write fails never reaches the close")
	}
}

// The same function with no branch between the two: the close runs on the one
// path there is, and reporting it would report every correct acquisition.
func TestCReleaseWithNoBranchBetweenCoversTheAcquisition(t *testing.T) {
	_, covered := cReleaseCoverage(t, `
UINT put_process(NX_WEB_HTTP_SERVER *server_ptr, NX_PACKET *packet_ptr)
{
UINT status;

    status = fx_file_open(server_ptr -> media_ptr, &(server_ptr -> file), server_ptr -> resource, FX_OPEN_FOR_WRITE);
    if (status != NX_SUCCESS)
    {
        response_send(server_ptr, 500);
        return;
    }

    status = fx_file_write(&(server_ptr -> file), packet_ptr -> prepend_ptr, 16);

    fx_file_close(&(server_ptr -> file));
}
`, "fx_file_open", "fx_file_close")
	if !covered {
		t.Error("nothing leaves the function between the open and the close")
	}
}
