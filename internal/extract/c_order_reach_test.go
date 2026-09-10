package extract_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/solvers"
	"github.com/vyprai/vyql/internal/usg"
)

// The end-to-end shape of CVE-2020-14354 (c-ares, ares_getaddrinfo.c): a release written
// in one branch, and further releases written in the branches that follow it. The two
// branches are separate constructs written one after the other, so region and order
// sequence them — but whether the first release reaches the second turns on the `return`
// that closes the first branch. Without it the branch falls through and the pair is the
// double free the CVE is; with it the branch ends the function and no later release runs
// after that release. Lowered C must answer both spellings that way.
func TestCEarlyReturnBetweenReleasesEndsThePath(t *testing.T) {
	const hostCallback = `
struct hq { int remaining; };

static void end_hquery(struct hq *hquery, int status)
{
    free(hquery);
}

static void host_callback(void *arg, int status)
{
    struct hq *hquery = (struct hq *)arg;
    int addinfo = 0;
    hquery->remaining--;

    if (status == 0)
      {
        addinfo = parse(abuf, alen, hquery);
      }
    else if (status == ARES_EDESTRUCTION)
      {
        end_hquery(hquery, status);
        %s
      }

    if (!hquery->remaining)
      {
        if (addinfo != 0)
          end_hquery(hquery, addinfo);
        else
          end_hquery(hquery, status);
      }
}
`

	calls := func(t *testing.T, g usg.Store) []usg.Node {
		t.Helper()
		nodes, err := g.AllNodes()
		if err != nil {
			t.Fatal(err)
		}
		var out []usg.Node
		for _, n := range nodes {
			if n.Type == "code.Call" && n.Prop("callee_path") == "end_hquery" {
				out = append(out, n)
			}
		}
		if len(out) != 3 {
			t.Fatalf("end_hquery() call sites = %d, want 3", len(out))
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Order < out[j].Order })
		return out
	}

	// The fixed spelling: `return` after the release. Nothing after that branch can run
	// once it is taken, so the first release reaches neither later release.
	fixed := lowerC(t, "ares.c", strings.Replace(hostCallback, "%s", "return;", 1))
	fixedCalls := calls(t, fixed)
	exits := solvers.NewExitIndex(fixed)
	for _, later := range fixedCalls[1:] {
		if solvers.Reaches(fixed, exits, fixedCalls[0].ID, later.ID) {
			t.Errorf("the release in the returning branch must not reach the later release at order %d", later.Order)
		}
	}

	// The vulnerable spelling: the `return` is missing, the branch falls through, and the
	// first release does run before the ones that follow.
	vuln := lowerC(t, "ares.c", strings.Replace(hostCallback, "%s", "", 1))
	vulnCalls := calls(t, vuln)
	vulnExits := solvers.NewExitIndex(vuln)
	reached := false
	for _, later := range vulnCalls[1:] {
		if solvers.Reaches(vuln, vulnExits, vulnCalls[0].ID, later.ID) {
			reached = true
		}
	}
	if !reached {
		t.Error("with the return taken out the branch falls through and the double free is reportable again")
	}
}
