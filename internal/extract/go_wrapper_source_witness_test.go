package extract_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract"
	"github.com/vyprai/vyql/internal/solvers"
	"github.com/vyprai/vyql/internal/usg"
)

// The quill notary shape, end to end through the Go frontend. An API client wraps its
// HTTP fetch in a struct (`s.http.get`), reads the metadata response through a shared
// helper (`handleResponse`), decodes a URL out of it, and fetches THAT with a bare
// http.Get whose URL argument is the sink. The wrapper's own fetch (`s.client.Do`) is the
// labelled source, and so is the vulnerable fetch's response (http.Get) — both are network
// reads. What the finding must report as its source is the METADATA chain: the wrapper's
// Do, whose response supplied the URL. Reporting the vulnerable fetch's own response
// instead — the sink's own data, arriving through the shared helper's return — is the
// call-site crossing this test pins: the witness has to enter and leave handleResponse
// through the metadata invocation, which needs the wrapper's return attribution to exist
// at all and the witness walk to re-anchor to the exiting call site's argument.
func TestGoWrapperSourceIsTheMetadataFetchNotTheVulnerableFetch(t *testing.T) {
	src := `package notary

import (
	"encoding/json"
	"io"
	"net/http"
)

type httpClient struct{ client *http.Client }

func (s httpClient) do(request *http.Request) (*http.Response, error) {
	return s.client.Do(request)
}

func (s httpClient) get(endpoint string) (*http.Response, error) {
	request, _ := http.NewRequest("GET", endpoint, nil)
	return s.do(request)
}

type APIClient struct {
	api  string
	http *httpClient
}

func (s APIClient) handleResponse(response *http.Response, err error) ([]byte, error) {
	return io.ReadAll(response.Body)
}

type logsMeta struct {
	Data struct {
		Attributes struct {
			DeveloperLogURL string
		}
	}
}

func (s APIClient) submissionLogs(id string) ([]byte, error) {
	metadataResp, err := s.http.get(s.api + "/" + id + "/logs")
	body, err := s.handleResponse(metadataResp, err)
	var meta logsMeta
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, err
	}
	logsResp, err := http.Get(meta.Data.Attributes.DeveloperLogURL)
	return s.handleResponse(logsResp, err)
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "api_client.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	g, _, err := extract.BuildGraph([]string{dir}, nil, extract.Options{})
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	// stand-ins for the net/http response binding: both network reads are sources
	wrapperDo := nodeByCallee(t, g, "s.client.Do")
	vulnFetch := nodeByCallee(t, g, "http.Get")
	if err := g.AddLabel(wrapperDo, usg.Label{Concept: "test.Source"}); err != nil {
		t.Fatal(err)
	}
	if err := g.AddLabel(vulnFetch, usg.Label{Concept: "test.Source"}); err != nil {
		t.Fatal(err)
	}
	// the sink is the vulnerable fetch's URL argument
	n, _, _ := g.GetNode(vulnFetch)
	sink := n.Prop("arg0")
	if sink == "" {
		t.Fatalf("http.Get call records no arg0")
	}
	if err := g.AddLabel(sink, usg.Label{Concept: "test.Sink"}); err != nil {
		t.Fatal(err)
	}

	flows, err := solvers.FindTaintFlows(g,
		map[string]bool{"test.Source": true}, map[string]bool{"test.Sink": true},
		map[string]bool{"test.Kind": true}, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 {
		t.Fatalf("expected exactly one flow to the URL sink, got %d", len(flows))
	}
	flow := flows[0]
	if flow.SourceID == vulnFetch {
		t.Fatalf("reported source is the vulnerable fetch's own response (the sink's data); " +
			"the witness crossed handleResponse into the wrong invocation")
	}
	if flow.SourceID != wrapperDo {
		t.Fatalf("reported source = %q, want the wrapper's client.Do (the metadata fetch)", flow.SourceID)
	}
	// and it got there through the metadata invocation, not the vulnerable one
	metadataGet := nodeByCallee(t, g, "s.http.get")
	onPath := false
	for _, id := range flow.Path {
		if id == metadataGet {
			onPath = true
		}
	}
	if !onPath {
		t.Fatalf("witness path does not run through the metadata s.http.get call: %v", flow.Path)
	}
}

func nodeByCallee(t *testing.T, g usg.Store, callee string) string {
	t.Helper()
	ids, err := g.NodesOfType("code.Call")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		n, ok, _ := g.GetNode(id)
		if ok && n.Prop("callee_path") == callee {
			return id
		}
	}
	t.Fatalf("no code.Call with callee_path %q", callee)
	return ""
}
