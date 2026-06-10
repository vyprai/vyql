package engine

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

const publicStorageRule = `
package vypr.cloud;
rule PublicStorageSensitive {
  meta { id: "VYQL-CLD-001", severity: critical }
  match cloud.PublicStorage as s
  where s holds_asset_kind [data.Pii]
}
`

// storageGraph mirrors case_04's storage_graph(): three public PII buckets
// across three clouds plus a private non-PII bucket that must NOT fire.
func storageGraph() usg.Store {
	s := usg.NewInMemStore()
	s.AddNode(usg.Node{ID: "aws.bucket", Type: "cloud.Bucket", Props: map[string]string{"loc": "aws/s3/exports", "acl": "public-read"}})
	s.AddNode(usg.Node{ID: "az.container", Type: "cloud.Bucket", Props: map[string]string{"loc": "azure/blob/exports", "public_access": "container"}})
	s.AddNode(usg.Node{ID: "gcp.bucket", Type: "cloud.Bucket", Props: map[string]string{"loc": "gcp/gcs/exports", "iam_member": "allUsers"}})
	s.AddNode(usg.Node{ID: "aws.private", Type: "cloud.Bucket", Props: map[string]string{"loc": "aws/s3/internal", "acl": "private"}})
	return s
}

// bucketAdapter labels a cloud.Bucket as cloud.PublicStorage (holding PII) when
// the given provider property has a public value — the provider-specific match.
func bucketAdapter(name, prop string, publicValues ...string) adapters.Adapter {
	pub := map[string]bool{}
	for _, v := range publicValues {
		pub[v] = true
	}
	return adapters.Adapter{
		Name: name, Technology: strings.SplitN(name, ".", 2)[0], Specificity: 2, Fidelity: "resolved", Origin: "human",
		Apply: func(s usg.Store) []adapters.Mapping {
			ids, _ := s.NodesOfType("cloud.Bucket")
			var out []adapters.Mapping
			for _, id := range ids {
				n, _, _ := s.GetNode(id)
				if pub[n.Prop(prop)] {
					out = append(out, adapters.Mapping{NodeID: id, Concept: "cloud.PublicStorage",
						Detail: map[string]string{"asset_kinds": "data.Pii"}})
				}
			}
			return out
		},
	}
}

// Mirrors poc/cases/case_04_cloud.py (a) — ONE public-storage rule fires once per
// cloud via three provider adapters (AWS ACL / Azure public_access / GCP IAM
// member); the private bucket never fires; the finding's provenance cites the
// adapter. The concept layer (cloud.PublicStorage) is provider-independent — only
// the technology matching differs.
func TestPublicStorageThreeProviders(t *testing.T) {
	onto := ontology.Seed()
	decls, err := parser.Parse(publicStorageRule)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}

	providers := []struct {
		adapter  adapters.Adapter
		provider string
	}{
		{bucketAdapter("aws.s3", "acl", "public-read", "public-read-write"), "aws"},
		{bucketAdapter("azure.blob", "public_access", "blob", "container"), "azure"},
		{bucketAdapter("gcp.storage", "iam_member", "allUsers", "allAuthenticatedUsers"), "gcp"},
	}
	for _, p := range providers {
		g := storageGraph()
		if _, _, err := adapters.Apply(g, []adapters.Adapter{p.adapter}, nil); err != nil {
			t.Fatal(err)
		}
		fs, err := New(onto, g).Evaluate(compiled[0])
		if err != nil {
			t.Fatalf("%s: eval: %v", p.provider, err)
		}
		if len(fs) != 1 {
			t.Fatalf("%s: expected 1 public-PII bucket finding, got %d", p.provider, len(fs))
		}
		if prov := fs[0].Bindings[0].LabelProvenance; !strings.Contains(prov, p.provider) {
			t.Fatalf("%s: finding provenance should cite the adapter, got %q", p.provider, prov)
		}
	}
}
