package solvers

import (
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// effective-permission solver (docs/09 §"can_access"): direct grant, access
// via an assumed role, action wildcard matching, and action mismatch.
func TestFindCanAccess(t *testing.T) {
	s := usg.NewInMemStore()
	// dev -assume-> dbrole -s3:GetObject*-> bucket  (access via an assumed role)
	s.AddNode(usg.Node{ID: "dev", Type: "identity.User"})
	s.AddNode(usg.Node{ID: "dbrole", Type: "identity.Role"})
	s.AddNode(usg.Node{ID: "bucket", Type: "cloud.Bucket"})
	s.AddNode(usg.Node{ID: "secrets", Type: "cloud.SecretStore"})
	s.AddEdge(usg.Edge{Type: "STEP", Src: "dev", Dst: "dbrole", Props: map[string]string{"ability": "sts:AssumeRole"}})
	s.AddEdge(usg.Edge{Type: "STEP", Src: "dbrole", Dst: "bucket", Props: map[string]string{"ability": "s3:GetObject*"}})
	s.AddEdge(usg.Edge{Type: "STEP", Src: "dbrole", Dst: "secrets", Props: map[string]string{"ability": "secretsmanager:GetSecretValue"}})

	// dev can read the bucket via the assumed dbrole; wildcard ability covers it
	paths, err := FindCanAccess(s, []string{"dev"}, []string{"bucket"}, "s3:GetObject")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected dev->bucket via assumed role, got %d", len(paths))
	}
	if via := paths[0].ViaRoles(); len(via) != 1 || via[0] != "dbrole" {
		t.Fatalf("witness should name the assumed role dbrole, got %v", via)
	}
	if v := ValidateResults(paths); len(v) != 0 {
		t.Fatalf("can_access result should conform to the solver contract, got %v", v)
	}

	// action mismatch: dev cannot Delete the bucket (no granting ability)
	if p, _ := FindCanAccess(s, []string{"dev"}, []string{"bucket"}, "s3:DeleteObject"); len(p) != 0 {
		t.Fatalf("s3:DeleteObject is not granted, expected no access, got %d", len(p))
	}

	// exact-ability grant matches its exact action
	if p, _ := FindCanAccess(s, []string{"dbrole"}, []string{"secrets"}, "secretsmanager:GetSecretValue"); len(p) != 1 {
		t.Fatalf("exact ability should grant exact action, got %d", len(p))
	}
}
