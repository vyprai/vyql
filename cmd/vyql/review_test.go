package main

import (
	"os"
	"path/filepath"
	"testing"
)

const authReviewJava = `class User {
  boolean hasPermission(String p) { return true; }
  boolean isAuthenticated() { return true; }
}

class Admin {
  void handle(User user, String id) {
    hasRole("ADMIN");
    deleteUser(id);
  }

  void update(User user) {
    if (!user.isAuthenticated()) {
      return;
    }
    changePassword("new");
  }

  void deleteUser(String id) {}
  void changePassword(String password) {}
  boolean hasRole(String role) { return true; }
}`

const accumuloPermissionReviewJava = `class MasterClientServiceHandler {
  Master master;
  void shutdown(TCredentials c) throws Exception {
    master.security.canPerformSystemActions(c);
    master.setMasterGoalState("CLEAN_STOP");
  }
  void flush(TCredentials c, String tableId, String namespaceId) throws Exception {
    master.security.canFlush(c, tableId, namespaceId);
  }
}`

const authReviewC = `int run_post_create(char *path);
int perform_http_xact(char *messagebuf_data) {
  return run_post_create(messagebuf_data);
}`

func TestCollectReviewItemsAuthCategory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Admin.java"), []byte(authReviewJava), 0o644); err != nil {
		t.Fatal(err)
	}
	applyProfile([]string{dir}, "auto")
	g, _, err := buildGraph([]string{dir})
	if err != nil {
		t.Fatalf("buildGraph: %v", err)
	}
	rows := collectReviewItems(g)
	if !hasReviewConcept(rows, "core.AuthorizationCheck") {
		t.Fatalf("expected AuthorizationCheck in review items, got %#v", rows)
	}
	if !hasReviewConcept(rows, "core.AuthenticationCheck") {
		t.Fatalf("expected AuthenticationCheck in review items, got %#v", rows)
	}
	sensitive := reviewRow(rows, "code.SensitiveOperation")
	if sensitive == nil {
		t.Fatalf("expected SensitiveOperation review target, got %#v", rows)
	}
	if !containsString(sensitive.Expected, "core.AuthorizationCheck") {
		t.Fatalf("SensitiveOperation should explain expected AuthorizationCheck, got %#v", sensitive.Expected)
	}
	if len(sensitive.NearbyChecks) == 0 {
		t.Fatalf("SensitiveOperation should include nearby auth context, got %#v", sensitive)
	}
	required := reviewRow(rows, "code.AuthenticationRequiredOp")
	if required == nil {
		t.Fatalf("expected AuthenticationRequiredOp review target, got %#v", rows)
	}
	if !containsString(required.Expected, "core.AuthenticationCheck") {
		t.Fatalf("AuthenticationRequiredOp should explain expected AuthenticationCheck, got %#v", required.Expected)
	}
}

func TestCollectReviewItemsAccumuloPermissionChecks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "MasterClientServiceHandler.java"), []byte(accumuloPermissionReviewJava), 0o644); err != nil {
		t.Fatal(err)
	}
	applyProfile([]string{dir}, "auto")
	g, _, err := buildGraph([]string{dir})
	if err != nil {
		t.Fatalf("buildGraph: %v", err)
	}
	rows := collectReviewItems(g)
	if !hasReviewCall(rows, "master.security.canPerformSystemActions", "core.AuthorizationCheck") {
		t.Fatalf("expected canPerformSystemActions authorization review item, got %#v", rows)
	}
	if !hasReviewCall(rows, "master.security.canFlush", "core.AuthorizationCheck") {
		t.Fatalf("expected canFlush authorization review item, got %#v", rows)
	}
}

func TestCollectReviewItemsCPostCreate(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "abrt-server.c"), []byte(authReviewC), 0o644); err != nil {
		t.Fatal(err)
	}
	applyProfile([]string{dir}, "auto")
	g, _, err := buildGraph([]string{dir})
	if err != nil {
		t.Fatalf("buildGraph: %v", err)
	}
	sensitive := reviewRow(collectReviewItems(g), "code.SensitiveOperation")
	if sensitive == nil {
		t.Fatal("expected run_post_create to be surfaced as an auth review target")
	}
	if sensitive.Category != "auth" || sensitive.Call != "run_post_create" {
		t.Fatalf("unexpected review item: %#v", sensitive)
	}
}

func hasReviewCall(rows []reviewItem, call, concept string) bool {
	for _, r := range rows {
		if r.Call == call && r.Concept == concept {
			return true
		}
	}
	return false
}

func hasReviewConcept(rows []reviewItem, concept string) bool {
	return reviewRow(rows, concept) != nil
}

func reviewRow(rows []reviewItem, concept string) *reviewItem {
	for i := range rows {
		if rows[i].Concept == concept {
			return &rows[i]
		}
	}
	return nil
}

func containsString(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
