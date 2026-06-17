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

const accurevReviewJava = `class DescriptorImpl {
  FormValidation doFillCredentialsIdItems(String credentialsId) {
    if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
      return FormValidation.ok();
    }
    return FormValidation.ok();
  }

  FormValidation doTest(String name, String host, int port, String credentialsId) {
    AccurevServer server = new AccurevServer("", name, host);
    server.setCredentialsId(credentialsId);
    if (Login.accurevLoginFromGlobalConfig(server)) {
      return FormValidation.ok("SUCCESS");
    }
    return FormValidation.error("FAILURE");
  }
}`

const activeDirectoryStatusReviewJava = `class ActiveDirectoryStatus {
  ProgressiveRendering startDomainHealthChecks(String domain) {
    ActiveDirectorySecurityRealm realm = Jenkins.getActiveInstance().getSecurityRealm();
    realm.getDescriptor().obtainLDAPServer(domain);
    return new ProgressiveRendering();
  }

  long computeLoginExecutionTime() throws Exception {
    String username = Jenkins.getAuthentication().getName();
    Jenkins.getActiveInstance().getSecurityRealm().loadUserByUsername(username);
    return 1L;
  }

  Object getTarget() {
    Jenkins.get().checkPermission(Jenkins.ADMINISTER);
    return this;
  }
}
class Jenkins {
  static Jenkins get() { return new Jenkins(); }
  static Jenkins getActiveInstance() { return new Jenkins(); }
  static Authentication getAuthentication() { return new Authentication(); }
  static String ADMINISTER;
  ActiveDirectorySecurityRealm getSecurityRealm() { return new ActiveDirectorySecurityRealm(); }
  void checkPermission(String p) {}
}
class Authentication { String getName() { return "u"; } }
class ActiveDirectorySecurityRealm {
  Descriptor getDescriptor() { return new Descriptor(); }
  void loadUserByUsername(String u) {}
}
class Descriptor { void obtainLDAPServer(String domain) {} }
class ProgressiveRendering {}`

const authReviewC = `int run_post_create(char *path);
int perform_http_xact(char *messagebuf_data) {
  return run_post_create(messagebuf_data);
}`

const memoryAttentionC = `struct bar { unsigned long addr; unsigned long size; };
struct dev { struct bar bar[8]; };
int pci_emul_mem_handler(struct dev *pdi, unsigned long addr, int size, long arg2) {
  int bidx = (int) arg2;
  return addr + size <= pdi->bar[bidx].addr + pdi->bar[bidx].size;
}`

const configExposureReviewGo = `package main

type Config struct{}

func handle(c Config) {
  MarshalConfig(&c, false)
}

func MarshalConfig(c *Config, redact bool) []byte { return nil }
`

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

func TestCollectReviewItemsAccurevCredentialTest(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "AccurevSCM.java"), []byte(accurevReviewJava), 0o644); err != nil {
		t.Fatal(err)
	}
	applyProfile([]string{dir}, "auto")
	g, _, err := buildGraph([]string{dir})
	if err != nil {
		t.Fatalf("buildGraph: %v", err)
	}
	rows := collectReviewItems(g)
	if !hasReviewCall(rows, "Jenkins.getInstance.hasPermission", "core.AuthorizationCheck") {
		t.Fatalf("expected Jenkins hasPermission authorization review item, got %#v", rows)
	}
	if !hasReviewCall(rows, "Login.accurevLoginFromGlobalConfig", "code.SensitiveOperation") {
		t.Fatalf("expected AccuRev global-config login review target, got %#v", rows)
	}
}

func TestCollectReviewItemsActiveDirectoryStatus(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ActiveDirectoryStatus.java"), []byte(activeDirectoryStatusReviewJava), 0o644); err != nil {
		t.Fatal(err)
	}
	applyProfile([]string{dir}, "auto")
	g, _, err := buildGraph([]string{dir})
	if err != nil {
		t.Fatalf("buildGraph: %v", err)
	}
	rows := collectReviewItems(g)
	if !hasReviewCall(rows, "realm.getDescriptor.obtainLDAPServer", "code.SensitiveOperation") {
		t.Fatalf("expected LDAP server health lookup review target, got %#v", rows)
	}
	if !hasReviewCall(rows, "Jenkins.getActiveInstance.getSecurityRealm.loadUserByUsername", "code.SensitiveOperation") {
		t.Fatalf("expected user lookup auth review target, got %#v", rows)
	}
	if !hasReviewCall(rows, "Jenkins.get.checkPermission", "core.AuthorizationCheck") {
		t.Fatalf("expected Jenkins checkPermission authorization check, got %#v", rows)
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

func TestCollectReviewItemsMemoryAttention(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "core.c"), []byte(memoryAttentionC), 0o644); err != nil {
		t.Fatal(err)
	}
	applyProfile([]string{dir}, "auto")
	g, _, err := buildGraph([]string{dir})
	if err != nil {
		t.Fatalf("buildGraph: %v", err)
	}
	rows := collectReviewItems(g)
	if !hasReviewKind(rows, "memory", "attention", "code.IndexAccess") {
		t.Fatalf("expected memory attention item for index access, got %#v", rows)
	}
	if !hasReviewKind(rows, "memory", "attention", "code.IntegerSizeArithmetic") {
		t.Fatalf("expected memory attention item for integer/address arithmetic, got %#v", rows)
	}
}

func TestCollectReviewItemsConfigExposureAttention(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.go"), []byte(configExposureReviewGo), 0o644); err != nil {
		t.Fatal(err)
	}
	applyProfile([]string{dir}, "auto")
	g, _, err := buildGraph([]string{dir})
	if err != nil {
		t.Fatalf("buildGraph: %v", err)
	}
	rows := collectReviewItems(g)
	if !hasReviewKind(rows, "secret", "attention", "code.ConfigExposureReview") {
		t.Fatalf("expected secret exposure review attention item, got %#v", rows)
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

func hasReviewKind(rows []reviewItem, category, kind, concept string) bool {
	for _, r := range rows {
		if r.Category == category && r.Kind == kind && r.Concept == concept {
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
