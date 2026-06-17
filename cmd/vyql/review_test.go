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

const startTLSBufferReviewPython = `class SMTP:
    def connection_made(self, transport):
        seen_starttls = self._original_transport is not None
        if self.transport is not None and seen_starttls:
            self._reader._transport = transport
            self._writer._transport = transport
            self.transport = transport
            self.session.ssl = self._tls_protocol._extra
        else:
            super().connection_made(transport)
`

const fixedStartTLSBufferReviewPython = `class SMTP:
    def connection_made(self, transport):
        seen_starttls = self._original_transport is not None
        if self.transport is not None and seen_starttls:
            self._reader._transport = transport
            self._writer._transport = transport
            self.transport = transport
            self._reader._buffer.clear()
            self.session.ssl = self._tls_protocol._extra
        else:
            super().connection_made(transport)
`

const phpBulkUpdateReview = `<?php
trait UpdateTrait {
  protected function updateItem($manager, $item, array $entry) {
    $item = $item->fromArray($entry, true);
    return $item;
  }
}
class CustomerStandard {
  protected function updateItem($manager, $item, array $entry) {
    $view = $this->context()->view();
    $item = $item->fromArray($entry);
    if ($view->access(['super', 'admin'])) {
      $item->setGroups($entry['groups'] ?? []);
    }
    return $item;
  }
}`

const phpAccessPolicyReview = `<?php
return [
  'locale' => [
    'groups' => ['admin', 'super'],
    'site' => [
      'groups' => ['admin', 'super'],
    ],
    'language' => [
      'groups' => ['admin', 'super'],
    ],
    'currency' => [
      'groups' => ['admin', 'super'],
    ],
    'text' => [
      'groups' => ['admin', 'super'],
    ],
  ],
  'catalog' => [
    'site' => [
      'groups' => ['admin', 'super'],
    ],
  ],
  'fixed' => [
    'locale' => [
      'site' => [
        'groups' => ['super'],
      ],
    ],
  ],
];`

const phpWorkflowPolicyReview = `<?php
class Download {
  protected function vulnerable($search, $customerId, $id) {
    $expr = array(
      $search->compare('==', 'order.customerid', $customerId),
      $search->compare('==', 'order.product.attribute.id', $id),
    );
  }

  protected function fixed($search, $customerId, $id) {
    $expr = array(
      $search->compare('>=', 'order.statuspayment', Base::PAY_RECEIVED),
      $search->compare('==', 'order.customerid', $customerId),
      $search->compare('==', 'order.product.attribute.id', $id),
    );
  }
}`

const phpIdorPolicyReview = `<?php
class Review {
  public function vulnerable($ids) {
    $filter = $this->manager->filter()->add(['review.id' => $ids]);
    $this->manager->delete($this->manager->search($filter)->toArray());
  }

  public function fixed($ids) {
    $filter = $this->manager->filter()->add([
      'review.id' => $ids,
      'review.customerid' => $this->context()->user(),
    ]);
    $this->manager->delete($this->manager->search($filter)->toArray());
  }
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

func TestCollectReviewItemsStartTLSBufferAttention(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "smtp.py"), []byte(startTLSBufferReviewPython), 0o644); err != nil {
		t.Fatal(err)
	}
	applyProfile([]string{dir}, "auto")
	g, _, err := buildGraph([]string{dir})
	if err != nil {
		t.Fatalf("buildGraph: %v", err)
	}
	rows := collectReviewItems(g)
	if !hasReviewKind(rows, "request", "attention", "code.ProtocolStateReview") {
		t.Fatalf("expected STARTTLS protocol-state review attention item, got %#v", rows)
	}

	fixed := t.TempDir()
	if err := os.WriteFile(filepath.Join(fixed, "smtp.py"), []byte(fixedStartTLSBufferReviewPython), 0o644); err != nil {
		t.Fatal(err)
	}
	applyProfile([]string{fixed}, "auto")
	g, _, err = buildGraph([]string{fixed})
	if err != nil {
		t.Fatalf("fixed buildGraph: %v", err)
	}
	if hasReviewKind(collectReviewItems(g), "request", "attention", "code.ProtocolStateReview") {
		t.Fatal("fixed STARTTLS buffer clear should suppress protocol-state review item")
	}
}

func TestCollectReviewItemsPhpBulkUpdateAuth(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Customer.php"), []byte(phpBulkUpdateReview), 0o644); err != nil {
		t.Fatal(err)
	}
	applyProfile([]string{dir}, "auto")
	g, _, err := buildGraph([]string{dir})
	if err != nil {
		t.Fatalf("buildGraph: %v", err)
	}
	rows := collectReviewItems(g)
	if !hasReviewCall(rows, "$item.fromArray", "code.SensitiveOperation") {
		t.Fatalf("expected fromArray sensitive-operation review item, got %#v", rows)
	}
	if !hasReviewCall(rows, "$view.access", "core.AuthorizationCheck") {
		t.Fatalf("expected access authorization check review item, got %#v", rows)
	}
}

func TestCollectReviewItemsPhpAccessPolicyConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "resource.php"), []byte(phpAccessPolicyReview), 0o644); err != nil {
		t.Fatal(err)
	}
	applyProfile([]string{dir}, "auto")
	g, _, err := buildGraph([]string{dir})
	if err != nil {
		t.Fatalf("buildGraph: %v", err)
	}
	rows := collectReviewItems(g)
	if got := countReviewConcept(rows, "code.AccessPolicyReview"); got != 3 {
		t.Fatalf("expected three locale subresource access-policy review items, got %d: %#v", got, rows)
	}
	if !hasReviewKind(rows, "auth", "attention", "code.AccessPolicyReview") {
		t.Fatalf("expected auth attention item for access policy config, got %#v", rows)
	}
}

func TestCollectReviewItemsPhpWorkflowPolicyConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Download.php"), []byte(phpWorkflowPolicyReview), 0o644); err != nil {
		t.Fatal(err)
	}
	applyProfile([]string{dir}, "auto")
	g, _, err := buildGraph([]string{dir})
	if err != nil {
		t.Fatalf("buildGraph: %v", err)
	}
	rows := collectReviewItems(g)
	if got := countReviewConcept(rows, "code.WorkflowPolicyReview"); got != 1 {
		t.Fatalf("expected one workflow policy review item, got %d: %#v", got, rows)
	}
	if !hasReviewKind(rows, "auth", "attention", "code.WorkflowPolicyReview") {
		t.Fatalf("expected auth attention item for workflow policy config, got %#v", rows)
	}
}

func TestCollectReviewItemsPhpIdorPolicyConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Review.php"), []byte(phpIdorPolicyReview), 0o644); err != nil {
		t.Fatal(err)
	}
	applyProfile([]string{dir}, "auto")
	g, _, err := buildGraph([]string{dir})
	if err != nil {
		t.Fatalf("buildGraph: %v", err)
	}
	rows := collectReviewItems(g)
	if got := countReviewConcept(rows, "code.IdorPolicyReview"); got != 1 {
		t.Fatalf("expected one IDOR policy review item, got %d: %#v", got, rows)
	}
	if !hasReviewKind(rows, "auth", "attention", "code.IdorPolicyReview") {
		t.Fatalf("expected auth attention item for IDOR policy config, got %#v", rows)
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

func countReviewConcept(rows []reviewItem, concept string) int {
	n := 0
	for _, r := range rows {
		if r.Concept == concept {
			n++
		}
	}
	return n
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
