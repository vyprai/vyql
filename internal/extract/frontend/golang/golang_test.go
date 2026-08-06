package golang_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	gofrontend "github.com/vyprai/vyql/internal/extract/frontend/golang"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/extract/nir"
)

func TestGoFunctionContextIncludesIndexAndSliceTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mysql.go")
	src := []byte(`package mysql

import "fmt"

func parse(readBuffer []byte) string {
	capabilities := fmt.Sprintf("%08b", uint32(readBuffer[4]))
	return string(capabilities[8]) + string(readBuffer[36:][0])
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := gofrontend.Extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context" {
			continue
		}
		tokens := n.Prop("str_args")
		if strings.Contains(tokens, "lang=go") &&
			strings.Contains(tokens, "function_name:parse") &&
			strings.Contains(tokens, "index:readBuffer:4") &&
			strings.Contains(tokens, "index:capabilities:8") &&
			strings.Contains(tokens, "slice:readBuffer:36:") {
			return
		}
	}
	t.Fatalf("Go function context did not include index/slice tokens; nodes=%#v", nodes)
}

func TestGoFunctionContextIncludesCompositeFieldValueTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mount.go")
	src := []byte(`package clustermesh

type VolumeMount struct {
	Name      string
	MountPath string
}

func generateDeployment() VolumeMount {
	return VolumeMount{
		Name:      "etcd-data-dir",
		MountPath: "etcd-data-dir",
	}
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := gofrontend.Extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context" {
			continue
		}
		tokens := n.Prop("str_args")
		if strings.Contains(tokens, "function_name:generateDeployment") &&
			strings.Contains(tokens, "field:MountPath=etcd-data-dir") &&
			strings.Contains(tokens, "field:Name=etcd-data-dir") {
			return
		}
	}
	t.Fatalf("Go function context did not include composite field-value tokens; nodes=%#v", nodes)
}

func TestGoFunctionContextIncludesAssignmentAndAppendCopyTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "env.go")
	src := []byte(`package cri

type ImageConfig struct {
	Env []string
}

type ContainerConfig struct{}

func (c *ContainerConfig) GetEnvs() []string { return nil }

func vulnerable(config *ContainerConfig, imageConfig *ImageConfig) {
	env := imageConfig.Env
	for _, e := range config.GetEnvs() {
		env = append(env, e)
	}
}

func fixed(config *ContainerConfig, imageConfig *ImageConfig) {
	env := append([]string{}, imageConfig.Env...)
	for _, e := range config.GetEnvs() {
		env = append(env, e)
	}
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := gofrontend.Extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var sawDirect, sawCopy bool
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context" {
			continue
		}
		tokens := n.Prop("str_args")
		if strings.Contains(tokens, "function_name:vulnerable") &&
			strings.Contains(tokens, "assign:env=imageConfig.Env") {
			sawDirect = true
		}
		if strings.Contains(tokens, "function_name:fixed") &&
			strings.Contains(tokens, "append_copy:imageConfig.Env") &&
			!strings.Contains(tokens, "assign:env=imageConfig.Env") {
			sawCopy = true
		}
	}
	if !sawDirect || !sawCopy {
		t.Fatalf("Go function context did not distinguish direct assignment from append copy; sawDirect=%v sawCopy=%v nodes=%#v", sawDirect, sawCopy, nodes)
	}
}

func TestGoSemanticReviewDetectsContainerdCRIImageEnvAlias(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "container_create.go")
	src := []byte(`package server

type Image struct{ Env []string }
type ContainerConfig struct{ Envs []EnvVar }
type EnvVar struct{ Key, Value string }

func (c *ContainerConfig) GetEnvs() []EnvVar { return c.Envs }
func (e EnvVar) GetKey() string { return e.Key }
func (e EnvVar) GetValue() string { return e.Value }

var oci = struct{ WithEnv func([]string) func() }{}

func vulnerable(cfg *ContainerConfig, img *Image) {
	merged := img.Env
	for _, item := range cfg.GetEnvs() {
		merged = append(merged, item.GetKey()+"="+item.GetValue())
	}
	_ = oci.WithEnv(merged)
}

func fixed(cfg *ContainerConfig, img *Image) {
	merged := append([]string{}, img.Env...)
	for _, item := range cfg.GetEnvs() {
		merged = append(merged, item.GetKey()+"="+item.GetValue())
	}
	_ = oci.WithEnv(merged)
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := gofrontend.Extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var count int
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.go.containerd_cri_image_env_alias" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("containerd CRI image env alias observations = %d, want 1; nodes=%#v", count, nodes)
	}
}

func TestGoSemanticReviewDetectsContainerdCRIImageEnvAliasInMethodShape(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "container_create.go")
	src := []byte(`package server

type ImageConfig struct{ Env []string }
type ContainerConfig struct{ Envs []EnvVar }
type EnvVar struct{ Key, Value string }
type SpecOpts func()
type service struct{}

func (c *ContainerConfig) GetEnvs() []EnvVar { return c.Envs }
func (e EnvVar) GetKey() string { return e.Key }
func (e EnvVar) GetValue() string { return e.Value }

var oci = struct{ WithEnv func([]string) SpecOpts }{}

func (s *service) generateContainerSpec(config *ContainerConfig, imageConfig *ImageConfig) error {
	specOpts := []SpecOpts{}
	env := imageConfig.Env
	for _, e := range config.GetEnvs() {
		env = append(env, e.GetKey()+"="+e.GetValue())
	}
	specOpts = append(specOpts, oci.WithEnv(env))
	_ = specOpts
	return nil
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := gofrontend.Extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var count int
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.go.containerd_cri_image_env_alias" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("containerd CRI method-shape observations = %d, want 1; nodes=%#v", count, nodes)
	}
}

func TestGoSemanticReviewDetectsPublicAllUsersRouteMissingAuth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "user.go")
	src := []byte(`package router

type AppRouterGroup struct {
	PublicRouterGroup *RouterGroup
	AuthRouterGroup   *RouterGroup
}
type RouterGroup struct{}
type UserHandler struct{}
type HandlerBundle struct{ UserHandler *UserHandler }

func (g *RouterGroup) GET(path string, handlers ...any) {}
func (h *UserHandler) GetAllUsers() any { return nil }

func vulnerable(groups *AppRouterGroup, h *HandlerBundle) {
	groups.PublicRouterGroup.GET("/allusers", h.UserHandler.GetAllUsers())
}

func fixed(groups *AppRouterGroup, h *HandlerBundle) {
	groups.AuthRouterGroup.GET("/allusers", h.UserHandler.GetAllUsers())
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := gofrontend.Extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var count int
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.go.public_user_list_route_missing_auth" {
			count++
			if !strings.Contains(n.Prop("str_args"), "route:/allusers") ||
				!strings.Contains(n.Prop("str_args"), "handler:h.UserHandler.GetAllUsers") {
				t.Fatalf("public allusers observation has weak evidence tokens: %q", n.Prop("str_args"))
			}
		}
	}
	if count != 1 {
		t.Fatalf("public allusers observations = %d, want 1; nodes=%#v", count, nodes)
	}
}

func TestGoSemanticReviewDetectsPowerShellCommandStringWrapperEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "windows_share.go")
	src := []byte(`package share

import "fmt"

func createLink(remoteShare, mountPoint string) error {
	script := "New-Item -ItemType SymbolicLink $Env:targetPath -Target $Env:sourcePath"
	_, err := win.InvokePowerShellCommand(script,
		fmt.Sprintf("sourcePath=%s", remoteShare),
		fmt.Sprintf("targetPath=%s", mountPoint))
	return err
}

func fixedConstantEnv() error {
	script := "New-Item -ItemType SymbolicLink $Env:targetPath -Target $Env:sourcePath"
	_, err := win.InvokePowerShellCommand(script,
		fmt.Sprintf("sourcePath=%s", "\\server\\share"),
		fmt.Sprintf("targetPath=%s", "c:\\mount"))
	return err
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := gofrontend.Extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var count int
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.go.powershell_command_string_wrapper_env" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("PowerShell command-string wrapper env observations = %d, want 1; nodes=%#v", count, nodes)
	}
}

func TestGoSemanticReviewDetectsOsqueryAllowUnsafePlatformArgs(t *testing.T) {
	dir := t.TempDir()
	vulnPath := filepath.Join(dir, "vuln_osqueryd_windows.go")
	vulnSrc := []byte(`package osqd

func platformArgs() map[string]interface{} {
	return map[string]interface{}{
		"allow_unsafe": true,
	}
}
`)
	if err := os.WriteFile(vulnPath, vulnSrc, 0o600); err != nil {
		t.Fatal(err)
	}
	fixedPath := filepath.Join(dir, "fixed_osqueryd_windows.go")
	fixedSrc := []byte(`package osqd

func platformArgs() map[string]interface{} {
	return nil
}
`)
	if err := os.WriteFile(fixedPath, fixedSrc, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := gofrontend.Extract([]string{vulnPath, fixedPath}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var count int
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.go.osquery_allow_unsafe_platform_args" {
			continue
		}
		count++
		if !strings.Contains(n.Prop("str_args"), "arg:allow_unsafe") ||
			!strings.Contains(n.Prop("str_args"), "component:osqueryd") ||
			strings.Contains(n.Prop("loc"), "fixed_osqueryd_windows.go") {
			t.Fatalf("osquery allow_unsafe observation has weak evidence: loc=%q args=%q", n.Prop("loc"), n.Prop("str_args"))
		}
	}
	if count != 1 {
		t.Fatalf("osquery allow_unsafe platformArgs observations = %d, want 1; nodes=%#v", count, nodes)
	}
}

func TestGoFunctionContextIncludesNonAdjacentCallBeforeTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "commands.go")
	src := []byte(`package http

import "os/exec"

func handler(raw string, d *data) {
	if !d.user.CanExecute(strings.Split(raw, " ")[0]) {
		return
	}
	command, _ := runner.ParseCommand(d.settings, raw)
	exec.Command(command[0], command[1:]...)
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := gofrontend.Extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context" {
			continue
		}
		tokens := n.Prop("str_args")
		if strings.Contains(tokens, "function_name:handler") &&
			strings.Contains(tokens, "call_before:d.user.CanExecute>runner.ParseCommand") &&
			strings.Contains(tokens, "call_before:d.user.CanExecute>exec.Command") {
			return
		}
	}
	t.Fatalf("Go function context did not include non-adjacent call_before tokens; nodes=%#v", nodes)
}

func TestGoModuleContextIncludesTopLevelVarInitializer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorization.go")
	src := []byte(`package server

type RoleID int

const (
	RoleAdmin RoleID = 1
	RoleNetworkManager RoleID = 3
)

var PermissionsByRole = map[RoleID][]string{
	RoleAdmin: {"*"},
	RoleNetworkManager: {
		PermBackup, PermRestore, PermSupportBundle,
	},
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := gofrontend.Extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.module.context" {
			continue
		}
		tokens := n.Prop("str_args")
		if strings.Contains(tokens, "var_name:PermissionsByRole") &&
			strings.Contains(tokens, "RoleNetworkManager:{PermBackup,PermRestore,PermSupportBundle,}") {
			return
		}
	}
	t.Fatalf("Go module context did not include top-level permission map initializer; nodes=%#v", nodes)
}

func TestGoModuleContextDetectsOverbroadRolePermissionGrant(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorization.go")
	src := []byte(`package server

var grants = map[RoleID][]string{
	RoleAdmin: {"*"},
	RoleNetworkManager: {
		PermReadUser, PermBackup, PermRestore,
	},
}

var clean = map[RoleID][]string{
	RoleAdmin: {PermBackup, PermRestore},
	RoleNetworkManager: {PermBackup, PermRestore},
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := gofrontend.Extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var count int
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.go.overbroad_role_permission_grant" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("overbroad role permission observations = %d, want 1; nodes=%#v", count, nodes)
	}
}

func TestGoFunctionContextIncludesIdentifierTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identifiers.go")
	src := []byte(`package repository

func query(cluster string) {
	var queryParams []string
	if ignoredSubresources.Has(cluster) {
		_ = queryParams
	}
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := gofrontend.Extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context" {
			continue
		}
		tokens := n.Prop("str_args")
		if strings.Contains(tokens, "function_name:query") &&
			strings.Contains(tokens, "identifier:queryParams") &&
			strings.Contains(tokens, "identifier:ignoredSubresources") {
			return
		}
	}
	t.Fatalf("Go function context did not include identifier tokens; nodes=%#v", nodes)
}

func TestGoSecurityObservationDetectsCountNonzeroGuard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bounds.go")
	src := []byte(`package bbolt

func guarded(p Page) {
	if p.Count() != 0 {
		use(p)
	}
}

func unguarded(p Page) {
	use(p)
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := gofrontend.Extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var count int
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.go.count_nonzero_guard" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("count nonzero guard observations = %d, want 1; nodes=%#v", count, nodes)
	}
}

func TestGoSecurityObservationDetectsManifestInfoLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.go")
	src := []byte(`package agent

func vulnerable(logger Logger, ctx Context, mp Manifest) {
	logger.Info(ctx, "fetched manifest", slog.F("manifest", mp))
}

func fixed(logger Logger, ctx Context, mp Manifest) {
	logger.Critical(ctx, "fetched manifest", slog.F("manifest", mp))
	logger.Info(ctx, "fetched manifest")
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := gofrontend.Extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var count int
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.go.coder_manifest_info_log" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("coder manifest info log observations = %d, want 1; nodes=%#v", count, nodes)
	}
}

// The Go frontend translates `defer` into nir.Defer and leaves placement to the lowerer.
// Before this existed the statement matched no case in the converter and the deferred call
// vanished from the IR, so `defer mu.Unlock()` looked like a lock that is never released.
func TestGoDeferStatementReachesNIR(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lock.go")
	src := []byte(`package lock

import "sync"

func f(mu *sync.Mutex) {
	mu.Lock()
	defer mu.Unlock()
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := gofrontend.Extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}

	var found []nir.Defer
	for _, m := range prog.Modules {
		for _, s := range m.Body {
			fn, ok := s.(nir.FuncDef)
			if !ok {
				continue
			}
			for _, b := range fn.Body {
				if d, ok := b.(nir.Defer); ok {
					found = append(found, d)
				}
			}
		}
	}
	if len(found) != 1 {
		t.Fatalf("want one nir.Defer in the function body, got %d", len(found))
	}
	// Go defers exactly one call, so the deferred block holds exactly that statement.
	if len(found[0].Body) != 1 {
		t.Fatalf("deferred body = %d statements, want 1", len(found[0].Body))
	}
	stmt, ok := found[0].Body[0].(nir.ExprStmt)
	if !ok {
		t.Fatalf("deferred statement = %T, want nir.ExprStmt", found[0].Body[0])
	}
	call, ok := stmt.Value.(nir.Call)
	if !ok {
		t.Fatalf("deferred call = %T, want nir.Call", stmt.Value)
	}
	if call.Path != "mu.Unlock" {
		t.Errorf("deferred call path = %q, want mu.Unlock", call.Path)
	}
	if !strings.HasSuffix(found[0].Loc, ":7") {
		t.Errorf("nir.Defer loc = %q, want the defer statement's line 7", found[0].Loc)
	}
}
