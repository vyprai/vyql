package golang_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	gofrontend "github.com/vyprai/vyql/internal/extract/frontend/golang"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/extract/parsecache"
	"github.com/vyprai/vyql/internal/usg"
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

func TestGoSecurityObservationDetectsDecodeOverwritesPresetFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "user.go")
	src := []byte(`package api

import "encoding/json"

type User struct {
	UserID int
	Email  string
}

func putVulnerable(r io.Reader) error {
	user := User{UserID: 42}
	if err := json.NewDecoder(r).Decode(&user); err != nil {
		return err
	}
	return save(user)
}

func putPresetAfterDecode(r io.Reader) error {
	user := User{}
	if err := json.NewDecoder(r).Decode(&user); err != nil {
		return err
	}
	user.UserID = 42
	return save(user)
}

func putDefaultsOnly(r io.Reader) error {
	cfg := User{Email: "none@example.com"}
	if err := json.NewDecoder(r).Decode(&cfg); err != nil {
		return err
	}
	return save(cfg)
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
	var facts []string
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.go.decode_overwrites_preset_fields" {
			continue
		}
		facts = append(facts, n.Prop("str_args"))
	}
	if len(facts) != 2 {
		t.Fatalf("decode-overwrites-preset observations = %d, want 2 (the preset-before-decode handlers); got %q", len(facts), facts)
	}
	if !strings.Contains(facts[0], "field:UserID") {
		t.Errorf("vulnerable handler fact tokens %q miss field:UserID", facts[0])
	}
	if !strings.Contains(facts[1], "field:Email") {
		t.Errorf("defaults handler fact tokens %q miss field:Email", facts[1])
	}
	for _, f := range facts {
		if strings.Contains(f, "function_name:putPresetAfterDecode") {
			t.Errorf("preset recorded after the decode: %q", f)
		}
	}
}

// The monetr mass-assignment shape (CVE-2026-39901, CWE-915): a bind-style decode
// fills a struct the handler then persists wholesale, and the fix's only change is
// re-establishing, between the decode and the persist, the fields the payload was
// never allowed to set. Whole-object taint cannot see that -- reassigning one field
// leaves the object tainted -- so the fact names the fields restored from a record
// the same body loaded, anchored at the persistence call and carrying the persisted
// expression as its first argument, which is what lets a binding both judge the
// restore set and report the write as the sink.
func TestGoSecurityObservationRecordsDecodeRestoreBeforePersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "transactions.go")
	src := []byte(`package controller

import "encoding/json"

type Transaction struct {
	Name      string
	Source    string
	CreatedAt string
}

func loadTransaction(id string) (*Transaction, error) { return nil, nil }

func putVulnerable(c Ctx) error {
	transaction := Transaction{}
	if err := c.Bind(&transaction); err != nil {
		return err
	}
	existing, err := loadTransaction(transaction.Name)
	if err != nil {
		return err
	}
	transaction.Name = existing.Name
	return c.Update("id", &transaction)
}

func putFixed(c Ctx) error {
	transaction := Transaction{}
	if err := c.Bind(&transaction); err != nil {
		return err
	}
	existing, err := loadTransaction(transaction.Name)
	if err != nil {
		return err
	}
	transaction.Name = existing.Name
	transaction.Source = existing.Source
	transaction.CreatedAt = existing.CreatedAt
	return c.Update("id", &transaction)
}

func restoreBeforeDecode(c Ctx) error {
	transaction := Transaction{}
	existing, _ := loadTransaction("id")
	transaction.Source = existing.Source
	if err := c.Bind(&transaction); err != nil {
		return err
	}
	return c.Update("id", &transaction)
}

func restoreFromLiteral(c Ctx) error {
	transaction := Transaction{}
	if err := c.Bind(&transaction); err != nil {
		return err
	}
	transaction.Source = "ach"
	return c.Update("id", &transaction)
}

func noPersistence(c Ctx) error {
	transaction := Transaction{}
	if err := c.Bind(&transaction); err != nil {
		return err
	}
	existing, _ := loadTransaction("id")
	transaction.Source = existing.Source
	return nil
}

func stdlibUnmarshal(body []byte) error {
	transaction := Transaction{}
	if err := json.Unmarshal(body, &transaction); err != nil {
		return err
	}
	existing, _ := loadTransaction("id")
	transaction.Source = existing.Source
	return saveTransaction(&transaction)
}

func saveTransaction(transaction *Transaction) error { return nil }
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
	var facts []string
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.go.decode_restore_before_persist" {
			continue
		}
		facts = append(facts, n.Prop("str_args"))
	}
	factFor := func(fn, field string) string {
		t.Helper()
		for _, f := range facts {
			if strings.Contains(f, "function_name:"+fn+"\x00") && strings.Contains(f, "field:"+field+"\x00") {
				return f
			}
		}
		t.Fatalf("no decode-restore fact for %s field %s among %q", fn, field, facts)
		return ""
	}
	// One fact per field of the declared struct (three fields here), per decode-then-persist
	// handler; none for noPersistence, which never persists.
	if len(facts) != 15 {
		t.Fatalf("decode-restore observations = %d, want 15 (one per field of Transaction per decode-then-persist handler); got %q", len(facts), facts)
	}
	if f := factFor("putVulnerable", "Name"); !strings.Contains(f, "restored:1") || !strings.Contains(f, "record:existing") ||
		!strings.Contains(f, "decode:Bind") || !strings.Contains(f, "callee:Update") {
		t.Errorf("vulnerable handler Name fact %q: want restored:1 + record:existing + decode:Bind + callee:Update", f)
	}
	if f := factFor("putVulnerable", "Source"); !strings.Contains(f, "restored:0") || strings.Contains(f, "record:") {
		t.Errorf("vulnerable handler Source fact %q: want restored:0 and no record (the handler never re-established it)", f)
	}
	if f := factFor("putFixed", "Source"); !strings.Contains(f, "restored:1") || !strings.Contains(f, "record:existing") {
		t.Errorf("fixed handler Source fact %q: want restored:1 + record:existing", f)
	}
	if f := factFor("putFixed", "CreatedAt"); !strings.Contains(f, "restored:1") {
		t.Errorf("fixed handler CreatedAt fact %q: want restored:1", f)
	}
	for _, field := range []string{"Name", "Source", "CreatedAt"} {
		if f := factFor("restoreBeforeDecode", field); strings.Contains(f, "restored:1") {
			t.Errorf("restore recorded even though it ran before the decode: %q", f)
		}
	}
	if f := factFor("restoreFromLiteral", "Source"); strings.Contains(f, "restored:1") || strings.Contains(f, "record:") {
		t.Errorf("literal assignment recorded as a restore from a loaded record: %q", f)
	}
	if f := factFor("stdlibUnmarshal", "Source"); !strings.Contains(f, "restored:1") || !strings.Contains(f, "decode:Unmarshal") || !strings.Contains(f, "callee:saveTransaction") {
		t.Errorf("stdlib unmarshal fact %q: want restored:1 + decode:Unmarshal + callee:saveTransaction", f)
	}
}

// The fact must carry the persisted object's taint, not just describe it: the
// bind call's whole-object taint has to reach the fact node itself, so a binding
// that reports the fact as a sink judges the same flow the vulnerable handler
// really has (code.HttpInput at Bind args[0] -> the bound object -> the write).
func TestGoDecodeRestoreFactCarriesTheBoundObject(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "put.go")
	src := []byte(`package controller

type Transaction struct {
	Name string
}

func put(c Ctx) error {
	transaction := Transaction{}
	if err := c.Bind(&transaction); err != nil {
		return err
	}
	return c.Update("id", &transaction)
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
	fact := goFindNode(t, g, "code.Call", map[string]string{"callee_path": "analysis.go.decode_restore_before_persist"})
	// The Bind statement's right-hand side is converted twice (the out-parameter join
	// re-evaluates it), so the source concept a binding labels at Bind args[0] lands on
	// every copy; the taint is live if ANY of them reaches the fact.
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	reached := false
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "c.Bind" {
			continue
		}
		seeds := []string{n.ID}
		if arg0 := n.Prop("arg0"); arg0 != "" {
			seeds = append(seeds, arg0)
		}
		for _, seed := range seeds {
			reachable, err := usg.BFS(g, seed, "FLOWS", 40)
			if err != nil {
				t.Fatal(err)
			}
			if reachable[fact] {
				reached = true
			}
		}
	}
	if !reached {
		t.Fatalf("the bound object's taint (joined at the Bind call) does not reach the decode-restore fact node")
	}
}

// The engine gap rank 2748 is blocked on, verbatim: "reassigning one field leaves the
// whole struct tainted and the fixed handler reports identically to the vulnerable one."
// A field-aware fact has to break that symmetry -- the same protected field's fact is
// tainted on the handler that never re-established it and clean on the handler that
// restored it from a loaded record, so a binding judging taint at the per-field facts
// separates two revisions whose whole-object sink is indistinguishable.
func TestGoDecodeFieldFactsSeparateRestoredFromClientControlled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "put.go")
	src := []byte(`package controller

type Transaction struct {
	Name      string
	Source    string
	CreatedAt string
}

func loadTransaction(id string) (*Transaction, error) { return nil, nil }

func putVulnerable(c Ctx) error {
	transaction := Transaction{}
	if err := c.Bind(&transaction); err != nil {
		return err
	}
	existing, err := loadTransaction(transaction.Name)
	if err != nil {
		return err
	}
	transaction.Name = existing.Name
	return c.Update("id", &transaction)
}

func putFixed(c Ctx) error {
	transaction := Transaction{}
	if err := c.Bind(&transaction); err != nil {
		return err
	}
	existing, err := loadTransaction(transaction.Name)
	if err != nil {
		return err
	}
	transaction.Name = existing.Name
	transaction.Source = existing.Source
	transaction.CreatedAt = existing.CreatedAt
	return c.Update("id", &transaction)
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
	// The bind taint's seeds: every Bind call node and its bound-object argument.
	var seeds []string
	facts := map[string]string{} // "function\x00field" -> fact node ID
	for _, n := range nodes {
		if n.Type != "code.Call" {
			continue
		}
		switch n.Prop("callee_path") {
		case "c.Bind":
			seeds = append(seeds, n.ID)
			if arg0 := n.Prop("arg0"); arg0 != "" {
				seeds = append(seeds, arg0)
			}
		case "analysis.go.decode_restore_before_persist":
			args := n.Prop("str_args")
			fn, field := "", ""
			for _, tok := range strings.Split(args, "\x00") {
				if strings.HasPrefix(tok, "function_name:") {
					fn = strings.TrimPrefix(tok, "function_name:")
				}
				if strings.HasPrefix(tok, "field:") {
					field = strings.TrimPrefix(tok, "field:")
				}
			}
			if fn != "" && field != "" {
				facts[fn+"\x00"+field] = n.ID
			}
		}
	}
	if len(facts) != 6 {
		t.Fatalf("decode-restore facts = %d, want 6 (Source, CreatedAt and Name for each handler); got %v", len(facts), facts)
	}
	reachable := map[string]bool{}
	for _, seed := range seeds {
		set, err := usg.BFS(g, seed, "FLOWS", 40)
		if err != nil {
			t.Fatal(err)
		}
		for id := range set {
			reachable[id] = true
		}
	}
	for fn, want := range map[string]bool{"putVulnerable": true, "putFixed": false} {
		fact := facts[fn+"\x00Source"]
		if got := reachable[fact]; got != want {
			t.Errorf("%s: bind taint reaches the Source fact = %v, want %v -- the restore %s the field's client control",
				fn, got, want, map[bool]string{true: "did not kill", false: "killed"}[want])
		}
	}
}

// The decode destination is a pointer, and Go handlers spell that pointer two
// more ways than the address operator: `v := new(T)` and `v := &T{}`, both then
// bound bare (`Bind(v)`, the spelling echo's own documentation uses). The taint
// side already joins those -- callOutParams takes every plain identifier a
// bind verb receives -- so the fact has to take them too, or the pointer-spelt
// handler carries the bind taint to its write with no per-field facts judging
// it and the two revisions of it are again indistinguishable.
func TestGoDecodeRestoreFactTracksPointerDeclaredBindTargets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "put.go")
	src := []byte(`package controller

type Transaction struct {
	Name      string
	Source    string
	CreatedAt string
}

func loadTransaction(id string) (*Transaction, error) { return nil, nil }

func putNewVulnerable(c Ctx) error {
	transaction := new(Transaction)
	if err := c.Bind(transaction); err != nil {
		return err
	}
	existing, err := loadTransaction(transaction.Name)
	if err != nil {
		return err
	}
	transaction.Name = existing.Name
	return c.Update("id", transaction)
}

func putNewFixed(c Ctx) error {
	transaction := new(Transaction)
	if err := c.Bind(transaction); err != nil {
		return err
	}
	existing, err := loadTransaction(transaction.Name)
	if err != nil {
		return err
	}
	transaction.Name = existing.Name
	transaction.Source = existing.Source
	transaction.CreatedAt = existing.CreatedAt
	return c.Update("id", transaction)
}

func putPtrLiteral(c Ctx) error {
	transaction := &Transaction{}
	if err := c.Bind(transaction); err != nil {
		return err
	}
	return c.Update("id", transaction)
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
	var facts []string
	var factIDs []string
	seeds := []string{}
	for _, n := range nodes {
		if n.Type != "code.Call" {
			continue
		}
		switch n.Prop("callee_path") {
		case "c.Bind":
			seeds = append(seeds, n.ID)
			if arg0 := n.Prop("arg0"); arg0 != "" {
				seeds = append(seeds, arg0)
			}
		case "analysis.go.decode_restore_before_persist":
			facts = append(facts, n.Prop("str_args"))
			factIDs = append(factIDs, n.ID)
		}
	}
	// Three fields per handler for each of the three pointer spellings.
	if len(facts) != 9 {
		t.Fatalf("decode-restore facts = %d, want 9 (one per field of Transaction per pointer-spelt handler); got %q", len(facts), facts)
	}
	factFor := func(fn, field string) string {
		t.Helper()
		for _, f := range facts {
			if strings.Contains(f, "function_name:"+fn+"\x00") && strings.Contains(f, "field:"+field+"\x00") {
				return f
			}
		}
		t.Fatalf("no decode-restore fact for %s field %s among %q", fn, field, facts)
		return ""
	}
	if f := factFor("putNewVulnerable", "Source"); !strings.Contains(f, "restored:0") || strings.Contains(f, "record:") {
		t.Errorf("new-spelt vulnerable handler Source fact %q: want restored:0 and no record", f)
	}
	if f := factFor("putNewFixed", "Source"); !strings.Contains(f, "restored:1") || !strings.Contains(f, "record:existing") ||
		!strings.Contains(f, "decode:Bind") || !strings.Contains(f, "callee:Update") {
		t.Errorf("new-spelt fixed handler Source fact %q: want restored:1 + record:existing + decode:Bind + callee:Update", f)
	}
	if f := factFor("putPtrLiteral", "Name"); !strings.Contains(f, "restored:0") {
		t.Errorf("pointer-literal handler Name fact %q: want restored:0", f)
	}
	// The field-level judgement the gap is blocked on, on the new(T) spelling: the
	// same protected field's fact is tainted on the handler that never re-established
	// it and clean on the handler that restored it from the loaded record.
	reachable := map[string]bool{}
	for _, seed := range seeds {
		set, err := usg.BFS(g, seed, "FLOWS", 40)
		if err != nil {
			t.Fatal(err)
		}
		for id := range set {
			reachable[id] = true
		}
	}
	factNode := func(fn, field string) string {
		t.Helper()
		for i, f := range facts {
			if strings.Contains(f, "function_name:"+fn+"\x00") && strings.Contains(f, "field:"+field+"\x00") {
				return factIDs[i]
			}
		}
		t.Fatalf("no fact node for %s field %s", fn, field)
		return ""
	}
	for fn, want := range map[string]bool{"putNewVulnerable": true, "putNewFixed": false} {
		if got := reachable[factNode(fn, "Source")]; got != want {
			t.Errorf("%s: bind taint reaches the Source fact = %v, want %v", fn, got, want)
		}
	}
}

func TestGoSecurityObservationDetectsUnboundedAppendAccumulation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decode.go")
	src := []byte(`package decode

import "io"

func fireVulnerable(r io.Reader) ([]byte, error) {
	buf := make([]byte, 128)
	dst := make([]byte, 0, 1024)
	for {
		b, err := io.ReadByte(r)
		if err != nil {
			return dst, nil
		}
		n := readRun(r, buf, int(b))
		dst = append(dst, buf[:n]...)
	}
}

func guardOrdering(r io.Reader, lim int) ([]byte, error) {
	dst := make([]byte, 0, 1024)
	for {
		dst = append(dst, readByte(r))
		if len(dst) > lim {
			return nil, errTooLarge
		}
	}
}

func guardEquality(r io.Reader, n int) ([]byte, error) {
	dst := make([]byte, 0, 1024)
	for {
		dst = append(dst, readByte(r))
		if len(dst) == n {
			return dst, nil
		}
	}
}

func guardCapacity(r io.Reader, max int) ([]byte, error) {
	dst := make([]byte, 0, 1024)
	for {
		dst = append(dst, readByte(r))
		if cap(dst) > max {
			return nil, errTooLarge
		}
	}
}

func guardAfterLoop(r io.Reader, lim int) ([]byte, error) {
	dst := make([]byte, 0, 1024)
	for {
		dst = append(dst, readByte(r))
		if done(r) {
			break
		}
	}
	if len(dst) > lim {
		return nil, errTooLarge
	}
	return dst, nil
}

func guardLabeledBreak(r io.Reader, lim int) ([]byte, error) {
	dst := make([]byte, 0, 1024)
outer:
	for {
		dst = append(dst, readByte(r))
		if len(dst) > lim {
			break outer
		}
	}
	return dst, nil
}

func guardConvertedLen(r io.Reader, lim int64) ([]byte, error) {
	dst := make([]byte, 0, 1024)
	for {
		dst = append(dst, readByte(r))
		if int64(len(dst)) > lim {
			return nil, errTooLarge
		}
	}
}

func emptinessCheckOnly(r io.Reader) ([]byte, error) {
	dst := make([]byte, 0, 1024)
	for {
		dst = append(dst, readByte(r))
		if len(dst) > 0 {
			_ = dst
		}
	}
}

func rangeLoop(data []byte) []byte {
	dst := make([]byte, 0, 1024)
	for _, b := range data {
		dst = append(dst, b)
	}
	return dst
}

func outerWithClosure(r io.Reader) {
	worker := func() {
		dst := make([]byte, 0, 1024)
		for {
			dst = append(dst, readByte(r))
		}
	}
	go worker()
}

func perIterationShort(data [][]byte) {
	for {
		fresh1 := []byte{}
		for _, b := range readBatch(data) {
			fresh1 = append(fresh1, b)
		}
		var fresh2 []byte
		for _, b := range readBatch(data) {
			fresh2 = append(fresh2, b)
		}
		fresh3 := []byte{}
		for _, b := range readBatch(data) {
			fresh3 = append(fresh3, b)
		}
		fresh3 = nil
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
	var facts []string
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.go.unbounded_append_accumulation" {
			continue
		}
		facts = append(facts, n.Prop("str_args"))
	}
	var fire, emptiness, closure int
	for _, f := range facts {
		switch {
		case strings.Contains(f, "function_name:fireVulnerable"):
			fire++
			if !strings.Contains(f, "var:dst") || !strings.Contains(f, "loop:no_exit_condition") {
				t.Errorf("fire-shape fact tokens %q miss var:dst or loop:no_exit_condition", f)
			}
		case strings.Contains(f, "function_name:emptinessCheckOnly"):
			emptiness++
		case strings.Contains(f, "function_name:outerWithClosure"):
			t.Errorf("closure's loop attributed to the enclosing function: %q", f)
		default:
			closure++
		}
	}
	if fire != 1 {
		t.Errorf("fire-shape facts = %d, want 1; all facts %q", fire, facts)
	}
	if emptiness != 1 {
		t.Errorf("emptiness-check-only facts = %d, want 1 (a len(x) > 0 check is not a bound); all facts %q", emptiness, facts)
	}
	if len(facts) != 3 {
		t.Errorf("total facts = %d, want 3 (fire shape, emptiness-check-only, and the hoisted closure's own); got %q", len(facts), facts)
	}
	if closure != 1 {
		t.Errorf("hoisted-closure facts = %d, want 1 (the closure's own pass); got %q", closure, facts)
	}
}

// TestGoMapLiteralKeepsItsLiteralKey covers the composite-literal shape that
// carries taint in the OWASP Go port. A struct literal keys on a field name,
// which is a path; a map keys on a value, so the key is a literal and the path
// of it is empty. An element that keeps no key is lowered under its position, so
// a read by the real key finds an empty slot and reads as clean -- which loses
// the flow silently rather than falling back to the whole container.
func TestGoMapLiteralKeepsItsLiteralKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "m.go")
	src := []byte("package m\n\nfunc f(payload string) string {\n\treturn map[string]string{\"v\": payload}[\"v\"]\n}\n")
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := gofrontend.Extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}

	var pairs []nir.Pair
	var walk func(nir.Expr)
	walk = func(e nir.Expr) {
		switch v := e.(type) {
		case nir.Seq:
			for _, p := range v.Parts {
				walk(p)
			}
		case nir.Pair:
			pairs = append(pairs, v)
			walk(v.Value)
		case nir.Index:
			walk(v.Base)
			walk(v.Key)
		case nir.Thru:
			walk(v.Inner)
		}
	}
	for _, m := range prog.Modules {
		for _, s := range m.Body {
			fn, ok := s.(nir.FuncDef)
			if !ok {
				continue
			}
			for _, b := range fn.Body {
				if r, ok := b.(nir.Return); ok {
					walk(r.Value)
				}
			}
		}
	}

	if len(pairs) != 1 {
		t.Fatalf("want one nir.Pair for the map element, got %d", len(pairs))
	}
	// Unquoted, because that is what a subscript's key resolves to.
	if pairs[0].Key != "v" {
		t.Errorf("map element key = %q, want %q", pairs[0].Key, "v")
	}
}

// A Go method call whose receiver is the RESULT of another call, dispatched through the
// service-registry indirection every Go web application writes:
//
//	MyService.ZeroTier().ZeroTierJoinNetwork(networkId)
//
// Both hops go through an interface, and the route handler carries the same short name as
// the service method it calls, so no unique-short-name fallback can carry the dispatch —
// only the receiver types can. CasaOS/CVE-2022-24193 is this shape verbatim.
func TestGoCallResultReceiverDispatchesThroughInterfaceImplementation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zerotier.go")
	src := []byte(`package casaos

import "os/exec"

func OnlyExec(cmdStr string) {
	cmd := exec.Command("/bin/bash", "-c", cmdStr)
	_ = cmd
}

type ZeroTierService interface {
	ZeroTierJoinNetwork(networkId string)
}

type zerotierStruct struct {
}

func (c *zerotierStruct) ZeroTierJoinNetwork(networkId string) {
	OnlyExec("zerotier-cli join " + networkId)
}

type Repository interface {
	ZeroTier() ZeroTierService
}

type store struct {
}

func (c *store) ZeroTier() ZeroTierService { return &zerotierStruct{} }

var MyService Repository

func ZeroTierJoinNetwork(networkId string) {
	MyService.ZeroTier().ZeroTierJoinNetwork(networkId)
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
	// The handler and the method are two declarations, so they are two signature nodes.
	// Keyed by short name alone they are one — the method's parameter IS the handler's, and
	// the sink looks reachable from a handler that never calls it.
	handlerParam := goFindNode(t, g, "code.Param", map[string]string{"name": "networkId", "loc": "zerotier.go:32"})
	methodParam := goFindNode(t, g, "code.Param", map[string]string{"name": "networkId", "loc": "zerotier.go:17"})
	if handlerParam == methodParam {
		t.Fatalf("the route handler and the method it calls share one parameter node: %s", handlerParam)
	}
	// the command string of `exec.Command("/bin/bash", "-c", cmdStr)`, by argument position.
	execCall, ok, err := g.GetNode(goFindNode(t, g, "code.Call", map[string]string{"loc": "zerotier.go:6", "lit0": "/bin/bash"}))
	if err != nil || !ok {
		t.Fatalf("exec.Command call node: ok=%v err=%v", ok, err)
	}
	sinkArg := execCall.Prop("arg2")
	if sinkArg == "" {
		t.Fatalf("exec.Command call has no third argument node: %#v", execCall)
	}
	reachable, err := usg.BFS(g, handlerParam, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[methodParam] {
		t.Fatalf("handler parameter did not reach the implementation's own parameter: the call-result receiver dispatched to nothing")
	}
	if !reachable[sinkArg] {
		t.Fatalf("handler parameter did not reach the exec.Command argument through the interface method")
	}
}

// The same dispatch across PACKAGES, which is how a Go application actually writes it:
// the route package calls `service.MyService.ZeroTier().ZeroTierJoinNetwork(id)`, where
// `MyService` is the service package's own variable and everything it dispatches to is
// declared there. CasaOS/CVE-2022-24193 is this file layout.
func TestGoQualifiedRegistryVariableDispatchesAcrossPackages(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module casaos\n\ngo 1.21\n")
	write("service/service.go", `package service

var MyService Repository

type Repository interface {
	ZeroTier() ZeroTierService
}

type store struct {
}

func (c *store) ZeroTier() ZeroTierService { return &zerotierStruct{} }
`)
	write("service/zerotier.go", `package service

import "os/exec"

type ZeroTierService interface {
	ZeroTierJoinNetwork(networkId string)
}

type zerotierStruct struct {
}

func (c *zerotierStruct) ZeroTierJoinNetwork(networkId string) {
	cmd := exec.Command("/bin/bash", "-c", "zerotier-cli join "+networkId)
	_ = cmd
}
`)
	write("route/zerotier.go", `package route

import "casaos/service"

func JoinRoute(networkId string) {
	service.MyService.ZeroTier().ZeroTierJoinNetwork(networkId)
}
`)
	prog, err := gofrontend.ExtractDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	routeParam := goFindNode(t, g, "code.Param", map[string]string{"name": "networkId", "loc": "route/zerotier.go:5"})
	execCall, ok, err := g.GetNode(goFindNode(t, g, "code.Call", map[string]string{"loc": "service/zerotier.go:13", "lit0": "/bin/bash"}))
	if err != nil || !ok {
		t.Fatalf("exec.Command call node: ok=%v err=%v", ok, err)
	}
	sinkArg := execCall.Prop("arg2")
	if sinkArg == "" {
		t.Fatalf("exec.Command call has no third argument node: %#v", execCall)
	}
	reachable, err := usg.BFS(g, routeParam, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[sinkArg] {
		t.Fatalf("the route parameter did not reach the shell argument through the service registry")
	}
}

// The monetr layout (CVE-2026-39901): the interface names its implementation
// nowhere, the implementation's methods are spread across the package's files,
// and the handler receives the interface through a dotted type -- either as a
// parameter (`repo repository.Repository`) or as the declared result of its own
// helper (`repo := c.mustGetAuthenticatedRepository()`). A call like
// repo.UpdateTransaction(...) then resolves to nothing and the taint stops at
// the controller. Interface satisfaction has to be judged against the whole
// package's method set, and a dotted declared type has to resolve through the
// import that spells it, for the handler to reach the implementation body.
func TestGoInterfaceReceiverDispatchesToSpreadImplementation(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module monetr\n\ngo 1.21\n")
	write("server/repository/repository.go", `package repository

type BaseRepository interface {
	UpdateTransaction(id string, transaction *Transaction) error
}

type Repository interface {
	BaseRepository
	UserId() string
}

type Transaction struct {
	Name string
}
`)
	write("server/repository/user.go", `package repository

type repositoryBase struct{}

func (r *repositoryBase) UserId() string { return "user" }
`)
	write("server/repository/transaction.go", `package repository

func (r *repositoryBase) UpdateTransaction(id string, transaction *Transaction) error {
	return traceSink(transaction)
}

func traceSink(transaction *Transaction) *Transaction {
	return transaction
}
`)
	write("server/controller/controller.go", `package controller

import "monetr/server/repository"

type Controller struct{}

func (c *Controller) mustGetAuthenticatedRepository() repository.Repository {
	return nil
}

func (c *Controller) putTransactions(payload string) error {
	transaction := repository.Transaction{Name: payload}
	repo := c.mustGetAuthenticatedRepository()
	return repo.UpdateTransaction("id", &transaction)
}
`)
	write("server/controller/param.go", `package controller

import "monetr/server/repository"

func putViaParam(repo repository.Repository, body string) error {
	transaction := repository.Transaction{Name: body}
	return repo.UpdateTransaction("id", &transaction)
}
`)
	prog, err := gofrontend.ExtractDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	traceSink, ok, err := g.GetNode(goFindNode(t, g, "code.Call", map[string]string{"callee_path": "traceSink"}))
	if err != nil || !ok {
		t.Fatalf("traceSink call node: ok=%v err=%v", ok, err)
	}
	sinkArg := traceSink.Prop("arg0")
	if sinkArg == "" {
		t.Fatalf("traceSink call has no first argument node: %#v", traceSink)
	}
	for _, seed := range []struct{ name, via string }{
		{"payload", "the constructor-returned repository"},
		{"body", "the dotted parameter type"},
	} {
		reachable, err := usg.BFS(g, goFindNode(t, g, "code.Param", map[string]string{"name": seed.name}), "FLOWS", 40)
		if err != nil {
			t.Fatal(err)
		}
		if !reachable[sinkArg] {
			t.Fatalf("handler parameter %s did not reach the repository implementation through %s", seed.name, seed.via)
		}
	}
}

// The explicit-list entry point the CLI dispatcher uses must see the same
// package-wide interface satisfaction the directory walk does, however the
// caller ordered the files: satisfaction is judged against the whole package's
// method set, and a type's methods sit in whichever files of the package they
// sit in. The list below interleaves the two packages so that converting in the
// caller's order would split each package into single-file groups -- user.go
// alone loses UpdateTransaction, transaction.go alone loses UserId, and no
// Base edge to Repository would exist for either handler's dispatch.
func TestGoExtractGroupsAnExplicitFileListByPackage(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module monetr\n\ngo 1.21\n")
	write("server/repository/repository.go", `package repository

type BaseRepository interface {
	UpdateTransaction(id string, transaction *Transaction) error
}

type Repository interface {
	BaseRepository
	UserId() string
}

type Transaction struct {
	Name string
}
`)
	write("server/repository/user.go", `package repository

type repositoryBase struct{}

func (r *repositoryBase) UserId() string { return "user" }
`)
	write("server/repository/transaction.go", `package repository

func (r *repositoryBase) UpdateTransaction(id string, transaction *Transaction) error {
	return traceSink(transaction)
}

func traceSink(transaction *Transaction) *Transaction {
	return transaction
}
`)
	write("server/controller/controller.go", `package controller

import "monetr/server/repository"

type Controller struct{}

func (c *Controller) mustGetAuthenticatedRepository() repository.Repository {
	return nil
}

func (c *Controller) putTransactions(payload string) error {
	transaction := repository.Transaction{Name: payload}
	repo := c.mustGetAuthenticatedRepository()
	return repo.UpdateTransaction("id", &transaction)
}
`)
	write("server/controller/param.go", `package controller

import "monetr/server/repository"

func putViaParam(repo repository.Repository, body string) error {
	transaction := repository.Transaction{Name: body}
	return repo.UpdateTransaction("id", &transaction)
}
`)
	// Interleaved on purpose: without grouping by directory, each package's
	// files convert in separate groups and neither group holds the whole
	// method set satisfaction needs.
	files := []string{
		filepath.Join(dir, "server/repository/user.go"),
		filepath.Join(dir, "server/controller/controller.go"),
		filepath.Join(dir, "server/repository/transaction.go"),
		filepath.Join(dir, "server/controller/param.go"),
		filepath.Join(dir, "server/repository/repository.go"),
	}
	prog, err := gofrontend.Extract(files, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	traceSink, ok, err := g.GetNode(goFindNode(t, g, "code.Call", map[string]string{"callee_path": "traceSink"}))
	if err != nil || !ok {
		t.Fatalf("traceSink call node: ok=%v err=%v", ok, err)
	}
	sinkArg := traceSink.Prop("arg0")
	if sinkArg == "" {
		t.Fatalf("traceSink call has no first argument node: %#v", traceSink)
	}
	for _, seed := range []struct{ name, via string }{
		{"payload", "the constructor-returned repository"},
		{"body", "the dotted parameter type"},
	} {
		reachable, err := usg.BFS(g, goFindNode(t, g, "code.Param", map[string]string{"name": seed.name}), "FLOWS", 40)
		if err != nil {
			t.Fatal(err)
		}
		if !reachable[sinkArg] {
			t.Fatalf("handler parameter %s did not reach the repository implementation through %s when the explicit file list interleaves the packages", seed.name, seed.via)
		}
	}
}

func goFindNode(t *testing.T, g usg.Store, typ string, props map[string]string) string {
	t.Helper()
	ids, err := g.NodesOfType(typ)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, id := range ids {
		n, ok, err := g.GetNode(id)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			continue
		}
		match := true
		for k, v := range props {
			if n.Prop(k) != v {
				match = false
				break
			}
		}
		if match {
			found = append(found, id)
		}
	}
	if len(found) == 0 {
		t.Fatalf("no %s node with %v", typ, props)
	}
	return found[0]
}

// goFieldFlowProgram is the shape a Go library uses to build a record in pieces: one function
// stores a value into a field of the *T it is handed, and a METHOD on T reads that field back
// and hands it to a command. Nothing aliases the two — the setter's parameter and the method's
// receiver are the same object only at run time, and the caller that makes them so is written
// last. `Detail` is a sibling field nothing writes, and Other.Spec is the same field name on a
// different type; neither may pick the value up.
const goFieldFlowProgram = `package fw

import "os/exec"

type Rule struct {
	Spec   string
	Detail string
}

type Other struct {
	Spec string
}

func setSpec(r *Rule, spec string) {
	r.Spec = spec
}

func (r *Rule) Apply() {
	exec.Command("/bin/sh", "-c", r.Spec)
}

func (r *Rule) Describe() {
	exec.Command("/bin/sh", "-c", r.Detail)
}

func (o *Other) Apply() {
	exec.Command("/bin/sh", "-c", o.Spec)
}

func Handle(input string) {
	r := &Rule{}
	setSpec(r, input)
	r.Apply()
}
`

// A field stored through a pointer-to-struct parameter is read back by a method on that type.
// The two ends only ever meet through the struct field: there is no call from the setter to
// the method and no expression either can see the other through, so a value that reaches the
// store reaches the sink or it dead-ends at the store.
func TestGoStructFieldCarriesTaintFromASetterIntoAMethodThatReadsIt(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fw.go"), []byte(goFieldFlowProgram), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := gofrontend.ExtractDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	reachable, err := usg.BFS(g, goFindNode(t, g, "code.Param", map[string]string{"name": "input"}), "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[goCommandArg(t, g, "fw.go:19")] {
		t.Fatal("the stored field did not reach the method that reads it")
	}
	if reachable[goCommandArg(t, g, "fw.go:23")] {
		t.Fatal("a sibling field nothing wrote picked the value up")
	}
	if reachable[goCommandArg(t, g, "fw.go:27")] {
		t.Fatal("the same field name on a different struct type picked the value up")
	}
}

// goCommandArg returns the node holding exec.Command's command argument at loc.
func goCommandArg(t *testing.T, g usg.Store, loc string) string {
	t.Helper()
	call, ok, err := g.GetNode(goFindNode(t, g, "code.Call", map[string]string{"loc": loc, "lit0": "/bin/sh"}))
	if err != nil || !ok {
		t.Fatalf("exec.Command node at %s: ok=%v err=%v", loc, ok, err)
	}
	arg := call.Prop("arg2")
	if arg == "" {
		t.Fatalf("exec.Command at %s has no third argument node: %#v", loc, call)
	}
	return arg
}

// A func literal bound to a local, and one invoked where it is written, are calls into a
// body this file contains. Both are the shape nektos/act's artifact server (CVE-2023-22726)
// writes: the path parameter is joined into a file path in the handler, and the open call
// that consumes it sits inside an immediately-invoked literal that captured it.
func TestGoFuncLiteralCallsCarryTaint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.go")
	src := []byte(`package artifacts

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"

	"github.com/julienschmidt/httprouter"
)

func uploads(router *httprouter.Router, fsys MkdirFS) {
	router.POST("/_apis/pipelines/workflows/:runId/artifacts", func(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
		runID := params.ByName("runId")
		itemPath := req.URL.Query().Get("itemPath")
		filePath := fmt.Sprintf("%s/%s", runID, itemPath)

		file, err := func() (fs.File, error) {
			if req.Header.Get("Content-Range") != "" {
				return fsys.OpenAtEnd(filePath)
			}
			return fsys.Open(filePath)
		}()
		_ = file
		_ = err
	})
}

func downloads(router *httprouter.Router) {
	router.GET("/download/:container", func(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
		read := func(name string) ([]byte, error) {
			return os.ReadFile(name)
		}
		body, err := read(params.ByName("container"))
		_ = body
		_ = err
	})
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

	// the immediately-invoked literal: the captured filePath reaches BOTH opens inside it.
	runID := goFindNode(t, g, "code.Call", map[string]string{"callee_path": "params.ByName", "lit0": "runId"})
	reachable, err := usg.BFS(g, runID, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	for _, callee := range []string{"fsys.OpenAtEnd", "fsys.Open"} {
		open, ok, err := g.GetNode(goFindNode(t, g, "code.Call", map[string]string{"callee_path": callee}))
		if err != nil || !ok {
			t.Fatalf("%s call node: ok=%v err=%v", callee, ok, err)
		}
		arg := open.Prop("arg0")
		if arg == "" {
			t.Fatalf("%s call has no argument node: %#v", callee, open)
		}
		if !reachable[arg] {
			t.Fatalf("the path parameter did not reach %s inside the invoked func literal", callee)
		}
	}

	// the call through the func-typed local: the argument reaches the literal's parameter
	// and the body it flows through.
	container := goFindNode(t, g, "code.Call", map[string]string{"callee_path": "params.ByName", "lit0": "container"})
	reachable, err = usg.BFS(g, container, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	param := goFindNode(t, g, "code.Param", map[string]string{"name": "name"})
	if !reachable[param] {
		t.Fatalf("the path parameter did not reach the parameter of the func-typed local's literal")
	}
	readFile, ok, err := g.GetNode(goFindNode(t, g, "code.Call", map[string]string{"callee_path": "os.ReadFile"}))
	if err != nil || !ok {
		t.Fatalf("os.ReadFile call node: ok=%v err=%v", ok, err)
	}
	if arg := readFile.Prop("arg0"); arg == "" || !reachable[arg] {
		t.Fatalf("the path parameter did not reach os.ReadFile inside the func-typed local's literal")
	}

	// and the call's RESULT comes from that literal's return, not from an opaque callee.
	readCall := goFindNode(t, g, "code.Call", map[string]string{"callee_path": "read"})
	ret := goFindNode(t, g, "code.Return", map[string]string{"func": goFuncOfParam(t, g, param)})
	outs, err := g.OutEdges(ret, "FLOWS")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range outs {
		if e.Dst == readCall {
			found = true
		}
	}
	if !found {
		t.Fatalf("the result of the call through the func-typed local does not come from the literal's return")
	}
}

// goFuncOfParam reports the synthetic function name a parameter node belongs to.
func goFuncOfParam(t *testing.T, g usg.Store, param string) string {
	t.Helper()
	n, ok, err := g.GetNode(param)
	if err != nil || !ok {
		t.Fatalf("param node %s: ok=%v err=%v", param, ok, err)
	}
	return n.Prop("func")
}

// The same two shapes under the deferred-body cache a memory-bounded scan installs: the
// synthetic FuncDefs are emitted into the statement list BEFORE it is spooled, so they
// have to survive the round trip and still register as the enclosing body's declarations.
func TestGoFuncLiteralCallsCarryTaintWithDeferredBodies(t *testing.T) {
	cache, err := parsecache.OpenTransient(t.TempDir())
	if err != nil {
		t.Fatalf("OpenTransient: %v", err)
	}
	defer cache.Close()
	restore := parsecache.SetShared(cache)
	defer restore()

	dir := t.TempDir()
	path := filepath.Join(dir, "server.go")
	src := []byte(`package artifacts

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"

	"github.com/julienschmidt/httprouter"
)

func uploads(router *httprouter.Router, fsys MkdirFS) {
	router.POST("/x/:runId", func(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
		filePath := fmt.Sprintf("%s/x", params.ByName("runId"))

		file, err := func() (fs.File, error) {
			return fsys.OpenAtEnd(filePath)
		}()
		_ = file
		_ = err

		read := func(name string) ([]byte, error) { return os.ReadFile(name) }
		body, _ := read(filePath)
		_ = body
	})
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := gofrontend.Extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.LowerTypedDeferred(prog, true, nil, cache)
	if err != nil {
		t.Fatal(err)
	}
	source := goFindNode(t, g, "code.Call", map[string]string{"callee_path": "params.ByName"})
	reachable, err := usg.BFS(g, source, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	for _, callee := range []string{"fsys.OpenAtEnd", "os.ReadFile"} {
		n, ok, err := g.GetNode(goFindNode(t, g, "code.Call", map[string]string{"callee_path": callee}))
		if err != nil || !ok {
			t.Fatalf("%s call node: ok=%v err=%v", callee, ok, err)
		}
		if arg := n.Prop("arg0"); arg == "" || !reachable[arg] {
			t.Fatalf("with bodies deferred to the parse cache, the path parameter did not reach %s", callee)
		}
	}
}

// The decode-restore universe must span packages, because the shape the real
// repositories use keeps the model struct in its own package (monetr's
// server/models) and the handler dot-imports it. Directories walk in lexical
// order, so the handler's package converts BEFORE the declaring package is
// even buffered, and the only universe that package can state on its own is
// the fields the handler's body touches -- exactly the set that omits the
// fields the vulnerability is: the ones no restore re-establishes because the
// body never names them at all. The scan-wide field index has to resolve the
// declaring package on demand; the body-touched fields stay the universe only
// for a type no package of the scan declares.
func TestGoDecodeRestoreUniverseResolvesAcrossPackages(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"api", "apiv2", "models"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"go.mod":                "module example.com/m\n\ngo 1.21\n",
		"models/transaction.go": "package models\n\ntype Transaction struct {\n\tName      string\n\tSource    string\n\tCreatedAt string\n\tDeletedAt *string\n\tAmount    int64\n}\n",
		"api/handler.go": `package api

import . "example.com/m/models"

type Ctx interface {
	Bind(any) error
	Update(string, any) error
}

func loadExisting() (*Transaction, error) { return nil, nil }

func putVulnerable(ctx Ctx) error {
	var transaction Transaction
	if err := ctx.Bind(&transaction); err != nil {
		return err
	}
	existing, err := loadExisting()
	if err != nil {
		return err
	}
	transaction.Name = existing.Name
	return ctx.Update("id", &transaction)
}

func putFixed(ctx Ctx) error {
	var transaction Transaction
	if err := ctx.Bind(&transaction); err != nil {
		return err
	}
	existing, err := loadExisting()
	if err != nil {
		return err
	}
	transaction.Name = existing.Name
	transaction.Source = existing.Source
	transaction.CreatedAt = existing.CreatedAt
	transaction.DeletedAt = existing.DeletedAt
	return ctx.Update("id", &transaction)
}
`,
		"apiv2/handler.go": `package apiv2

import "example.com/m/models"

type Ctx interface {
	Bind(any) error
}

type repo struct{}

func (repo) UpdateTransaction(t any) error { return nil }

func loadExisting() (*models.Transaction, error) { return nil, nil }

func putDotted(r repo, ctx Ctx) error {
	transaction := &models.Transaction{}
	if err := ctx.Bind(transaction); err != nil {
		return err
	}
	existing, err := loadExisting()
	if err != nil {
		return err
	}
	transaction.Name = existing.Name
	return r.UpdateTransaction(transaction)
}

func putUnknown(ctx Ctx) error {
	var widget Widget
	if err := ctx.Bind(&widget); err != nil {
		return err
	}
	widget.Name = "set"
	return ctx.Update("id", &widget)
}
`,
	}
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(name)), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	prog, err := gofrontend.ExtractDir(dir)
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
	var facts []string
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.go.decode_restore_before_persist" {
			continue
		}
		facts = append(facts, n.Prop("str_args"))
	}
	factFor := func(fn, field string) string {
		t.Helper()
		for _, f := range facts {
			if strings.Contains(f, "function_name:"+fn+"\x00") && strings.Contains(f, "field:"+field+"\x00") {
				return f
			}
		}
		t.Fatalf("no decode-restore fact for %s field %s among %q", fn, field, facts)
		return ""
	}
	countFor := func(fn string) int {
		t.Helper()
		n := 0
		for _, f := range facts {
			if strings.Contains(f, "function_name:"+fn+"\x00") {
				n++
			}
		}
		return n
	}
	// One fact per field of the DECLARED struct per handler (five fields), in
	// the handler package that dot-imports it and the one that spells the type
	// dotted; the handler binding a type no package declares keeps the
	// body-touched universe (one field).
	if got := countFor("putVulnerable"); got != 5 {
		t.Errorf("putVulnerable (dot-imported type): %d facts, want 5 (one per field of the declared models.Transaction -- the body names only Name); got %q", got, facts)
	}
	if got := countFor("putFixed"); got != 5 {
		t.Errorf("putFixed (dot-imported type): %d facts, want 5; got %q", got, facts)
	}
	if got := countFor("putDotted"); got != 5 {
		t.Errorf("putDotted (dotted declared type): %d facts, want 5; got %q", got, facts)
	}
	if got := countFor("putUnknown"); got != 1 {
		t.Errorf("putUnknown (type declared by no package of the scan): %d facts, want 1 (the body-touched universe); got %q", got, facts)
	}
	// The vulnerable handler must state the exposure itself: every field no
	// restore re-established, named by the body or not, carries restored:0 and
	// no record -- the tokens a binding fires on. The fixed handler states the
	// same fields restored:1 with the record, so the two revisions of one
	// handler are told apart by their facts, not by their absence.
	for _, fn := range []string{"putVulnerable", "putDotted"} {
		for _, field := range []string{"Source", "CreatedAt", "DeletedAt", "Amount"} {
			if f := factFor(fn, field); !strings.Contains(f, "restored:0") || strings.Contains(f, "record:") {
				t.Errorf("%s %s fact %q: want restored:0 and no record (no restore re-established it)", fn, field, f)
			}
		}
		if f := factFor(fn, "Name"); !strings.Contains(f, "restored:1") || !strings.Contains(f, "record:existing") {
			t.Errorf("%s Name fact %q: want restored:1 + record:existing", fn, f)
		}
	}
	for _, field := range []string{"Source", "CreatedAt", "DeletedAt"} {
		if f := factFor("putFixed", field); !strings.Contains(f, "restored:1") || !strings.Contains(f, "record:existing") {
			t.Errorf("putFixed %s fact %q: want restored:1 + record:existing", field, f)
		}
	}
	if f := factFor("putFixed", "Amount"); !strings.Contains(f, "restored:0") {
		t.Errorf("putFixed Amount fact %q: want restored:0 (the fix does not protect it)", f)
	}
	if f := factFor("putUnknown", "Name"); !strings.Contains(f, "restored:0") {
		t.Errorf("putUnknown Name fact %q: want restored:0", f)
	}
	for _, f := range facts {
		if strings.Contains(f, "function_name:putUnknown\x00") && strings.Contains(f, "field:Source") {
			t.Errorf("putUnknown stated a field for a type no package declares: %q", f)
		}
	}
}
