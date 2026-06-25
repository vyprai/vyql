package golang_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	gofrontend "github.com/vyprai/vyql/extract/frontend/golang"
	"github.com/vyprai/vyql/extract/lowering"
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
