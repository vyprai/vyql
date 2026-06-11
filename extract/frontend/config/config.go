// Package config is a non-tree-sitter frontend for mobile app configuration
// files — AndroidManifest.xml and iOS Info.plist — that surfaces insecure
// settings as markable NIR Call nodes. Each dangerous setting becomes a bare
// call whose path is a stable token (e.g. "android_exported"), which the config
// adapter labels with a presence concept (ExportedComponent/CleartextConfig/...).
package config

import (
	"bytes"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"

	"github.com/vyprai/vyql/extract/nir"
)

// Extract parses AndroidManifest.xml / *.plist files into one NIR Program. Other
// XML files (and unparseable input) yield no nodes — never an error.
func Extract(files []string, root string) (nir.Program, error) {
	var prog nir.Program
	prog.SelfName = "self"
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		rel := relPath(root, f)
		var body []nir.Stmt
		switch kind(f, src) {
		case "android":
			body = scanAndroidManifest(src, rel)
		case "plist":
			body = scanPlist(src, rel)
		case "dockerfile":
			body = scanDockerfile(src, rel)
		case "yaml":
			body = scanK8sYaml(src, rel)
		case "terraform":
			body = scanTerraform(src, rel)
		}
		if len(body) == 0 {
			continue
		}
		// wrap in a synthetic function so the lowering walks the statements.
		fn := nir.FuncDef{Name: "__config__", Body: body, Loc: rel + ":1"}
		prog.Modules = append(prog.Modules, nir.Module{Key: rel, File: rel, Body: []nir.Stmt{fn}})
	}
	return prog, nil
}

// kind classifies a config file by filename and root element (robust to either).
func kind(path string, src []byte) string {
	base := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(path))
	if base == "androidmanifest.xml" {
		return "android"
	}
	if ext == ".plist" {
		return "plist"
	}
	if base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile") {
		return "dockerfile"
	}
	if ext == ".tf" {
		return "terraform"
	}
	if ext == ".yaml" || ext == ".yml" {
		// only Kubernetes-shaped manifests yield nodes; other YAML is inert.
		if bytes.Contains(src, []byte("apiVersion")) && bytes.Contains(src, []byte("kind")) {
			return "yaml"
		}
		return ""
	}
	// fall back to the root element for unconventionally-named files.
	dec := xml.NewDecoder(bytes.NewReader(src))
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		if se, ok := tok.(xml.StartElement); ok {
			switch se.Name.Local {
			case "manifest":
				return "android"
			case "plist":
				return "plist"
			default:
				return ""
			}
		}
	}
}

// androidComponents are the manifest elements whose android:exported="true" is a
// security-relevant attack surface (CWE-926).
var androidComponents = map[string]bool{
	"activity": true, "activity-alias": true, "service": true,
	"receiver": true, "provider": true,
}

func scanAndroidManifest(src []byte, file string) []nir.Stmt {
	var out []nir.Stmt
	dec := xml.NewDecoder(bytes.NewReader(src))
	line := 1
	emit := func(token string) {
		out = append(out, nir.ExprStmt{Value: call(token, file, line)})
	}
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		line++
		attr := func(name string) string {
			for _, a := range se.Attr {
				if a.Name.Local == name {
					return a.Value
				}
			}
			return ""
		}
		if androidComponents[se.Name.Local] && isTrue(attr("exported")) {
			emit("android_exported")
		}
		if se.Name.Local == "application" {
			if isTrue(attr("usesCleartextTraffic")) {
				emit("android_cleartext")
			}
			if isTrue(attr("debuggable")) {
				emit("android_debuggable")
			}
		}
	}
	return out
}

// plistFlagKeys map an Info.plist boolean key (set to <true/>) to its finding token.
var plistFlagKeys = map[string]string{
	"NSAllowsArbitraryLoads":             "ats_arbitrary_loads",
	"NSAllowsArbitraryLoadsInWebContent": "ats_arbitrary_loads",
	"NSAllowsArbitraryLoadsForMedia":     "ats_arbitrary_loads",
}

func scanPlist(src []byte, file string) []nir.Stmt {
	var out []nir.Stmt
	dec := xml.NewDecoder(bytes.NewReader(src))
	line := 1
	lastKey := ""   // text of the most recent <key>
	inKey := false  // currently reading a <key>'s CharData
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			line++
			switch t.Name.Local {
			case "key":
				inKey = true
				lastKey = ""
			case "true":
				if token, ok := plistFlagKeys[lastKey]; ok {
					out = append(out, nir.ExprStmt{Value: call(token, file, line)})
				}
				lastKey = "" // value consumed
			case "false", "string", "integer", "real", "data", "date":
				lastKey = "" // a non-matching value resets the pending key
			}
		case xml.CharData:
			if inKey {
				lastKey += strings.TrimSpace(string(t))
			}
		case xml.EndElement:
			if t.Name.Local == "key" {
				inKey = false
			}
		}
	}
	return out
}

// scanDockerfile flags running as root (USER root, or no USER directive at all is NOT
// flagged — too noisy) and privileged build args. Line-based, comment-aware.
func scanDockerfile(src []byte, file string) []nir.Stmt {
	var out []nir.Stmt
	for i, raw := range strings.Split(string(src), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		low := strings.ToLower(line)
		switch {
		case strings.HasPrefix(low, "user "):
			user := strings.TrimSpace(line[5:])
			if user == "root" || user == "0" || strings.HasPrefix(user, "root:") || strings.HasPrefix(user, "0:") {
				out = append(out, nir.ExprStmt{Value: call("container_user_root", file, i+1)})
			}
		case strings.Contains(low, "--privileged"):
			out = append(out, nir.ExprStmt{Value: call("docker_privileged", file, i+1)})
		}
	}
	return out
}

// k8sFlags map a `key: true`-style security-relevant K8s field to its finding token.
var k8sFlags = []struct{ needle, token string }{
	{"privileged: true", "k8s_privileged"},
	{"allowprivilegeescalation: true", "k8s_privileged"},
	{"hostnetwork: true", "k8s_host_namespace"},
	{"hostpid: true", "k8s_host_namespace"},
	{"hostipc: true", "k8s_host_namespace"},
}

// scanK8sYaml flags privileged containers / host-namespace sharing / host-path mounts in
// a Kubernetes manifest. Line-based (whitespace-insensitive) — no YAML parse needed.
func scanK8sYaml(src []byte, file string) []nir.Stmt {
	var out []nir.Stmt
	for i, raw := range strings.Split(string(src), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		low := strings.ToLower(strings.ReplaceAll(line, " ", ""))
		for _, f := range k8sFlags {
			if low == strings.ReplaceAll(f.needle, " ", "") {
				out = append(out, nir.ExprStmt{Value: call(f.token, file, i+1)})
			}
		}
		if strings.HasPrefix(low, "hostpath:") || low == "hostpath:" {
			out = append(out, nir.ExprStmt{Value: call("k8s_host_path", file, i+1)})
		}
	}
	return out
}

// scanTerraform flags an open security-group CIDR (0.0.0.0/0) and wildcard IAM
// action/resource. Line-based over HCL/JSON — robust to formatting.
func scanTerraform(src []byte, file string) []nir.Stmt {
	var out []nir.Stmt
	for i, raw := range strings.Split(string(src), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		low := strings.ToLower(line)
		if strings.Contains(low, "0.0.0.0/0") {
			out = append(out, nir.ExprStmt{Value: call("tf_open_cidr", file, i+1)})
		}
		// wildcard IAM: HCL `actions = ["*"]` / `resources = ["*"]` or JSON `"Action": "*"`.
		if (strings.Contains(low, "action") || strings.Contains(low, "resource")) &&
			(strings.Contains(line, `"*"`) || strings.Contains(line, `'*'`)) {
			out = append(out, nir.ExprStmt{Value: call("tf_wildcard_iam", file, i+1)})
		}
	}
	return out
}

func call(token, file string, line int) nir.Call {
	loc := file + ":" + itoa(line)
	return nir.Call{Callee: nir.Name{ID: token, Loc: loc}, Path: token, Method: token, Loc: loc}
}

func isTrue(v string) bool { return strings.EqualFold(strings.TrimSpace(v), "true") }

func relPath(root, f string) string {
	if rel, err := filepath.Rel(root, f); err == nil {
		return rel
	}
	return filepath.Base(f)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
