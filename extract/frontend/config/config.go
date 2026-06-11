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
