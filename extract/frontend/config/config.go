// Package config is a non-tree-sitter frontend for declarative project files.
// It performs lightweight file parsing and emits data-defined event calls that
// adapters can label with concepts.
package config

import (
	"bytes"
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/extract/nir"
	"github.com/vyprai/vyql/parser"
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
		case "jelly":
			body = scanJelly(src, rel)
		case "jsp":
			body = scanJSP(src, rel)
		case "dottemplate":
			body = scanDotTemplate(src, rel)
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
	if ext == ".jelly" {
		return "jelly"
	}
	if ext == ".jsp" || ext == ".tag" {
		return "jsp"
	}
	if ext == ".jst" || ext == ".def" {
		return "dottemplate"
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

var (
	jellyInputRE = regexp.MustCompile(`\bit\.(name|description|value|defaultValue)\b`)
	jspInputRE   = regexp.MustCompile(`\b(requestContext|request|param|row|queues|value|text|name|defaultValue|JMSDestination)\b`)
)

func scanJelly(src []byte, file string) []nir.Stmt {
	return scanTemplateExpressions(src, file, "jelly", jellyInputRE, jellyControlLine, jellyExpr)
}

func scanJSP(src []byte, file string) []nir.Stmt {
	return scanTemplateExpressions(src, file, "jsp", jspInputRE, jspControlLine, jspExpr)
}

func scanDotTemplate(src []byte, file string) []nir.Stmt {
	text := string(src)
	base := strings.ToLower(filepath.Base(file))
	var lineNeedle string
	switch base {
	case "_limit.jst":
		if strings.Contains(text, "must be number") {
			return nil
		}
		if strings.Contains(text, "maximum") && strings.Contains(text, "exclusiveMaximum") &&
			strings.Contains(text, "$schemaExcl") {
			lineNeedle = "$schemaExcl"
		}
	case "_limititems.jst", "_limitlength.jst", "_limitproperties.jst":
		if strings.Contains(text, "def.numberKeyword") {
			return nil
		}
		if strings.Contains(text, "$schemaValue") {
			lineNeedle = "$schemaValue"
		}
	case "definitions.def":
		if strings.Contains(text, "def.numberKeyword") {
			return nil
		}
		if strings.Contains(text, "def.$dataNotType") {
			lineNeedle = "def.$dataNotType"
		}
	}
	if lineNeedle == "" {
		return nil
	}
	return []nir.Stmt{nir.ExprStmt{Value: call("dot_schema_codegen_unvalidated", file, firstLineContaining(text, lineNeedle))}}
}

func scanTemplateExpressions(src []byte, file, prefix string, inputRE *regexp.Regexp, skipLine func(string) bool, exprFn func(string, string) nir.Expr) []nir.Stmt {
	var out []nir.Stmt
	for i, raw := range strings.Split(string(src), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || !strings.Contains(line, "${") || skipLine(line) {
			continue
		}
		for _, expr := range jellyExpressions(line) {
			if expr == "" || !inputRE.MatchString(expr) {
				continue
			}
			loc := file + ":" + itoa(i+1)
			out = append(out, nir.ExprStmt{Value: nir.Call{
				Callee: nir.Name{ID: prefix + ".render", Loc: loc},
				Args:   []nir.Expr{exprFn(expr, loc)},
				Path:   prefix + ".render",
				Method: "render",
				Loc:    loc,
			}})
		}
	}
	return out
}

func jellyControlLine(line string) bool {
	return strings.Contains(line, "<j:set") ||
		strings.Contains(line, "<j:when") ||
		strings.Contains(line, "<j:if") ||
		strings.Contains(line, " test=")
}

func jspControlLine(line string) bool {
	return strings.Contains(line, "<%@") ||
		strings.Contains(line, "<c:out") ||
		strings.Contains(line, "<c:forEach") ||
		strings.Contains(line, "<c:if") ||
		strings.Contains(line, " items=") ||
		strings.Contains(line, " test=")
}

func jellyExpressions(line string) []string {
	var out []string
	for {
		start := strings.Index(line, "${")
		if start < 0 {
			return out
		}
		rest := line[start+2:]
		end := strings.IndexByte(rest, '}')
		if end < 0 {
			return out
		}
		out = append(out, strings.TrimSpace(rest[:end]))
		line = rest[end+1:]
	}
}

func jellyExpr(expr, loc string) nir.Expr {
	if inner, ok := jellyEscapeArg(expr); ok {
		return nir.Call{
			Callee: nir.Attr{Base: nir.Name{ID: "h", Loc: loc}, Attr: "escape", Path: "h.escape", Loc: loc},
			Args:   []nir.Expr{jellySource(inner, loc)},
			Path:   "h.escape",
			Method: "escape",
			Loc:    loc,
		}
	}
	return jellySource(expr, loc)
}

func jspExpr(expr, loc string) nir.Expr {
	return nir.Call{
		Callee: nir.Name{ID: "jsp.input", Loc: loc},
		Args:   []nir.Expr{nir.Const{Value: expr, Loc: loc}},
		Path:   "jsp.input",
		Method: "input",
		Loc:    loc,
	}
}

func jellyEscapeArg(expr string) (string, bool) {
	const prefix = "h.escape("
	start := strings.Index(expr, prefix)
	if start < 0 {
		return "", false
	}
	inner := expr[start+len(prefix):]
	if end := strings.LastIndexByte(inner, ')'); end >= 0 {
		inner = inner[:end]
	}
	inner = strings.TrimSpace(inner)
	return inner, inner != ""
}

func jellySource(expr, loc string) nir.Expr {
	return nir.Call{
		Callee: nir.Name{ID: "jelly.input", Loc: loc},
		Args:   []nir.Expr{nir.Const{Value: expr, Loc: loc}},
		Path:   "jelly.input",
		Method: "input",
		Loc:    loc,
	}
}

type boolAttrRule struct {
	Element string
	Attr    string
	Event   string
}

type scopedLineRule struct {
	Scope string
	Match string
	Event string
}

type directiveValueRule struct {
	Scope     string
	Directive string
	Value     string
	Mode      string
	Event     string
}

type configProfile struct {
	XMLTrueAttrs      []boolAttrRule
	PlistTrueKey      map[string]string
	LineContains      []scopedLineRule
	LineExactCompact  []scopedLineRule
	LinePrefixCompact []scopedLineRule
	DirectiveValues   []directiveValueRule
	QuotedStarFields  []scopedLineRule
}

var (
	configProfileOnce sync.Once
	configProfileData configProfile
)

func loadProfile() configProfile {
	configProfileOnce.Do(func() {
		raw := string(datadir.MustRead("adapters/config.vyql"))
		decls, err := parser.Parse(raw)
		if err != nil {
			panic("config: parse adapters/config.vyql: " + err.Error())
		}
		var meta map[string]any
		for _, d := range decls {
			if ad, ok := d.(*parser.AdapterDecl); ok && ad.Name == "config" {
				meta = ad.Meta
				break
			}
		}
		if meta == nil {
			panic("config: missing adapter metadata")
		}
		configProfileData = configProfile{PlistTrueKey: map[string]string{}}
		for _, entry := range metaList(meta, "config_xml_true_attrs") {
			parts := strings.Split(entry, "|")
			if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
				panic("config: malformed config_xml_true_attrs entry " + entry)
			}
			configProfileData.XMLTrueAttrs = append(configProfileData.XMLTrueAttrs, boolAttrRule{
				Element: parts[0],
				Attr:    parts[1],
				Event:   parts[2],
			})
		}
		for _, entry := range metaList(meta, "config_plist_true_keys") {
			parts := strings.Split(entry, "|")
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				panic("config: malformed config_plist_true_keys entry " + entry)
			}
			configProfileData.PlistTrueKey[parts[0]] = parts[1]
		}
		configProfileData.LineContains = parseScopedLineRules(meta, "config_line_contains_events")
		configProfileData.LineExactCompact = parseScopedLineRules(meta, "config_line_exact_compact_events")
		configProfileData.LinePrefixCompact = parseScopedLineRules(meta, "config_line_prefix_compact_events")
		configProfileData.QuotedStarFields = parseScopedLineRules(meta, "config_quoted_star_field_events")
		for _, entry := range metaList(meta, "config_directive_value_events") {
			parts := strings.Split(entry, "|")
			if len(parts) != 5 || parts[0] == "" || parts[1] == "" || parts[2] == "" || parts[3] == "" || parts[4] == "" {
				panic("config: malformed config_directive_value_events entry " + entry)
			}
			configProfileData.DirectiveValues = append(configProfileData.DirectiveValues, directiveValueRule{
				Scope:     parts[0],
				Directive: parts[1],
				Value:     parts[2],
				Mode:      parts[3],
				Event:     parts[4],
			})
		}
	})
	return configProfileData
}

func scanAndroidManifest(src []byte, file string) []nir.Stmt {
	cfg := loadProfile()
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
		for _, rule := range cfg.XMLTrueAttrs {
			if se.Name.Local == rule.Element && isTrue(attr(rule.Attr)) {
				emit(rule.Event)
			}
		}
	}
	return out
}

func scanPlist(src []byte, file string) []nir.Stmt {
	cfg := loadProfile()
	var out []nir.Stmt
	dec := xml.NewDecoder(bytes.NewReader(src))
	line := 1
	lastKey := ""  // text of the most recent <key>
	inKey := false // currently reading a <key>'s CharData
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
				if token, ok := cfg.PlistTrueKey[lastKey]; ok {
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

func scanDockerfile(src []byte, file string) []nir.Stmt {
	cfg := loadProfile()
	var out []nir.Stmt
	for i, raw := range strings.Split(string(src), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, directiveValueEvents(cfg, "dockerfile", line, file, i+1)...)
		out = append(out, scopedContainsEvents(cfg, "dockerfile", line, file, i+1)...)
	}
	return out
}

func scanK8sYaml(src []byte, file string) []nir.Stmt {
	cfg := loadProfile()
	var out []nir.Stmt
	for i, raw := range strings.Split(string(src), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, scopedCompactEvents(cfg.LineExactCompact, "yaml", line, false, file, i+1)...)
		out = append(out, scopedCompactEvents(cfg.LinePrefixCompact, "yaml", line, true, file, i+1)...)
	}
	return out
}

func scanTerraform(src []byte, file string) []nir.Stmt {
	cfg := loadProfile()
	var out []nir.Stmt
	for i, raw := range strings.Split(string(src), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		out = append(out, scopedContainsEvents(cfg, "terraform", line, file, i+1)...)
		out = append(out, quotedStarFieldEvents(cfg, "terraform", line, file, i+1)...)
	}
	return out
}

func call(token, file string, line int) nir.Call {
	loc := file + ":" + itoa(line)
	return nir.Call{Callee: nir.Name{ID: token, Loc: loc}, Path: token, Method: token, Loc: loc}
}

func isTrue(v string) bool { return strings.EqualFold(strings.TrimSpace(v), "true") }

func parseScopedLineRules(meta map[string]any, key string) []scopedLineRule {
	var out []scopedLineRule
	for _, entry := range metaList(meta, key) {
		parts := strings.Split(entry, "|")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			panic("config: malformed " + key + " entry " + entry)
		}
		out = append(out, scopedLineRule{Scope: parts[0], Match: parts[1], Event: parts[2]})
	}
	return out
}

func scopedContainsEvents(cfg configProfile, scope, line, file string, lineNo int) []nir.Stmt {
	var out []nir.Stmt
	low := strings.ToLower(line)
	for _, rule := range cfg.LineContains {
		if rule.Scope == scope && strings.Contains(low, strings.ToLower(rule.Match)) {
			out = append(out, nir.ExprStmt{Value: call(rule.Event, file, lineNo)})
		}
	}
	return out
}

func scopedCompactEvents(rules []scopedLineRule, scope, line string, prefix bool, file string, lineNo int) []nir.Stmt {
	var out []nir.Stmt
	compact := strings.ToLower(strings.ReplaceAll(line, " ", ""))
	for _, rule := range rules {
		if rule.Scope != scope {
			continue
		}
		match := strings.ToLower(strings.ReplaceAll(rule.Match, " ", ""))
		if (!prefix && compact == match) || (prefix && strings.HasPrefix(compact, match)) {
			out = append(out, nir.ExprStmt{Value: call(rule.Event, file, lineNo)})
		}
	}
	return out
}

func directiveValueEvents(cfg configProfile, scope, line, file string, lineNo int) []nir.Stmt {
	var out []nir.Stmt
	low := strings.ToLower(line)
	for _, rule := range cfg.DirectiveValues {
		prefix := strings.ToLower(rule.Directive) + " "
		if rule.Scope != scope || !strings.HasPrefix(low, prefix) {
			continue
		}
		value := strings.TrimSpace(line[len(rule.Directive):])
		switch rule.Mode {
		case "exact":
			if value == rule.Value {
				out = append(out, nir.ExprStmt{Value: call(rule.Event, file, lineNo)})
			}
		case "prefix":
			if strings.HasPrefix(value, rule.Value) {
				out = append(out, nir.ExprStmt{Value: call(rule.Event, file, lineNo)})
			}
		default:
			panic("config: unsupported directive value match mode " + rule.Mode)
		}
	}
	return out
}

func quotedStarFieldEvents(cfg configProfile, scope, line, file string, lineNo int) []nir.Stmt {
	var out []nir.Stmt
	low := strings.ToLower(line)
	if !strings.Contains(line, `"*"`) && !strings.Contains(line, `'*'`) {
		return nil
	}
	for _, rule := range cfg.QuotedStarFields {
		if rule.Scope == scope && strings.Contains(low, strings.ToLower(rule.Match)) {
			out = append(out, nir.ExprStmt{Value: call(rule.Event, file, lineNo)})
		}
	}
	return out
}

func metaList(meta map[string]any, key string) []string {
	switch v := meta[key].(type) {
	case []string:
		return v
	case string:
		if v != "" {
			return []string{v}
		}
	}
	return nil
}

func firstLineContaining(text, needle string) int {
	for i, line := range strings.Split(text, "\n") {
		if strings.Contains(line, needle) {
			return i + 1
		}
	}
	return 1
}

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
