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

// Extract parses declarative config/template files into one NIR Program. Other
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
		k := kind(f, src)
		if k == "" {
			if scope, ok := textTemplateScope(f, src, loadProfile()); ok {
				k = "texttemplate:" + scope
			}
		}
		switch {
		case k == "android":
			body = scanAndroidManifest(src, rel)
		case k == "plist":
			body = scanPlist(src, rel)
		case k == "dockerfile":
			body = scanDockerfile(src, rel)
		case k == "yaml":
			body = scanK8sYaml(src, rel)
		case k == "terraform":
			body = scanTerraform(src, rel)
		case k == "jelly":
			body = scanJelly(src, rel)
		case k == "jsp":
			body = scanJSP(src, rel)
		case k == "dottemplate":
			body = scanDotTemplate(src, rel)
		case strings.HasPrefix(k, "texttemplate:"):
			body = scanTextTemplate(src, rel, strings.TrimPrefix(k, "texttemplate:"))
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
	defaultExprStart = "${"
	defaultExprEnd   = "}"
)

func scanJelly(src []byte, file string) []nir.Stmt {
	return scanTemplateExpressions(src, file, "jelly")
}

func scanJSP(src []byte, file string) []nir.Stmt {
	return scanTemplateExpressions(src, file, "jsp")
}

func scanDotTemplate(src []byte, file string) []nir.Stmt {
	cfg := loadProfile()
	text := string(src)
	base := strings.ToLower(filepath.Base(file))
	for _, rule := range cfg.DotRules {
		if strings.ToLower(rule.File) != base {
			continue
		}
		if containsAny(text, rule.SkipContains) || !containsAll(text, rule.RequiredContains) {
			continue
		}
		return []nir.Stmt{nir.ExprStmt{Value: call(rule.Event, file, firstLineContaining(text, rule.LineNeedle))}}
	}
	return nil
}

func scanTextTemplate(src []byte, file, scope string) []nir.Stmt {
	cfg := loadProfile()
	profile, ok := cfg.TextTemplates[scope]
	if !ok {
		return nil
	}
	var out []nir.Stmt
	for i, raw := range strings.Split(string(src), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		loc := file + ":" + itoa(i+1)
		for _, rule := range profile.LineEvents {
			if containsMatch(line, rule.Match) {
				out = append(out, nir.ExprStmt{Value: call(rule.Event, file, i+1)})
			}
		}
		for _, rule := range profile.AssignEvents {
			m := rule.AssignPattern.FindStringSubmatch(line)
			if len(m) < 2 {
				continue
			}
			expr := rule.SourcePattern.FindString(line)
			if expr == "" {
				continue
			}
			out = append(out, nir.Assign{
				Targets: []string{m[1]},
				Value:   textTemplateValue(rule.InputEvent, expr, loc),
			})
		}
		for _, rule := range profile.FlowEvents {
			if !containsMatch(line, rule.Match) {
				continue
			}
			expr := rule.SourcePattern.FindString(line)
			if expr == "" {
				continue
			}
			out = append(out, nir.ExprStmt{Value: nir.Call{
				Callee: nir.Name{ID: rule.OperationEvent, Loc: loc},
				Args:   []nir.Expr{textTemplateValue(rule.InputEvent, expr, loc)},
				Path:   rule.OperationEvent,
				Method: lastSeg(rule.OperationEvent),
				Loc:    loc,
			}})
		}
	}
	return out
}

func textTemplateValue(inputEvent, expr, loc string) nir.Expr {
	name := strings.TrimPrefix(expr, "$")
	name = strings.TrimPrefix(name, "!")
	if !strings.HasPrefix(name, "request.") {
		return nir.Name{ID: name, Loc: loc}
	}
	return nir.Call{
		Callee: nir.Name{ID: inputEvent, Loc: loc},
		Args:   []nir.Expr{nir.Const{Value: expr, Loc: loc}},
		Path:   inputEvent,
		Method: "input",
		Loc:    loc,
	}
}

func scanTemplateExpressions(src []byte, file, scope string) []nir.Stmt {
	cfg := loadProfile()
	profile, ok := cfg.Templates[scope]
	if !ok {
		return nil
	}
	var out []nir.Stmt
	for i, raw := range strings.Split(string(src), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || !strings.Contains(line, profile.ExprStart) || containsAny(line, profile.SkipContains) {
			continue
		}
		for _, expr := range templateExpressions(line, profile.ExprStart, profile.ExprEnd) {
			if expr == "" || !profile.InputPattern.MatchString(expr) {
				continue
			}
			loc := file + ":" + itoa(i+1)
			out = append(out, nir.ExprStmt{Value: nir.Call{
				Callee: nir.Name{ID: profile.RenderEvent, Loc: loc},
				Args:   []nir.Expr{templateExpr(profile, expr, loc)},
				Path:   profile.RenderEvent,
				Method: "render",
				Loc:    loc,
			}})
		}
	}
	return out
}

func templateExpressions(line, startDelim, endDelim string) []string {
	var out []string
	for {
		start := strings.Index(line, startDelim)
		if start < 0 {
			return out
		}
		rest := line[start+len(startDelim):]
		end := strings.Index(rest, endDelim)
		if end < 0 {
			return out
		}
		out = append(out, strings.TrimSpace(rest[:end]))
		line = rest[end+1:]
	}
}

func templateExpr(profile templateProfile, expr, loc string) nir.Expr {
	if inner, ok := templateWrapperArg(expr, profile.EscapePrefix); ok {
		return nir.Call{
			Callee: nir.Name{ID: profile.EscapeEvent, Loc: loc},
			Args:   []nir.Expr{templateInput(profile, inner, loc)},
			Path:   profile.EscapeEvent,
			Method: lastSeg(profile.EscapeEvent),
			Loc:    loc,
		}
	}
	return templateInput(profile, expr, loc)
}

func templateWrapperArg(expr, prefix string) (string, bool) {
	if prefix == "" {
		return "", false
	}
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

func templateInput(profile templateProfile, expr, loc string) nir.Expr {
	return nir.Call{
		Callee: nir.Name{ID: profile.InputEvent, Loc: loc},
		Args:   []nir.Expr{nir.Const{Value: expr, Loc: loc}},
		Path:   profile.InputEvent,
		Method: "input",
		Loc:    loc,
	}
}

type boolAttrRule struct {
	Element string
	Attr    string
	Event   string
}

type attrNotValueRule struct {
	Element string
	Attr    string
	Value   string
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

type templateProfile struct {
	ExprStart    string
	ExprEnd      string
	InputPattern *regexp.Regexp
	SkipContains []string
	InputEvent   string
	RenderEvent  string
	EscapePrefix string
	EscapeEvent  string
}

type dotTemplateRule struct {
	File             string
	SkipContains     []string
	RequiredContains []string
	LineNeedle       string
	Event            string
}

type textTemplateFlowRule struct {
	Match          string
	SourcePattern  *regexp.Regexp
	InputEvent     string
	OperationEvent string
}

type textTemplateAssignRule struct {
	AssignPattern *regexp.Regexp
	SourcePattern *regexp.Regexp
	InputEvent    string
}

type textTemplateProfile struct {
	Extensions       []string
	RequiredContains []string
	LineEvents       []scopedLineRule
	AssignEvents     []textTemplateAssignRule
	FlowEvents       []textTemplateFlowRule
}

type configProfile struct {
	XMLTrueAttrs      []boolAttrRule
	XMLAttrNotValues  []attrNotValueRule
	PlistTrueKey      map[string]string
	LineContains      []scopedLineRule
	LineExactCompact  []scopedLineRule
	LinePrefixCompact []scopedLineRule
	DirectiveValues   []directiveValueRule
	QuotedStarFields  []scopedLineRule
	Templates         map[string]templateProfile
	DotRules          []dotTemplateRule
	TextTemplates     map[string]textTemplateProfile
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
		configProfileData = configProfile{
			PlistTrueKey:  map[string]string{},
			Templates:     map[string]templateProfile{},
			TextTemplates: map[string]textTemplateProfile{},
		}
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
		for _, entry := range metaList(meta, "config_xml_attr_not_value_events") {
			parts := strings.Split(entry, "|")
			if len(parts) != 4 || parts[0] == "" || parts[1] == "" || parts[2] == "" || parts[3] == "" {
				panic("config: malformed config_xml_attr_not_value_events entry " + entry)
			}
			configProfileData.XMLAttrNotValues = append(configProfileData.XMLAttrNotValues, attrNotValueRule{
				Element: parts[0],
				Attr:    parts[1],
				Value:   parts[2],
				Event:   parts[3],
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
		exprStart := firstNonEmpty(metaString(meta, "config_template_expr_start"), defaultExprStart)
		exprEnd := firstNonEmpty(metaString(meta, "config_template_expr_end"), defaultExprEnd)
		for _, scope := range metaList(meta, "config_template_scopes") {
			pattern := metaString(meta, "config_template_input_pattern_"+scope)
			inputEvent := metaString(meta, "config_template_input_event_"+scope)
			renderEvent := metaString(meta, "config_template_render_event_"+scope)
			if scope == "" || pattern == "" || inputEvent == "" || renderEvent == "" {
				panic("config: malformed config template profile " + scope)
			}
			configProfileData.Templates[scope] = templateProfile{
				ExprStart:    exprStart,
				ExprEnd:      exprEnd,
				InputPattern: regexp.MustCompile(pattern),
				SkipContains: metaList(meta, "config_template_skip_contains_"+scope),
				InputEvent:   inputEvent,
				RenderEvent:  renderEvent,
				EscapePrefix: metaString(meta, "config_template_escape_prefix_"+scope),
				EscapeEvent:  metaString(meta, "config_template_escape_event_"+scope),
			}
		}
		for _, entry := range metaList(meta, "config_dot_template_rules") {
			parts := strings.Split(entry, "|")
			if len(parts) != 5 || parts[0] == "" || parts[2] == "" || parts[3] == "" || parts[4] == "" {
				panic("config: malformed config_dot_template_rules entry " + entry)
			}
			configProfileData.DotRules = append(configProfileData.DotRules, dotTemplateRule{
				File:             parts[0],
				SkipContains:     splitList(parts[1]),
				RequiredContains: splitList(parts[2]),
				LineNeedle:       parts[3],
				Event:            parts[4],
			})
		}
		for _, scope := range metaList(meta, "config_text_template_scopes") {
			if scope == "" {
				panic("config: malformed config text template profile")
			}
			profile := textTemplateProfile{
				Extensions:       metaList(meta, "config_text_template_extensions_"+scope),
				RequiredContains: metaList(meta, "config_text_template_required_contains_"+scope),
			}
			if len(profile.Extensions) == 0 || len(profile.RequiredContains) == 0 {
				panic("config: malformed config text template classifier " + scope)
			}
			for _, entry := range metaList(meta, "config_text_template_line_events_"+scope) {
				parts := strings.Split(entry, "|")
				if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
					panic("config: malformed config_text_template_line_events entry " + entry)
				}
				profile.LineEvents = append(profile.LineEvents, scopedLineRule{Scope: scope, Match: parts[0], Event: parts[1]})
			}
			for _, entry := range metaList(meta, "config_text_template_assign_events_"+scope) {
				parts := strings.Split(entry, "|")
				if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
					panic("config: malformed config_text_template_assign_events entry " + entry)
				}
				profile.AssignEvents = append(profile.AssignEvents, textTemplateAssignRule{
					AssignPattern: regexp.MustCompile(parts[0]),
					SourcePattern: regexp.MustCompile(parts[1]),
					InputEvent:    parts[2],
				})
			}
			for _, entry := range metaList(meta, "config_text_template_flow_events_"+scope) {
				parts := strings.Split(entry, "|")
				if len(parts) != 4 || parts[0] == "" || parts[1] == "" || parts[2] == "" || parts[3] == "" {
					panic("config: malformed config_text_template_flow_events entry " + entry)
				}
				profile.FlowEvents = append(profile.FlowEvents, textTemplateFlowRule{
					Match:          parts[0],
					SourcePattern:  regexp.MustCompile(parts[1]),
					InputEvent:     parts[2],
					OperationEvent: parts[3],
				})
			}
			configProfileData.TextTemplates[scope] = profile
		}
	})
	return configProfileData
}

func textTemplateScope(path string, src []byte, cfg configProfile) (string, bool) {
	text := string(src)
	ext := strings.ToLower(filepath.Ext(path))
	for scope, profile := range cfg.TextTemplates {
		if !extensionAllowed(ext, profile.Extensions) || !containsAll(text, profile.RequiredContains) {
			continue
		}
		return scope, true
	}
	return "", false
}

func extensionAllowed(ext string, allowed []string) bool {
	for _, candidate := range allowed {
		if strings.EqualFold(ext, candidate) {
			return true
		}
	}
	return false
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
		for _, rule := range cfg.XMLAttrNotValues {
			if se.Name.Local == rule.Element && !strings.EqualFold(strings.TrimSpace(attr(rule.Attr)), rule.Value) {
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

func containsAny(text string, needles []string) bool {
	for _, needle := range needles {
		if needle != "" && strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

func containsAll(text string, needles []string) bool {
	for _, needle := range needles {
		if needle != "" && !strings.Contains(text, needle) {
			return false
		}
	}
	return true
}

func containsMatch(text, needle string) bool {
	return needle != "" && strings.Contains(strings.ToLower(text), strings.ToLower(needle))
}

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

func metaString(meta map[string]any, key string) string {
	if s, ok := meta[key].(string); ok {
		return s
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ";") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func lastSeg(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[i+1:]
	}
	return path
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
