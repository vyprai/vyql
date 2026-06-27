package parser

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"
	"strings"
)

type V2MigrationResult struct {
	Files  []V2MigrationFile
	Ledger []V2MigrationRecord
}

type V2MigrationFile struct {
	PathHint string
	Module   string
	Source   string
}

type V2MigrationRecord struct {
	File        string
	Line        int
	Declaration string
	Construct   string
	Original    string
	Reason      string
	Resolved    bool
	Suggestion  string
}

// ConvertV1ToV2 converts the parsed legacy AST into isolated v2 source files.
// It is deliberately outside production scan/load paths. Unsupported constructs
// are recorded in the ledger and emitted as TODO_v2Migrate stubs that fail
// ParseV2, so migration cannot silently drop security knowledge.
func ConvertV1ToV2(src, file string) (V2MigrationResult, error) {
	return ConvertV1ToV2WithKindPlan(src, file, V2MigrationKindPlan{})
}

func ConvertV1ToV2WithConceptKinds(src, file string, conceptKindHints map[string]string) (V2MigrationResult, error) {
	return ConvertV1ToV2WithKindPlan(src, file, V2MigrationKindPlan{ConceptKinds: conceptKindHints})
}

func ConvertV1ToV2WithKindPlan(src, file string, plan V2MigrationKindPlan) (V2MigrationResult, error) {
	decls, err := Parse(src)
	if err != nil {
		return V2MigrationResult{}, err
	}
	plan = mergeV2MigrationKindPlan(plan, InferV2MigrationKindPlan(decls))
	return convertParsedV1ToV2WithKindPlanAndSource(decls, file, src, plan), nil
}

// ConvertParsedV1ToV2WithKindPlan converts already-parsed v1 declarations using
// a caller-supplied kind plan. It is used by whole-tree migrations to avoid
// reparsing every source file after the global plan has been inferred.
func ConvertParsedV1ToV2WithKindPlan(decls []Decl, file string, plan V2MigrationKindPlan) V2MigrationResult {
	return convertParsedV1ToV2WithKindPlanAndSource(decls, file, "", plan)
}

func ConvertParsedV1ToV2WithKindPlanAndSource(decls []Decl, file, src string, plan V2MigrationKindPlan) V2MigrationResult {
	return convertParsedV1ToV2WithKindPlanAndSource(decls, file, src, plan)
}

func convertParsedV1ToV2WithKindPlanAndSource(decls []Decl, file, src string, plan V2MigrationKindPlan) V2MigrationResult {
	if plan.ConceptKinds == nil {
		plan.ConceptKinds = map[string]string{}
	}
	if plan.Aliases == nil {
		plan.Aliases = map[string]map[string]string{}
	}
	if plan.IssueMirrors == nil {
		plan.IssueMirrors = map[string]bool{}
	}
	if plan.CoverageModes == nil {
		plan.CoverageModes = map[string]map[string]bool{}
	}
	estimate := v2MigrationFileEstimate(decls, plan)
	c := v2Migrator{
		file:     file,
		files:    make([]V2MigrationFile, 0, estimate),
		ledger:   make([]V2MigrationRecord, 0, estimate),
		source:   newV2MigrationSource(src),
		kindPlan: plan,
	}
	for _, d := range decls {
		c.convertDecl(d)
	}
	return V2MigrationResult{Files: c.files, Ledger: c.ledger}
}

func v2MigrationFileEstimate(decls []Decl, plan V2MigrationKindPlan) int {
	estimate := 0
	for _, d := range decls {
		switch x := d.(type) {
		case *AdapterDecl:
			estimate += len(x.Mappings)
			if len(x.Meta) > 0 {
				estimate++
			}
		case *ConceptDecl:
			estimate++
			estimate += len(plan.Aliases[x.QualifiedName()])
		default:
			estimate++
		}
	}
	if estimate < len(decls) {
		return len(decls)
	}
	return estimate
}

func mergeV2MigrationKindPlan(plan, localPlan V2MigrationKindPlan) V2MigrationKindPlan {
	if plan.ConceptKinds == nil {
		plan.ConceptKinds = map[string]string{}
	}
	if plan.Aliases == nil {
		plan.Aliases = map[string]map[string]string{}
	}
	if plan.IssueMirrors == nil {
		plan.IssueMirrors = map[string]bool{}
	}
	if plan.CoverageModes == nil {
		plan.CoverageModes = map[string]map[string]bool{}
	}
	for name, kind := range localPlan.ConceptKinds {
		if plan.ConceptKinds[name] == "" {
			plan.ConceptKinds[name] = kind
		}
	}
	for name, aliases := range localPlan.Aliases {
		if plan.Aliases[name] == nil {
			plan.Aliases[name] = map[string]string{}
		}
		for kind, alias := range aliases {
			if plan.Aliases[name][kind] == "" {
				plan.Aliases[name][kind] = alias
			}
		}
	}
	for name, mirror := range localPlan.IssueMirrors {
		if mirror {
			plan.IssueMirrors[name] = true
		}
	}
	for name, modes := range localPlan.CoverageModes {
		if plan.CoverageModes[name] == nil {
			plan.CoverageModes[name] = map[string]bool{}
		}
		for mode := range modes {
			plan.CoverageModes[name][mode] = true
		}
	}
	return plan
}

type v2Migrator struct {
	file   string
	files  []V2MigrationFile
	ledger []V2MigrationRecord
	seq    int

	source   v2MigrationSource
	kindPlan V2MigrationKindPlan
}

type v2MigrationSource struct {
	lines      []string
	declLines  map[string]v2MigrationSourceHit
	constructs map[string]v2MigrationSourceHit
	cache      map[string]v2MigrationSourceHit
}

type v2MigrationSourceHit struct {
	line     int
	original string
}

func newV2MigrationSource(src string) v2MigrationSource {
	if src == "" {
		return v2MigrationSource{}
	}
	s := v2MigrationSource{
		lines:      strings.Split(src, "\n"),
		declLines:  map[string]v2MigrationSourceHit{},
		constructs: map[string]v2MigrationSourceHit{},
		cache:      map[string]v2MigrationSourceHit{},
	}
	s.index()
	return s
}

func (s v2MigrationSource) index() {
	module := ""
	currentDecl := ""
	currentDepth := 0
	for i, line := range s.lines {
		lineNo := i + 1
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if mod, ok := v2MigrationModuleLine(trimmed); ok {
			module = mod
		}
		if decl := v2MigrationDeclName(trimmed, module); decl != "" {
			currentDecl = decl
			currentDepth = 0
			s.addDeclHit(decl, lineNo, trimmed)
		}
		if currentDecl != "" {
			v2MigrationLineConstructs(lower, func(construct string) {
				s.addConstructHit(currentDecl, construct, lineNo, trimmed)
			})
			currentDepth += strings.Count(trimmed, "{")
			currentDepth -= strings.Count(trimmed, "}")
			if currentDepth <= 0 && strings.Contains(trimmed, "}") {
				currentDecl = ""
				currentDepth = 0
			}
		}
	}
}

func v2MigrationModuleLine(line string) (string, bool) {
	if !strings.HasPrefix(line, "module ") {
		return "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, "module "))
	rest = strings.TrimSuffix(rest, ";")
	if rest == "" {
		return "", false
	}
	return rest, true
}

func v2MigrationDeclName(line, module string) string {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return ""
	}
	name := strings.Trim(fields[1], "{;")
	switch fields[0] {
	case "concept", "threat", "rule":
		if strings.Contains(name, ".") || module == "" {
			return name
		}
		return module + "." + name
	case "review":
		return strings.Trim(name, "{;")
	case "profile", "state_machine", "adapter":
		return name
	default:
		return ""
	}
}

func v2MigrationLineConstructs(lower string, add func(string)) {
	switch {
	case strings.HasPrefix(lower, "source param"):
		add("source_param")
	case strings.HasPrefix(lower, "source receiver"):
		add("source_receiver")
	case strings.HasPrefix(lower, "source method"):
		add("source_method")
	case strings.HasPrefix(lower, "source "):
		add("source")
	case strings.HasPrefix(lower, "sink receiver"):
		add("sink_receiver")
	case strings.HasPrefix(lower, "sink method"):
		add("sink_method")
	case strings.HasPrefix(lower, "sink "):
		add("sink_path")
	case strings.HasPrefix(lower, "control receiver method"):
		add("control_receiver_method")
	case strings.HasPrefix(lower, "control method"), strings.HasPrefix(lower, "control "):
		add("control")
	case strings.HasPrefix(lower, "mark method"), strings.HasPrefix(lower, "mark "):
		add("mark")
	case strings.HasPrefix(lower, "flag "):
		add("flag")
	case strings.HasPrefix(lower, "filter method"), strings.HasPrefix(lower, "filter path"):
		add("filter")
	case strings.HasPrefix(lower, "flow prefix"):
		add("flow_prefix")
	case strings.HasPrefix(lower, "flow method"):
		add("flow_method")
	case strings.HasPrefix(lower, "flow path"):
		add("flow_path")
	case strings.HasPrefix(lower, "type "):
		add("type")
	case strings.HasPrefix(lower, "assume "):
		add("assume")
	case strings.HasPrefix(lower, "meta "):
		add("adapter meta")
	}
	if strings.Contains(lower, "sanitized_by") {
		add("sanitized_by")
	}
	if strings.Contains(lower, "guarded_by") {
		add("guarded_by")
	}
	if strings.Contains(lower, "closed_by") {
		add("closed_by")
	}
	if strings.HasPrefix(lower, "where ") {
		add("where")
	}
	if strings.HasPrefix(lower, "along ") {
		add("along")
	}
	if strings.HasPrefix(lower, "match transition") {
		add("match transition")
	} else if strings.HasPrefix(lower, "match ") {
		add("match")
	}
	if strings.HasPrefix(lower, "order ") {
		add("order")
	}
	if strings.HasPrefix(lower, "taint ") || strings.HasPrefix(lower, "flow ") || strings.HasPrefix(lower, "assume ") {
		add("rule " + strings.Fields(lower)[0])
	}
}

func (s v2MigrationSource) addDeclHit(decl string, line int, original string) {
	hit := v2MigrationSourceHit{line: line, original: original}
	forEachV2MigrationDeclKey(decl, func(key string) {
		if key != "" {
			if _, exists := s.declLines[key]; !exists {
				s.declLines[key] = hit
			}
		}
	})
}

func (s v2MigrationSource) addConstructHit(decl, construct string, line int, original string) {
	hit := v2MigrationSourceHit{line: line, original: original}
	forEachV2MigrationDeclKey(decl, func(declKey string) {
		forEachV2MigrationConstructKey(construct, func(constructKey string) {
			key := declKey + "\x00" + constructKey
			if _, exists := s.constructs[key]; !exists {
				s.constructs[key] = hit
			}
		})
	})
}

func forEachV2MigrationDeclKey(decl string, fn func(string)) {
	fn(decl)
	short := lastSeg(decl)
	if short != "" && short != decl {
		fn(short)
	}
}

func forEachV2MigrationConstructKey(construct string, fn func(string)) {
	fn(construct)
	if strings.Contains(construct, "_") {
		fn(strings.ReplaceAll(construct, "_", " "))
	}
}

func (s v2MigrationSource) locate(decl, construct string) v2MigrationSourceHit {
	if len(s.lines) == 0 {
		return v2MigrationSourceHit{}
	}
	cacheKey := decl + "\x00" + construct
	if hit, ok := s.cache[cacheKey]; ok {
		return hit
	}
	var found v2MigrationSourceHit
	forEachV2MigrationDeclKey(decl, func(declKey string) {
		if found.line != 0 || found.original != "" {
			return
		}
		forEachV2MigrationConstructKey(construct, func(constructKey string) {
			if found.line != 0 || found.original != "" {
				return
			}
			if hit, ok := s.constructs[declKey+"\x00"+constructKey]; ok {
				found = hit
			}
		})
	})
	if found.line != 0 || found.original != "" {
		s.cache[cacheKey] = found
		return found
	}
	forEachV2MigrationDeclKey(decl, func(declKey string) {
		if found.line != 0 || found.original != "" {
			return
		}
		if hit, ok := s.declLines[declKey]; ok {
			found = hit
		}
	})
	if found.line != 0 || found.original != "" {
		s.cache[cacheKey] = found
		return found
	}
	s.cache[cacheKey] = v2MigrationSourceHit{}
	return v2MigrationSourceHit{}
}

type V2MigrationKindPlan struct {
	ConceptKinds  map[string]string
	Aliases       map[string]map[string]string
	IssueMirrors  map[string]bool
	CoverageModes map[string]map[string]bool
}

func InferV2MigrationConceptKinds(decls []Decl) map[string]string {
	return InferV2MigrationKindPlan(decls).ConceptKinds
}

func InferV2MigrationKindPlan(decls []Decl) V2MigrationKindPlan {
	kinds := map[string]string{}
	desired := map[string]map[string]bool{}
	issueMirrors := map[string]bool{}
	coverageModes := map[string]map[string]bool{}
	want := func(concept, kind string) {
		if concept == "" || kind == "" {
			return
		}
		if desired[concept] == nil {
			desired[concept] = map[string]bool{}
		}
		desired[concept][kind] = true
	}
	wantCoverage := func(concept, mode string) {
		if concept == "" || mode == "" {
			return
		}
		if coverageModes[concept] == nil {
			coverageModes[concept] = map[string]bool{}
		}
		coverageModes[concept][mode] = true
	}
	for _, d := range decls {
		if c, ok := d.(*ConceptDecl); ok {
			kinds[c.QualifiedName()] = v2ConceptKind(c.Kind)
		}
	}
	for _, d := range decls {
		switch x := d.(type) {
		case *AdapterDecl:
			for _, m := range x.Mappings {
				switch m.Kind {
				case "mark", "mark_method", "flag":
					want(m.Concept, "issue")
				case "source", "source_method", "source_receiver", "source_param", "sink_path", "sink_method", "sink_receiver":
					if strings.HasPrefix(m.Kind, "source") {
						want(m.Concept, "source")
					} else {
						want(m.Concept, "sink")
					}
				case "control", "control_method", "control_receiver_method":
					want(m.Concept, "check")
					if m.Kind == "control_receiver_method" {
						wantCoverage(m.Concept, "sameReceiver")
					} else {
						wantCoverage(m.Concept, "path")
					}
				case "filter_path", "filter_method":
					want("threat.CharFilter", "check")
					wantCoverage("threat.CharFilter", "path")
				case "assume_guard_path", "assume_guard_method", "assume_sanitizer_path", "assume_sanitizer_method":
					want("core.Assumption", "check")
					if strings.Contains(m.Kind, "guard") {
						wantCoverage("core.Assumption", "dominates")
					} else {
						wantCoverage("core.Assumption", "path")
					}
				}
			}
		case *Rule:
			switch body := x.Body.(type) {
			case *FlowStmt:
				switch body.Verb {
				case "taint", "flow":
					want(body.Src.Concept, "source")
					want(body.Dst.Concept, "sink")
				case "assume":
					want(body.Src.Concept, "principal")
					want(body.Dst.Concept, "privilege")
				}
			case *MatchStmt:
				if body.TargetKind == "concept" {
					kind := kinds[body.Concept]
					if !v2FactEmitKinds[kind] {
						want(body.Concept, "issue")
						issueMirrors[body.Concept] = true
					} else {
						want(body.Concept, "fact")
					}
				}
			}
			for _, cl := range x.Clauses {
				if cl.Kind != "unless" {
					continue
				}
				switch ex := cl.Unless.(type) {
				case SanitizedBy:
					want(ex.Concept, "check")
					wantCoverage(ex.Concept, "path")
				case GuardedBy:
					want(ex.Concept, "check")
					wantCoverage(ex.Concept, "endpoint")
				case ClosedBy:
					want(ex.Concept, "check")
					wantCoverage(ex.Concept, "dominates")
				}
			}
		}
	}
	aliases := map[string]map[string]string{}
	for concept, uses := range desired {
		final := kinds[concept]
		switch {
		case uses["check"]:
			final = "check"
		case uses["issue"]:
			final = "issue"
		case final == "":
			final = firstV2MigrationKind(uses)
		case !v2MigrationKindSatisfies(final, uses) && len(uses) == 1:
			final = firstV2MigrationKind(uses)
		}
		kinds[concept] = final
		for kind := range uses {
			if v2MigrationKindAllows(final, kind) {
				continue
			}
			if aliases[concept] == nil {
				aliases[concept] = map[string]string{}
			}
			aliases[concept][kind] = v2MigrationAlias(concept, kind)
		}
	}
	return V2MigrationKindPlan{ConceptKinds: kinds, Aliases: aliases, IssueMirrors: issueMirrors, CoverageModes: coverageModes}
}

func firstV2MigrationKind(uses map[string]bool) string {
	for _, kind := range []string{"source", "sink", "check", "issue", "fact", "asset", "exposure", "principal", "privilege", "state"} {
		if uses[kind] {
			return kind
		}
	}
	return "fact"
}

func v2MigrationKindSatisfies(final string, uses map[string]bool) bool {
	for kind := range uses {
		if !v2MigrationKindAllows(final, kind) {
			return false
		}
	}
	return true
}

func v2MigrationKindAllows(final, want string) bool {
	if final == want {
		return true
	}
	return want == "fact" && v2FactEmitKinds[final]
}

func v2MigrationAlias(concept, kind string) string {
	return concept + v2MigrationKindSuffix(kind)
}

func v2MigrationKindSuffix(kind string) string {
	switch kind {
	case "source":
		return "Source"
	case "sink":
		return "Sink"
	case "check":
		return "Check"
	case "issue":
		return "Issue"
	case "principal":
		return "Principal"
	case "privilege":
		return "Privilege"
	case "asset":
		return "Asset"
	case "exposure":
		return "Exposure"
	case "state":
		return "State"
	default:
		return "Fact"
	}
}

func (c *v2Migrator) convertDecl(d Decl) {
	switch x := d.(type) {
	case *ConceptDecl:
		c.addFile(x.QualifiedName(), x.Package, c.convertConcept(x))
		for kind, alias := range c.kindPlan.Aliases[x.QualifiedName()] {
			c.addFile(alias, x.Package, c.convertConceptAlias(x, alias, kind))
		}
	case *ThreatDecl:
		c.addFile(x.QualifiedName(), x.Package, c.convertThreat(x))
	case *ReviewDecl:
		module := v2ModuleForRef(x.Concept)
		c.addFile("review."+v2Ident(lastSeg(x.Concept)), module, c.withModule(module, c.convertReview(x)))
	case *ProfileDecl:
		c.addFile("profile."+x.Name, "profiles", c.withModule("profiles", c.convertProfile(x)))
	case *Rule:
		src, _ := c.convertRule(x)
		c.addFile(x.QualifiedName(), x.Package, src)
	case *AdapterDecl:
		c.convertAdapter(x)
	case *StateMachine:
		reason := "state_machine declarations need native v2 state/fact modelling"
		c.unresolved(x.Name, "state_machine", reason, "")
		c.addFile("unresolved.stateMachine."+x.Name, "migration", c.todoFile("migration", x.Name, reason))
	default:
		reason := "no v2 converter for declaration kind"
		kind := fmt.Sprintf("%T", d)
		c.unresolved("declaration", kind, reason, "")
		c.addFile("unresolved.declaration", "migration", c.todoFile("migration", "declaration", reason))
	}
}

func (c *v2Migrator) convertConcept(x *ConceptDecl) string {
	var b strings.Builder
	fmt.Fprintf(&b, "module %s;\n\n", v2ModuleOrDefault(x.Package, "model"))
	kind := c.kindPlan.ConceptKinds[x.QualifiedName()]
	if kind == "" {
		kind = v2ConceptKind(x.Kind)
	}
	fmt.Fprintf(&b, "concept %s : %s {\n", v2ShortName(x.Name), kind)
	writeV2Fields(&b, c.fieldsWithCoverage(x.Fields, x.QualifiedName(), kind))
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

func (c *v2Migrator) convertConceptAlias(x *ConceptDecl, alias, kind string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "module %s;\n\n", v2ModuleOrDefault(x.Package, "model"))
	fmt.Fprintf(&b, "concept %s : %s {\n", v2ShortName(alias), kind)
	writeV2Fields(&b, c.fieldsWithCoverage(x.Fields, x.QualifiedName(), kind))
	fmt.Fprintf(&b, "}\n")
	c.record(x.QualifiedName(), "concept kind alias", "v1 concept is used as multiple v2 kinds; generated typed alias "+alias, true, alias)
	return b.String()
}

func (c *v2Migrator) fieldsWithCoverage(fields map[string]any, concept, kind string) map[string]any {
	if kind != "check" {
		return fields
	}
	modes := c.kindPlan.CoverageModes[concept]
	if len(modes) == 0 {
		return fields
	}
	merged := make(map[string]any, len(fields)+1)
	for k, v := range fields {
		merged[k] = v
	}
	existing := map[string]bool{}
	if raw, ok := merged["covers"].([]string); ok {
		for _, mode := range raw {
			existing[mode] = true
		}
	}
	for mode := range modes {
		existing[mode] = true
	}
	if len(existing) > 0 {
		out := make([]string, 0, len(existing))
		for mode := range existing {
			out = append(out, mode)
		}
		sort.Strings(out)
		merged["covers"] = out
	}
	return merged
}

func (c *v2Migrator) convertThreat(x *ThreatDecl) string {
	var b strings.Builder
	fmt.Fprintf(&b, "module %s;\n\n", v2ModuleOrDefault(x.Package, "model"))
	fmt.Fprintf(&b, "threat %s {\n", v2ShortName(x.Name))
	writeV2Fields(&b, x.Fields)
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

func (c *v2Migrator) convertReview(x *ReviewDecl) string {
	var b strings.Builder
	fmt.Fprintf(&b, "review %s {\n", x.Concept)
	writeV2Fields(&b, x.Fields)
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

func (c *v2Migrator) convertProfile(x *ProfileDecl) string {
	var b strings.Builder
	fmt.Fprintf(&b, "profile %s {\n", x.Name)
	writeV2Fields(&b, x.Fields)
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

func (c *v2Migrator) convertRule(r *Rule) (string, bool) {
	var b strings.Builder
	module := v2ModuleOrDefault(r.Package, "rules")
	fmt.Fprintf(&b, "module %s;\n\n", module)
	fmt.Fprintf(&b, "rule %s {\n", v2ShortName(r.Name))
	if len(r.Meta) > 0 {
		fmt.Fprintf(&b, "  meta {\n")
		writeV2FieldsIndented(&b, r.Meta, "    ")
		fmt.Fprintf(&b, "  }\n")
	}
	switch body := r.Body.(type) {
	case *FlowStmt:
		verb := body.Verb
		if verb == "assume" {
			verb = "grant"
			c.record(r.QualifiedName(), "rule assume", "v1 assume rule verb maps to v2 grant; review endpoint kinds", true, "grant")
		}
		srcKind, dstKind := "source", "sink"
		if verb == "grant" {
			srcKind, dstKind = "principal", "privilege"
		}
		fmt.Fprintf(&b, "  %s %s%s -> %s%s\n",
			verb,
			c.refForKind(body.Src.Concept, srcKind), v2Alias(body.Src.Binding),
			c.refForKind(body.Dst.Concept, dstKind), v2Alias(body.Dst.Binding))
	case *MatchStmt:
		if body.TargetKind != "concept" {
			fmt.Fprintf(&b, "  query state as %s where %s.machine == %s and %s.from == %q and %s.to == %s select %s\n",
				v2RuleAliasOrDefault(body.Binding, "transition"),
				v2RuleAliasOrDefault(body.Binding, "transition"), body.Machine,
				v2RuleAliasOrDefault(body.Binding, "transition"), body.FromState,
				v2RuleAliasOrDefault(body.Binding, "transition"), body.ToState,
				v2RuleAliasOrDefault(body.Binding, "transition"))
			c.record(r.QualifiedName(), "match transition", "v1 transition match converted to v2 semantic state query; review state schema fields", true, "query state")
			break
		}
		verb := "issue"
		concept := c.refForKind(body.Concept, "issue")
		if v2FactEmitKinds[c.kindPlan.ConceptKinds[body.Concept]] {
			verb = "fact"
			concept = c.refForKind(body.Concept, "fact")
		}
		fmt.Fprintf(&b, "  %s %s%s\n", verb, concept, v2Alias(body.Binding))
		c.record(r.QualifiedName(), "match", "v1 match converted to v2 "+verb+"; confirm concept kind", true, verb)
	case *OrderStmt:
		firstAlias := v2RuleAliasOrDefault(body.First.Binding, "first")
		secondAlias := v2RuleAliasOrDefault(body.Second.Binding, "second")
		fmt.Fprintf(&b, "  query concept as %s where %s.concept == %s reaches concept as %s where %s.concept == %s select %s\n",
			firstAlias, firstAlias, body.First.Concept, secondAlias, secondAlias, body.Second.Concept, secondAlias)
		c.record(r.QualifiedName(), "order", "v1 temporal order converted to v2 semantic reaches query; review CFG-order semantics", true, "query concept reaches concept")
	default:
		c.unresolved(r.QualifiedName(), fmt.Sprintf("%T", r.Body), "unsupported rule body", "")
		return c.todoFile(module, r.Name, "unsupported rule body"), false
	}
	for _, cl := range r.Clauses {
		switch cl.Kind {
		case "unless":
			switch ex := cl.Unless.(type) {
			case SanitizedBy:
				fmt.Fprintf(&b, "  unless %s coveredBy %s\n", v2RuleCoverageTarget(r.Body, "path"), c.refForKind(ex.Concept, "check"))
				c.record(r.QualifiedName(), "sanitized_by", "suggested v2 coverage mode path; review candidate alias/part", true, "path")
			case GuardedBy:
				fmt.Fprintf(&b, "  unless %s coveredBy %s\n", v2RuleCoverageTarget(r.Body, "endpoint"), c.refForKind(ex.Concept, "check"))
				c.record(r.QualifiedName(), "guarded_by", "suggested v2 coverage mode endpoint; review candidate alias/part", true, "endpoint")
			case ClosedBy:
				fmt.Fprintf(&b, "  unless %s coveredBy %s\n", v2RuleCoverageTarget(r.Body, "dominates"), c.refForKind(ex.Concept, "check"))
				c.record(r.QualifiedName(), "closed_by", "suggested v2 coverage mode dominates; review candidate alias/part", true, "dominates")
			default:
				c.unresolved(r.QualifiedName(), "unless expression", "expression unless clauses need v2 where/coveredBy review", "")
				return c.todoFile(module, r.Name, "unless expression requires manual v2 migration"), false
			}
		case "where":
			expr, ok := v2RuleWhereExpr(cl.Where)
			if !ok {
				c.unresolved(r.QualifiedName(), "where", "rule where clause needs semantic v2 expression conversion", "")
				return c.todoFile(module, r.Name, "where clause requires manual v2 migration"), false
			}
			fmt.Fprintf(&b, "  where %s\n", expr)
			c.record(r.QualifiedName(), "where", "v1 where expression converted to v2 expression; review semantic helper names", true, expr)
		case "along":
			c.unresolved(r.QualifiedName(), cl.Kind, "rule clause needs semantic v2 expression conversion", "")
			return c.todoFile(module, r.Name, cl.Kind+" clause requires manual v2 migration"), false
		}
	}
	fmt.Fprintf(&b, "}\n")
	return b.String(), true
}

func (c *v2Migrator) convertAdapter(a *AdapterDecl) {
	module := "bindings." + a.Name + ".migration." + v2MigrationModuleSuffix(c.file)
	if len(a.Meta) > 0 {
		src, ok := c.convertAdapterMeta(module, a)
		name := a.Name + ".000.adapterMetadata"
		if ok {
			c.addFile(name, module, src)
		} else {
			c.addFile(name+".unresolved", module, src)
		}
	}
	for i, m := range a.Mappings {
		src, ok := c.convertAdapterMapping(module, a.Name, i, m)
		name := fmt.Sprintf("%s.%03d.%s", a.Name, i, v2Ident(m.Concept))
		if ok {
			c.addFile(name, module, src)
		} else {
			c.addFile(name+".unresolved", module, src)
		}
	}
}

func (c *v2Migrator) convertAdapterMeta(module string, a *AdapterDecl) (string, bool) {
	reason := "adapter metadata requires stable v2 declaration support"
	c.unresolved(a.Name, "adapter meta", reason, "")
	return c.todoFile(module, a.Name+"AdapterMetadata", reason), false
}

func (c *v2Migrator) convertAdapterMapping(module, adapter string, idx int, m AdapterMapping) (string, bool) {
	if reason := unsupportedAdapterMappingReason(m); reason != "" {
		c.unresolved(adapter, m.Kind, reason, "")
		return c.todoFile(module, fmt.Sprintf("%s%d", adapter, idx), reason), false
	}
	var b strings.Builder
	fmt.Fprintf(&b, "module %s;\n\n", module)
	bindingName := v2Ident(lastSeg(m.Concept))
	if bindingName == "" {
		bindingName = "binding"
	}
	fmt.Fprintf(&b, "binding %s%d {\n", strings.ToLower(bindingName[:1])+bindingName[1:], idx)
	writeV2PackageRequires(&b, m.Packages)
	_, legacyFlag := v2LegacyFlagPredicate(m)
	simpleFlagExpr, simpleFlag := v2SimpleFlagPredicate(m)
	callValueFlagExpr, callValueFlag := "", false
	if c.kindPlan.ConceptKinds[m.Concept] != "check" {
		callValueFlagExpr, callValueFlag = v2CallValueFlagPredicate(m)
	}
	if m.Kind == "flag" && legacyFlag && !simpleFlag && !callValueFlag {
		reason := "flag predicates require reviewed stable v2 patterns/matchers"
		c.unresolved(adapter, "flag", reason, "")
		return c.todoFile(module, fmt.Sprintf("%s%d", adapter, idx), reason), false
	}
	if simpleFlag {
		fmt.Fprintf(&b, "  query pattern callExpr where %s\n", simpleFlagExpr)
	} else if callValueFlag {
		fmt.Fprintf(&b, "  query pattern callExpr where %s\n", callValueFlagExpr)
	} else if m.Kind == "source_param" {
		fmt.Fprintf(&b, "  query param as param\n")
	} else {
		fmt.Fprintf(&b, "  query pattern callExpr where %s\n", v2AdapterPredicate(m))
	}
	switch m.Kind {
	case "source_param":
		fmt.Fprintf(&b, "  emit source %s at param\n", c.refForKind(m.Concept, "source"))
		c.record(adapter, "source_param", "v1 source param converted to v2 param-family source binding", true, "query param")
	case "type":
		fmt.Fprintf(&b, "  emit fact %s at call.result {\n", v2RuntimeTypeFactConcept())
		fmt.Fprintf(&b, "    about: %s\n", m.Concept)
		fmt.Fprintf(&b, "  }\n")
		c.record(adapter, "type", "v1 constructor type hint converted to v2 runtime type fact; review runtime fact concept", true, "emit fact "+v2RuntimeTypeFactConcept())
	case "flow_path", "flow_method":
		from := "call.result"
		if !m.FlowSourceResult {
			from = fmt.Sprintf("args[%d]", m.FlowSourceArg)
		}
		fmt.Fprintf(&b, "  propagate value from %s to args[%d].pointee\n", from, m.FlowDestArg)
		c.record(adapter, m.Kind, "v1 flow adapter converted to v2 value propagation", true, "propagate value")
	case "source", "source_method", "source_receiver":
		fmt.Fprintf(&b, "  emit source %s at call.result\n", c.refForKind(m.Concept, "source"))
		c.writeIssueMirrorEmit(&b, m.Concept, "call")
	case "sink_path", "sink_method", "sink_receiver":
		fmt.Fprintf(&b, "  emit sink %s at %s\n", c.refForKind(m.Concept, "sink"), v2SinkLocation(m))
		c.writeIssueMirrorEmit(&b, m.Concept, "call")
	case "filter_path", "filter_method":
		fmt.Fprintf(&b, "  emit check %s at call {\n", c.refForKind("threat.CharFilter", "check"))
		fmt.Fprintf(&b, "    covers path {\n")
		fmt.Fprintf(&b, "      from: call\n")
		fmt.Fprintf(&b, "      to: call\n")
		fmt.Fprintf(&b, "    }\n")
		fmt.Fprintf(&b, "  }\n")
		c.record(adapter, "filter", "v1 always-global character filter converted to v2 CharFilter check", true, "threat.CharFilter")
	case "control", "control_method":
		fmt.Fprintf(&b, "  emit check %s at call {\n", c.refForKind(m.Concept, "check"))
		fmt.Fprintf(&b, "    covers path {\n")
		fmt.Fprintf(&b, "      from: call\n")
		fmt.Fprintf(&b, "      to: call\n")
		fmt.Fprintf(&b, "    }\n")
		fmt.Fprintf(&b, "  }\n")
		c.writeIssueMirrorEmit(&b, m.Concept, "call")
		c.record(adapter, "control", "suggested path coverage for v1 control; review coverage mode and anchors", true, "covers path")
	case "control_receiver_method":
		fmt.Fprintf(&b, "  emit check %s at callee.receiver {\n", c.refForKind(m.Concept, "check"))
		fmt.Fprintf(&b, "    covers sameReceiver {\n")
		fmt.Fprintf(&b, "      anchor: callee.receiver\n")
		fmt.Fprintf(&b, "    }\n")
		fmt.Fprintf(&b, "  }\n")
		c.writeIssueMirrorEmit(&b, m.Concept, "call")
		c.record(adapter, "control_receiver_method", "v1 receiver method control converted to v2 sameReceiver check", true, "sameReceiver check")
	case "mark", "mark_method":
		fmt.Fprintf(&b, "  emit issue %s at call\n", c.refForKind(m.Concept, "issue"))
		c.writeAliasEmits(&b, m.Concept, "call")
		c.record(adapter, "mark", "v1 mark converted to v2 issue; confirm concept kind is issue", true, "emit issue")
	case "flag":
		fmt.Fprintf(&b, "  emit issue %s at call\n", c.refForKind(m.Concept, "issue"))
		c.writeAliasEmits(&b, m.Concept, "call")
		c.record(adapter, "flag", "v1 flag converted to v2 issue; confirm concept kind and pattern family", true, "emit issue")
	case "assume_guard_path", "assume_guard_method", "assume_sanitizer_path", "assume_sanitizer_method":
		fmt.Fprintf(&b, "  emit check %s at call {\n", c.refForKind("core.Assumption", "check"))
		fmt.Fprintf(&b, "    advisory: true\n")
		fmt.Fprintf(&b, "    about: %s\n", m.About)
		mode := "path"
		if strings.Contains(m.Kind, "guard") {
			mode = "dominates"
		}
		fmt.Fprintf(&b, "    covers %s {\n", mode)
		fmt.Fprintf(&b, "      from: call\n")
		fmt.Fprintf(&b, "      to: call\n")
		fmt.Fprintf(&b, "    }\n")
		fmt.Fprintf(&b, "  }\n")
		c.record(adapter, "assume", "v1 assume converted to advisory core.Assumption check; review coverage/about semantics", true, "advisory check")
	}
	fmt.Fprintf(&b, "}\n")
	return b.String(), true
}

func unsupportedAdapterMappingReason(m AdapterMapping) string {
	switch {
	case m.Flag != nil:
		if _, ok := v2SimpleFlagPredicate(m); ok {
			return ""
		}
		if _, ok := v2CallValueFlagPredicate(m); ok {
			return ""
		}
		return "flag predicates require reviewed stable v2 patterns/matchers"
	case m.Kind == "flow_prefix":
		return "adapter flow prefix requires native v2 prefix query support"
	case strings.HasPrefix(m.Kind, "flow"):
		return ""
	case strings.HasPrefix(m.Kind, "assume"):
		if strings.HasPrefix(m.Pattern, "analysis.") {
			return "analysis-derived assumptions require stable v2 facts"
		}
		return ""
	case strings.HasPrefix(m.Kind, "filter"):
		return ""
	}
	switch m.Kind {
	case "source", "source_method", "source_receiver", "source_param", "sink_path", "sink_method", "sink_receiver", "filter_path", "filter_method", "control", "control_method", "control_receiver_method", "mark", "mark_method", "flag", "type",
		"flow_path", "flow_method",
		"assume_guard_path", "assume_guard_method", "assume_sanitizer_path", "assume_sanitizer_method":
		return ""
	default:
		return "unsupported adapter mapping kind"
	}
}

func (c *v2Migrator) addFile(name, module, src string) {
	c.files = append(c.files, V2MigrationFile{
		PathHint: v2PathHint(name),
		Module:   module,
		Source:   src,
	})
}

func (c *v2Migrator) withModule(module, body string) string {
	return "module " + v2ModuleOrDefault(module, "migration") + ";\n\n" + body
}

func (c *v2Migrator) todoFile(module, name, reason string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "module %s;\n\n", v2ModuleOrDefault(module, "migration"))
	fmt.Fprintf(&b, "// TODO(v2Migrate): %s\n", reason)
	fmt.Fprintf(&b, "TODO_v2Migrate %s;\n", v2Ident(name))
	return b.String()
}

func (c *v2Migrator) record(decl, construct, reason string, resolved bool, suggestion string) {
	hit := c.source.locate(decl, construct)
	c.ledger = append(c.ledger, V2MigrationRecord{
		File:        c.file,
		Line:        hit.line,
		Declaration: decl,
		Construct:   construct,
		Original:    hit.original,
		Reason:      reason,
		Resolved:    resolved,
		Suggestion:  suggestion,
	})
}

func (c *v2Migrator) refForKind(concept, kind string) string {
	if aliases := c.kindPlan.Aliases[concept]; aliases != nil {
		if alias := aliases[kind]; alias != "" {
			return alias
		}
	}
	return concept
}

func (c *v2Migrator) writeAliasEmits(b *strings.Builder, concept, location string) {
	aliases := c.kindPlan.Aliases[concept]
	for _, kind := range []string{"source", "sink", "check"} {
		alias := aliases[kind]
		if alias == "" {
			continue
		}
		loc := location
		if kind == "source" && location == "call" {
			loc = "call.result"
		}
		fmt.Fprintf(b, "  emit %s %s at %s\n", kind, alias, loc)
		c.record(concept, "concept kind alias emit", "v1 emitted concept also feeds "+kind+" semantics; generated typed alias "+alias, true, "emit "+kind)
	}
}

func (c *v2Migrator) writeIssueMirrorEmit(b *strings.Builder, concept, location string) {
	if !c.kindPlan.IssueMirrors[concept] {
		return
	}
	if c.kindPlan.ConceptKinds[concept] != "issue" {
		return
	}
	if c.refForKind(concept, "issue") != concept {
		return
	}
	fmt.Fprintf(b, "  emit issue %s at %s\n", concept, location)
	c.record(concept, "concept kind issue mirror emit", "v1 endpoint/check mapping also fed match semantics; preserved original issue label", true, "emit issue")
}

func v2MigrationModuleSuffix(file string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(file))
	return fmt.Sprintf("m%08x", h.Sum32())
}

func v2RuntimeTypeFactConcept() string {
	return "runtime." + "Receiver" + "Type"
}

func (c *v2Migrator) unresolved(decl, construct, reason, suggestion string) {
	c.record(decl, construct, reason, false, suggestion)
}

func writeV2PackageRequires(b *strings.Builder, pkgs []string) {
	if len(pkgs) == 0 {
		return
	}
	fmt.Fprintf(b, "  requires {\n")
	if len(pkgs) == 1 {
		fmt.Fprintf(b, "    dependency(%q)\n", pkgs[0])
		fmt.Fprintf(b, "  }\n")
		return
	}
	fmt.Fprintf(b, "    any(")
	for i, pkg := range pkgs {
		if i > 0 {
			fmt.Fprintf(b, ", ")
		}
		fmt.Fprintf(b, "dependency(%q)", pkg)
	}
	fmt.Fprintf(b, ")\n")
	fmt.Fprintf(b, "  }\n")
}

func v2AdapterPredicate(m AdapterMapping) string {
	if pred, ok := v2SimpleFlagPredicate(m); ok {
		return pred
	}
	field := "callee.path"
	op := "~="
	if strings.Contains(m.Kind, "method") || strings.Contains(m.Kind, "receiver") {
		field = "callee.method"
		op = "=="
	} else if m.Exact {
		op = "=="
	}
	parts := []string{fmt.Sprintf("%s %s %q", field, op, m.Pattern)}
	for _, v := range m.ValMatches {
		parts = append(parts, fmt.Sprintf("args.any.literal contains %q", v))
	}
	for _, v := range m.ValAbsents {
		parts = append(parts, fmt.Sprintf("not args.any.literal contains %q", v))
	}
	if strings.HasPrefix(m.Kind, "filter") && m.Constraint == "global" {
		parts = append(parts, "call.filter.global == true")
	} else if m.Constraint != "" {
		parts = append(parts, v2ReceiverConstraintPredicate(m.Constraint))
	}
	return strings.Join(parts, " and ")
}

func v2ReceiverConstraintPredicate(constraint string) string {
	parts := strings.Split(constraint, ",")
	if len(parts) == 1 {
		return fmt.Sprintf("callee.receiver.type == %q", strings.TrimSpace(parts[0]))
	}
	var values []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			values = append(values, p)
		}
	}
	return "callee.receiver.type in " + v2FieldValue(values)
}

func v2SimpleFlagPredicate(m AdapterMapping) (string, bool) {
	if m.Flag == nil || len(m.Flag.Operands) != 0 || len(m.Flag.Predicates) != 1 {
		return "", false
	}
	p := m.Flag.Predicates[0]
	if p.Subject != "node" || p.Negative || len(p.Values) != 1 {
		return "", false
	}
	value := p.Values[0]
	switch p.Property {
	case "method":
		if p.Op != "equals" {
			return "", false
		}
		return fmt.Sprintf("callee.method == %q", value), true
	case "path":
		if p.Op != "match" || strings.HasPrefix(value, "analysis.") {
			return "", false
		}
		op := "~="
		if p.Exact {
			op = "=="
		}
		return fmt.Sprintf("callee.path %s %q", op, value), true
	default:
		return "", false
	}
}

func v2CallValueFlagPredicate(m AdapterMapping) (string, bool) {
	if m.Flag == nil || len(m.Flag.Operands) != 0 || m.Flag.Scope != "" {
		return "", false
	}
	kind := m.Flag.NodeKind
	if kind == "" {
		kind = "any"
	}
	if kind != "any" && kind != "call" {
		return "", false
	}
	var callee string
	var vals []string
	var nvals []string
	for _, p := range m.Flag.Predicates {
		if p.Subject != "node" || len(p.Values) != 1 {
			return "", false
		}
		value := p.Values[0]
		switch p.Property {
		case "path":
			if p.Negative || p.Op != "match" || strings.HasPrefix(value, "analysis.") || callee != "" {
				return "", false
			}
			op := "~="
			if p.Exact {
				op = "=="
			}
			callee = fmt.Sprintf("callee.path %s %q", op, value)
		case "method":
			if p.Negative || p.Op != "equals" || callee != "" {
				return "", false
			}
			callee = fmt.Sprintf("callee.method == %q", value)
		case "tokens":
			value, ok := v2CallValueFlagLiteral(value)
			if p.Op != "contains" || !ok {
				return "", false
			}
			if p.Negative {
				nvals = append(nvals, value)
			} else {
				vals = append(vals, value)
			}
		default:
			return "", false
		}
	}
	if callee == "" || len(vals)+len(nvals) == 0 {
		return "", false
	}
	parts := []string{callee}
	for _, v := range vals {
		parts = append(parts, fmt.Sprintf("args.any.literal contains %q", v))
	}
	for _, v := range nvals {
		parts = append(parts, fmt.Sprintf("not args.any.literal contains %q", v))
	}
	return strings.Join(parts, " and "), true
}

func v2CallValueFlagLiteral(value string) (string, bool) {
	if literal, ok := strings.CutPrefix(value, "literal:"); ok {
		if literal != "" && !strings.ContainsAny(literal, ":=") {
			return literal, true
		}
		return "", false
	}
	return "", false
}

func v2LegacyFlagPredicate(m AdapterMapping) (string, bool) {
	if m.Flag == nil {
		return "", false
	}
	var parts []string
	if m.Flag.Scope != "" {
		parts = append(parts, fmt.Sprintf("node.scope == %q", m.Flag.Scope))
	} else {
		kind := m.Flag.NodeKind
		if kind == "" {
			kind = "any"
		}
		parts = append(parts, fmt.Sprintf("node.kind == %q", kind))
	}
	for _, pred := range m.Flag.Predicates {
		expr, ok := v2LegacyFlagPredicateAtom(pred)
		if !ok {
			return "", false
		}
		parts = append(parts, expr)
	}
	for _, operand := range m.Flag.Operands {
		var opParts []string
		for _, pred := range operand.Predicates {
			expr, ok := v2LegacyFlagPredicateAtom(pred)
			if !ok {
				return "", false
			}
			opParts = append(opParts, expr)
		}
		if len(opParts) == 0 {
			return "", false
		}
		parts = append(parts, fmt.Sprintf("operand(node, where: %s)", strings.Join(opParts, " and ")))
	}
	return strings.Join(parts, " and "), true
}

func v2LegacyFlagPredicateAtom(pred AdapterFlagPredicate) (string, bool) {
	field, ok := v2LegacyFlagPredicateField(pred)
	if !ok {
		return "", false
	}
	switch pred.Property {
	case "path":
		if pred.Op != "match" || len(pred.Values) != 1 {
			return "", false
		}
		op := "~="
		if pred.Exact {
			op = "=="
		}
		atom := fmt.Sprintf("%s %s %q", field, op, pred.Values[0])
		if pred.Negative {
			return "not (" + atom + ")", true
		}
		return atom, true
	case "method":
		if pred.Op != "equals" || len(pred.Values) != 1 {
			return "", false
		}
	}
	atom, ok := v2LegacyFlagValueAtom(field, pred.Op, pred.Values)
	if !ok {
		return "", false
	}
	if pred.Negative {
		return "not (" + atom + ")", true
	}
	return atom, true
}

func v2LegacyFlagPredicateField(pred AdapterFlagPredicate) (string, bool) {
	base := ""
	switch pred.Subject {
	case "node":
		base = "node"
	case "operand":
		base = "operand"
	case "scope_call":
		base = "node.scopeCall"
	case "flow_to":
		base = "node.flowTo"
	default:
		return "", false
	}
	switch pred.Property {
	case "path":
		return base + ".path", true
	case "method":
		return base + ".method", true
	case "tokens":
		return base + ".token", true
	case "op", "identifier", "key", "any":
		return base + "." + pred.Property, true
	default:
		return base + ".prop." + pred.Property, true
	}
}

func v2LegacyFlagValueAtom(field, op string, values []string) (string, bool) {
	switch op {
	case "contains":
		if len(values) != 1 {
			return "", false
		}
		return fmt.Sprintf("%s contains %q", field, values[0]), true
	case "equals":
		if len(values) != 1 {
			return "", false
		}
		return fmt.Sprintf("%s == %q", field, values[0]), true
	case "contains_any":
		return fmt.Sprintf("containsAny(%s, %s)", field, v2FieldValue(values)), true
	case "equals_any":
		return fmt.Sprintf("%s in %s", field, v2FieldValue(values)), true
	default:
		return "", false
	}
}

func v2Alias(alias string) string {
	if alias == "" {
		return ""
	}
	return " as " + alias
}

func v2SinkLocation(m AdapterMapping) string {
	if m.Kind == "sink_receiver" {
		return "callee.receiver"
	}
	base := ""
	if m.ArgIndex < 0 {
		base = "args.any"
	} else {
		base = fmt.Sprintf("args[%d]", m.ArgIndex)
	}
	if m.CollectionFirst {
		return fmt.Sprintf("%s.collection[%d]", base, m.CollectionIndex)
	}
	if m.Collection {
		return base + ".collection"
	}
	return base
}

func v2RuleAliasOrDefault(alias, fallback string) string {
	if alias != "" {
		return alias
	}
	return fallback
}

func v2RuleCoverageTarget(body Stmt, mode string) string {
	switch x := body.(type) {
	case *FlowStmt:
		if x.Dst.Binding != "" {
			return x.Dst.Binding + "." + mode
		}
	case *MatchStmt:
		if x.Binding != "" {
			return x.Binding + "." + mode
		}
	}
	return mode
}

func v2RuleWhereExpr(expr Expr) (string, bool) {
	switch x := expr.(type) {
	case Ref:
		return x.String(), true
	case And:
		parts := make([]string, 0, len(x.Parts))
		for _, part := range x.Parts {
			s, ok := v2RuleWhereExpr(part)
			if !ok {
				return "", false
			}
			parts = append(parts, s)
		}
		return strings.Join(parts, " and "), true
	case Not:
		inner, ok := v2RuleWhereExpr(x.Inner)
		if !ok {
			return "", false
		}
		if _, nested := x.Inner.(And); nested {
			inner = "(" + inner + ")"
		}
		return "not " + inner, true
	case SolverCall:
		args := make([]string, 0, len(x.Args))
		for _, arg := range x.Args {
			if arg.Binding != "" {
				return "", false
			}
			s := arg.Ref.String()
			args = append(args, s)
		}
		out := fmt.Sprintf("%s(%s)", x.Verb, strings.Join(args, ", "))
		if x.Binding != "" {
			return "", false
		}
		return out, true
	case HoldsAssetKind:
		return fmt.Sprintf("holdsAssetKind(%s, %s)", x.Ref.String(), v2FieldValue(x.Kinds)), true
	case Has:
		return fmt.Sprintf("has(%s, %s)", x.Ref.String(), x.Concept), true
	case Is:
		return fmt.Sprintf("%s is %s", x.Ref.String(), x.Concept), true
	case Cmp:
		return fmt.Sprintf("%s %s %s", x.Ref.String(), x.Op, v2FieldValue(x.Value)), true
	case NotIn:
		op := "not in"
		if !x.Negate {
			op = "in"
		}
		return fmt.Sprintf("%s %s %s", x.Ref.String(), op, v2FieldValue(x.Values)), true
	default:
		return "", false
	}
}

func writeV2Fields(b *strings.Builder, fields map[string]any) {
	writeV2FieldsIndented(b, fields, "  ")
}

func writeV2FieldsIndented(b *strings.Builder, fields map[string]any, indent string) {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(b, "%s%s: %s\n", indent, v2FieldName(k), v2FieldValue(fields[k]))
	}
}

func v2FieldName(name string) string {
	switch name {
	case "vulnerable_to":
		return "vulnerableTo"
	case "enabled_by":
		return "enabledBy"
	case "confidence_floor":
		return "confidenceFloor"
	case "source_policy":
		return "sourcePolicy"
	case "review_category":
		return "reviewCategory"
	case "review_condition":
		return "reviewCondition"
	case "review_evidence":
		return "reviewEvidence"
	case "review_confidence":
		return "reviewConfidence"
	default:
		return name
	}
}

func v2ConceptKind(kind string) string {
	switch kind {
	case "control":
		return "check"
	case "action", "observation", "indicator":
		return "fact"
	}
	return kind
}

func v2FieldValue(v any) string {
	switch x := v.(type) {
	case string:
		if isV2BareValue(x) {
			return x
		}
		return strconv.Quote(x)
	case bool:
		if x {
			return "true"
		}
		return "false"
	case int:
		return strconv.Itoa(x)
	case []string:
		parts := make([]string, 0, len(x))
		for _, s := range x {
			if isV2BareValue(s) {
				parts = append(parts, s)
			} else {
				parts = append(parts, strconv.Quote(s))
			}
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case []any:
		parts := make([]string, 0, len(x))
		for _, v := range x {
			parts = append(parts, v2FieldValue(v))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		var b strings.Builder
		b.WriteString("{\n")
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "      %s: %s\n", v2FieldName(k), v2FieldValue(x[k]))
		}
		b.WriteString("    }")
		return b.String()
	default:
		return strconv.Quote(fmt.Sprint(v))
	}
}

func v2MetadataValue(v any) string {
	switch x := v.(type) {
	case string:
		return strconv.Quote(x)
	case bool:
		if x {
			return "true"
		}
		return "false"
	case int:
		return strconv.Itoa(x)
	case []string:
		parts := make([]string, 0, len(x))
		for _, s := range x {
			parts = append(parts, strconv.Quote(s))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case []any:
		parts := make([]string, 0, len(x))
		for _, v := range x {
			parts = append(parts, v2MetadataValue(v))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		var b strings.Builder
		b.WriteString("{\n")
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "      %s: %s\n", v2FieldName(k), v2MetadataValue(x[k]))
		}
		b.WriteString("    }")
		return b.String()
	default:
		return strconv.Quote(fmt.Sprint(v))
	}
}

func isV2BareValue(s string) bool {
	if s == "" {
		return false
	}
	first := s[0]
	if first != '_' && (first < 'a' || first > 'z') && (first < 'A' || first > 'Z') {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' || c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

func v2ModuleForRef(ref string) string {
	if i := strings.LastIndex(ref, "."); i > 0 {
		return ref[:i]
	}
	return "migration"
}

func v2ModuleOrDefault(module, fallback string) string {
	if module != "" {
		return module
	}
	return fallback
}

func v2ShortName(name string) string {
	return lastSeg(name)
}

func v2PathHint(name string) string {
	name = strings.Trim(name, ".")
	if name == "" {
		name = "migration"
	}
	return strings.ReplaceAll(name, ".", "/") + ".vyql"
}

func v2Ident(s string) string {
	var b strings.Builder
	upperNext := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !ok {
			upperNext = b.Len() > 0
			continue
		}
		if b.Len() == 0 && c >= '0' && c <= '9' {
			b.WriteByte('X')
		}
		if upperNext && c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		b.WriteByte(c)
		upperNext = false
	}
	return b.String()
}
