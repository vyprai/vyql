// Package ontology is the VyQL security ontology + type system (docs/06),
// ported from poc/vyql/ontology.py. Controls declare which threat kinds they
// neutralize; sinks declare what they are vulnerable to; sources declare their
// taint kinds. The type checker uses these to reject ill-typed rules at compile
// time — the ontology "paying rent".
package ontology

import (
	"fmt"
	"sort"
)

// Concept is the unit of the controlled vocabulary. Loaded from
// data/concepts.json. Names are SHORT (PascalCase) within a `package`
// namespace; the qualified id is `<package>.<Name>` (e.g. code.HttpInput).
// Cross-package references (Refines/VulnerableTo/…) are written qualified.
type Concept struct {
	Name                    string   `json:"name"`                    // short PascalCase
	Package                 string   `json:"package"`                 // namespace (e.g. code, core, cloud)
	Kind                    string   `json:"kind"`                    // source|sink|control|asset|privilege|principal|exposure|action|state
	Taint                   []string `json:"taint,omitempty"`         // for sources (taint kinds, qualified)
	VulnerableTo            []string `json:"vulnerable_to,omitempty"` // for sinks (threat kinds, qualified)
	Neutralizes             []string `json:"neutralizes,omitempty"`   // for controls (threat kinds, qualified)
	Applies                 string   `json:"applies,omitempty"`       // control: path|endpoint|scope
	Refines                 string   `json:"refines,omitempty"`       // single-parent specialization (qualified)
	EnabledBy               []string `json:"enabled_by,omitempty"`    // for sinks: taint kinds that arm it (qualified)
	CWE                     []string `json:"cwe,omitempty"`           // mapped weakness ids (CWE_89)
	CAPEC                   []string `json:"capec,omitempty"`         // mapped attack-pattern ids (CAPEC_66)
	Attack                  []string `json:"attack,omitempty"`        // MITRE ATT&CK technique ids
	Aliases                 []string `json:"aliases,omitempty"`
	Deprecated              string   `json:"deprecated,omitempty"`
	Possibility             string   `json:"possibility,omitempty"` // possibility pass policy: include|exclude
	ReviewCategory          string   `json:"review_category,omitempty"`
	ReviewCondition         string   `json:"review_condition,omitempty"`
	ReviewEvidence          string   `json:"review_evidence,omitempty"`
	ReviewAssumption        string   `json:"review_assumption,omitempty"`
	ReviewConfidence        string   `json:"review_confidence,omitempty"`
	SourcePolicy            string   `json:"source_policy,omitempty"` // source review policy: direct|caller_conditional
	SourceConditionCategory string   `json:"source_condition_category,omitempty"`
	SourceCondition         string   `json:"source_condition,omitempty"`
	SourceAssumption        string   `json:"source_assumption,omitempty"`
	SourceConfidence        string   `json:"source_confidence,omitempty"`
	AssumeMinLevel          string   `json:"assume_min_level,omitempty"`
	AnalysisRole            string   `json:"analysis_role,omitempty"`
	ContextReachSource      string   `json:"context_reach_source,omitempty"`
	ContextReachLabel       string   `json:"context_reach_label,omitempty"`
	ContextReachTargetProp  string   `json:"context_reach_target_prop,omitempty"`
	ContextAssetTargetProp  string   `json:"context_asset_target_prop,omitempty"`
	ContextAssetLabel       string   `json:"context_asset_label,omitempty"`
	ContextConfirmDstProp   string   `json:"context_confirm_dst_prop,omitempty"`
	ContextConfirmFlagProp  string   `json:"context_confirm_flag_prop,omitempty"`
	ContextConfirmFlagValue string   `json:"context_confirm_flag_value,omitempty"`
	ContextConfirmLabel     string   `json:"context_confirm_label,omitempty"`
	// ExcludedChars: for sinks, the characters that MUST be absent for taint to be
	// neutralized — lets a character-filter (allowlist replace) be proven a sound
	// sanitizer when its output alphabet excludes all of them.
	ExcludedChars string `json:"excluded_chars,omitempty"`
}

const (
	AnalysisRoleAttributeSink         = "attribute_sink"
	AnalysisRoleCharFilter            = "char_filter"
	AnalysisRoleDomInput              = "dom_input"
	AnalysisRoleNeutralizerAssumption = "neutralizer_assumption"
	AnalysisRolePathAccessCheck       = "path_access_check"
	AnalysisRoleProcessArgVector      = "process_arg_vector"
)

// QualifiedName returns the namespaced id `<package>.<Name>`.
func (c Concept) QualifiedName() string {
	if c.Package == "" {
		return c.Name
	}
	return c.Package + "." + c.Name
}

// Ontology holds concepts + an alias index.
type Ontology struct {
	concepts map[string]*Concept
	alias    map[string]string // alias -> canonical
}

func New() *Ontology {
	return &Ontology{concepts: map[string]*Concept{}, alias: map[string]string{}}
}

func (o *Ontology) Add(c Concept) *Concept {
	if c.Kind == "control" && c.Applies == "" {
		c.Applies = "path"
	}
	cp := c
	q := cp.QualifiedName()
	o.concepts[q] = &cp
	for _, a := range c.Aliases {
		o.alias[a] = q
	}
	return &cp
}

// AllConcepts returns all concepts sorted by qualified name.
func (o *Ontology) AllConcepts() []Concept {
	out := make([]Concept, 0, len(o.concepts))
	for _, c := range o.concepts {
		out = append(out, *c)
	}
	sortConcepts(out)
	return out
}

// ConceptsWithAnalysisRole returns the concepts tagged for an internal engine
// role. The role names are generic mechanics; the concrete concept identities
// live in ontology data.
func (o *Ontology) ConceptsWithAnalysisRole(role string) map[string]bool {
	out := map[string]bool{}
	if role == "" {
		return out
	}
	for _, c := range o.concepts {
		if c.AnalysisRole == role {
			out[c.QualifiedName()] = true
		}
	}
	return out
}

// SingleConceptWithAnalysisRole returns the sole concept tagged for role.
func (o *Ontology) SingleConceptWithAnalysisRole(role string) string {
	concepts := o.ConceptsWithAnalysisRole(role)
	var out string
	for c := range concepts {
		if out != "" {
			return ""
		}
		out = c
	}
	return out
}

// Alias registers alternative names for an existing concept (rename support).
func (o *Ontology) Alias(canonical string, names ...string) {
	for _, a := range names {
		o.alias[a] = canonical
	}
}

// Deprecate marks a concept deprecated with a note.
func (o *Ontology) Deprecate(name, note string) {
	if c, ok := o.concepts[o.Canonical(name)]; ok {
		c.Deprecated = note
	}
}

// Canonical maps an alias to its canonical name (identity if not an alias).
func (o *Ontology) Canonical(name string) string {
	if c, ok := o.alias[name]; ok {
		return c
	}
	return name
}

func (o *Ontology) Exists(name string) bool {
	_, ok := o.concepts[o.Canonical(name)]
	return ok
}

// Get returns the canonical concept, or an error if unknown.
func (o *Ontology) Get(name string) (*Concept, error) {
	if c, ok := o.concepts[o.Canonical(name)]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("unknown concept '%s' (not in ontology)", name)
}

func (o *Ontology) MustGet(name string) *Concept {
	c, err := o.Get(name)
	if err != nil {
		panic(err)
	}
	return c
}

// DeprecationWarning returns a warning if name is an alias and/or deprecated.
func (o *Ontology) DeprecationWarning(name string) string {
	canon := o.Canonical(name)
	c, ok := o.concepts[canon]
	if !ok {
		return ""
	}
	var msgs []string
	if name != canon {
		msgs = append(msgs, fmt.Sprintf("'%s' is an alias of '%s'", name, canon))
	}
	if c.Deprecated != "" {
		msgs = append(msgs, fmt.Sprintf("'%s' is deprecated: %s", canon, c.Deprecated))
	}
	return join(msgs, "; ")
}

// Descendants returns a concept and all concepts that (transitively) refine it.
// Matching a parent concept matches all refinements (downward-closed).
func (o *Ontology) Descendants(name string) map[string]bool {
	name = o.Canonical(name)
	out := map[string]bool{name: true}
	for changed := true; changed; {
		changed = false
		for _, c := range o.concepts {
			q := c.QualifiedName()
			if c.Refines != "" && out[c.Refines] && !out[q] {
				out[q] = true
				changed = true
			}
		}
	}
	return out
}

// --- typing predicates ---------------------------------------------------

func (o *Ontology) SinkThreats(sink string) []string     { return o.field(sink, "vulnerable_to") }
func (o *Ontology) ControlNeutralizes(c string) []string { return o.field(c, "neutralizes") }
func (o *Ontology) SourceTaints(s string) []string       { return o.field(s, "taint") }
func (o *Ontology) SinkArmedBy(sink string) []string     { return o.field(sink, "enabled_by") }

func (o *Ontology) field(name, which string) []string {
	c, err := o.Get(name)
	if err != nil {
		return nil
	}
	switch which {
	case "vulnerable_to":
		return c.VulnerableTo
	case "neutralizes":
		return c.Neutralizes
	case "taint":
		return c.Taint
	case "enabled_by":
		return c.EnabledBy
	}
	return nil
}

// CheckSanitizerTyping returns the neutralized threat kind if
// `unless sanitized_by control` is well-typed for `taint source -> sink`, else
// an error. This makes `taint HTTP_INPUT -> SQL_EXECUTION unless sanitized_by
// HTML_ESCAPE` a compile error (docs/06).
func (o *Ontology) CheckSanitizerTyping(source, sink, control string) (string, error) {
	sinkThreats := set(o.SinkThreats(sink))
	neutralized := set(o.ControlNeutralizes(control))
	armed := set(o.SinkArmedBy(sink))
	srcTaints := set(o.SourceTaints(source))

	common := intersect(sinkThreats, neutralized)
	if len(common) == 0 {
		return "", fmt.Errorf("control '%s' neutralizes %v but sink '%s' is vulnerable to %v — "+
			"no overlap. This sanitizer does not defend this sink.",
			control, sortedKeys(neutralized), sink, sortedKeys(sinkThreats))
	}
	if len(armed) > 0 && len(intersect(srcTaints, armed)) == 0 {
		return "", fmt.Errorf("source '%s' carries taint %v but sink '%s' is only armed by %v — "+
			"source taint kind does not arm this sink.",
			source, sortedKeys(srcTaints), sink, sortedKeys(armed))
	}
	c := sortedKeys(common)
	return c[0], nil
}

// --- small set helpers ---------------------------------------------------

func set(xs []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func intersect(a, b map[string]bool) map[string]bool {
	m := map[string]bool{}
	for x := range a {
		if b[x] {
			m[x] = true
		}
	}
	return m
}

func sortConcepts(cs []Concept) {
	sort.Slice(cs, func(i, j int) bool { return cs[i].QualifiedName() < cs[j].QualifiedName() })
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func join(xs []string, sep string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += sep
		}
		out += x
	}
	return out
}
