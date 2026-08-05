// Package resultpolicy loads v2 result policies and applies them to scanner
// outputs. Go supplies the primitive field extraction; VyQL content owns the
// identity key shape.
package resultpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/findings"
	"github.com/vyprai/vyql/internal/parser"
)

type IdentityPolicy struct {
	FindingKey   []string
	FlagKey      []string
	Fingerprint  []string
	StableAcross []string
}

type FlagIdentity struct {
	Concept    string
	Location   string
	CallPath   string
	CallMethod string
	NodeID     string
}

var (
	identityOnce sync.Once
	identityCfg  IdentityPolicy
	identityErr  error
)

func DefaultIdentity() (IdentityPolicy, error) {
	identityOnce.Do(func() {
		identityCfg, identityErr = loadIdentityPolicy()
	})
	return identityCfg, identityErr
}

func MustDefaultIdentity() IdentityPolicy {
	p, err := DefaultIdentity()
	if err != nil {
		panic("resultpolicy: invalid policy resultIdentity default: " + err.Error())
	}
	return p
}

func Fingerprint(f *findings.Finding) string {
	return MustDefaultIdentity().FingerprintFinding(f)
}

func Dedup(fs []*findings.Finding) []*findings.Finding {
	return MustDefaultIdentity().Dedup(fs)
}

func (p IdentityPolicy) Dedup(fs []*findings.Finding) []*findings.Finding {
	byKey := map[string]*findings.Finding{}
	keys := make([]string, 0, len(fs))
	for _, f := range fs {
		key := p.FindingKeyFor(f)
		if existing, ok := byKey[key]; ok {
			if compareFindingsForDedup(f, existing) < 0 {
				byKey[key] = f
			}
			continue
		}
		byKey[key] = f
		keys = append(keys, key)
	}
	sortStringsLinear(keys)
	out := make([]*findings.Finding, 0, len(keys))
	for _, key := range keys {
		out = append(out, byKey[key])
	}
	return out
}

func sortStringsLinear(xs []string) {
	if len(xs) < 2 {
		return
	}
	aux := make([]string, len(xs))
	msdStringSort(xs, aux, 0, len(xs), 0)
}

func msdStringSort(xs, aux []string, lo, hi, depth int) {
	if hi-lo < 2 {
		return
	}
	var count [258]int
	for i := lo; i < hi; i++ {
		count[stringRadixAt(xs[i], depth)+1]++
	}
	for r := 0; r < 257; r++ {
		count[r+1] += count[r]
	}
	next := count
	for i := lo; i < hi; i++ {
		c := stringRadixAt(xs[i], depth)
		aux[next[c]] = xs[i]
		next[c]++
	}
	copy(xs[lo:hi], aux[:hi-lo])
	for c := 1; c <= 256; c++ {
		start := lo + count[c]
		end := lo + count[c+1]
		if end-start > 1 {
			msdStringSort(xs, aux, start, end, depth+1)
		}
	}
}

func stringRadixAt(s string, depth int) int {
	if depth >= len(s) {
		return 0
	}
	return int(s[depth]) + 1
}

func compareFindingsForDedup(a, b *findings.Finding) int {
	if a == b {
		return 0
	}
	as := findingDedupSortKey(a)
	bs := findingDedupSortKey(b)
	if as < bs {
		return -1
	}
	if as > bs {
		return 1
	}
	return 0
}

func findingDedupSortKey(f *findings.Finding) string {
	if f == nil {
		return "9"
	}
	target := primaryTarget(f)
	return fmt.Sprintf("%02d|%02d|%06d|%06d|%s|%s|%s|%s|%s",
		99-ConfidenceRank(f.Confidence),
		99-SeverityRank(f.Severity),
		999999-len(f.Witness),
		999999-len(f.Context)-len(f.ReviewConditions),
		f.RuleID,
		target.Loc,
		target.Concept,
		target.NodeID,
		bindingsStableKey(f.Bindings),
	)
}

func bindingsStableKey(bindings []findings.Binding) string {
	parts := make([]string, 0, len(bindings))
	for _, b := range bindings {
		parts = append(parts, b.Name+"="+b.Concept+"@"+b.Loc+"#"+b.NodeID)
	}
	return strings.Join(parts, ";")
}

func (p IdentityPolicy) FindingKeyFor(f *findings.Finding) string {
	return p.joinFindingFields(p.FindingKey, f)
}

func (p IdentityPolicy) FlagKeyFor(flag FlagIdentity) string {
	parts := make([]string, 0, len(p.FlagKey))
	for _, field := range p.FlagKey {
		parts = append(parts, field+"="+flagField(flag, field))
	}
	return strings.Join(parts, "|")
}

func (p IdentityPolicy) FingerprintFinding(f *findings.Finding) string {
	parts := p.Fingerprint
	if len(parts) == 0 {
		parts = p.FindingKey
	}
	sum := sha256.Sum256([]byte(p.joinFindingFields(parts, f)))
	return hex.EncodeToString(sum[:])[:16]
}

func (p IdentityPolicy) joinFindingFields(fields []string, f *findings.Finding) string {
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		parts = append(parts, field+"="+findingField(f, field))
	}
	return strings.Join(parts, "|")
}

func flagField(flag FlagIdentity, field string) string {
	switch field {
	case "concept":
		return flag.Concept
	case "location":
		return flag.Location
	case "call.path":
		return flag.CallPath
	case "call.method":
		return flag.CallMethod
	case "nodeID":
		return flag.NodeID
	default:
		return ""
	}
}

func findingField(f *findings.Finding, field string) string {
	if f == nil {
		return ""
	}
	target := primaryTarget(f)
	switch field {
	case "rule.id", "rule":
		return f.RuleID
	case "primaryTarget.location", "target.location", "location":
		return target.Loc
	case "primaryTarget.concept", "target.concept", "concept":
		return target.Concept
	case "primaryTarget.nodeID", "target.nodeID", "nodeID":
		return target.NodeID
	case "primaryTarget.binding", "target.binding":
		return target.Name
	default:
		return ""
	}
}

func primaryTarget(f *findings.Finding) findings.Binding {
	for _, b := range f.Bindings {
		if b.Name == "sink" || b.Name == "target" {
			return b
		}
	}
	if len(f.Bindings) > 0 {
		return f.Bindings[len(f.Bindings)-1]
	}
	return findings.Binding{}
}

func loadIdentityPolicy() (IdentityPolicy, error) {
	files, err := datadir.ReadVYQLDir("policies")
	if err != nil {
		return IdentityPolicy{}, err
	}
	raw := make([]parser.V2DefinitionSource, 0, len(files))
	for _, file := range files {
		raw = append(raw, parser.V2DefinitionSource{Name: file.Name, Source: string(file.Data)})
	}
	decls, err := parser.ParseV2DefinitionSources(raw)
	if err != nil {
		return IdentityPolicy{}, err
	}
	var policy *parser.V2PolicyDecl
	for _, decl := range decls {
		p, ok := decl.(*parser.V2PolicyDecl)
		if !ok || p.Kind != "resultIdentity" || p.Name != "default" {
			continue
		}
		if policy != nil {
			return IdentityPolicy{}, fmt.Errorf("duplicate policy resultIdentity default")
		}
		policy = p
	}
	if policy == nil {
		return IdentityPolicy{}, fmt.Errorf("missing policy resultIdentity default")
	}
	return identityPolicyFromDecl(policy)
}

func identityPolicyFromDecl(p *parser.V2PolicyDecl) (IdentityPolicy, error) {
	out := IdentityPolicy{}
	for _, item := range p.Items {
		if len(item.Key) != 1 {
			continue
		}
		values := identityPolicyStringList(item.Value)
		switch item.Key[0] {
		case "findingKey":
			out.FindingKey = values
		case "flagKey":
			out.FlagKey = values
		case "fingerprint":
			out.Fingerprint = values
		case "stableAcross":
			out.StableAcross = values
		}
	}
	if len(out.FindingKey) == 0 {
		return IdentityPolicy{}, fmt.Errorf("findingKey must be a non-empty list")
	}
	if len(out.FlagKey) == 0 {
		return IdentityPolicy{}, fmt.Errorf("flagKey must be a non-empty list")
	}
	if len(out.Fingerprint) == 0 {
		return IdentityPolicy{}, fmt.Errorf("fingerprint must be a non-empty list")
	}
	if len(out.StableAcross) == 0 {
		return IdentityPolicy{}, fmt.Errorf("stableAcross must be a non-empty list")
	}
	for _, field := range append(append([]string{}, out.FindingKey...), out.Fingerprint...) {
		if !supportedFindingIdentityField(field) {
			return IdentityPolicy{}, fmt.Errorf("unsupported finding identity field %q", field)
		}
	}
	for _, field := range out.FlagKey {
		if !supportedFlagIdentityField(field) {
			return IdentityPolicy{}, fmt.Errorf("unsupported flag identity field %q", field)
		}
	}
	return out, nil
}

func identityPolicyStringList(raw any) []string {
	xs, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func supportedFindingIdentityField(field string) bool {
	switch field {
	case "rule.id", "rule", "primaryTarget.location", "target.location", "location",
		"primaryTarget.concept", "target.concept", "concept", "primaryTarget.nodeID",
		"target.nodeID", "nodeID", "primaryTarget.binding", "target.binding":
		return true
	default:
		return false
	}
}

func supportedFlagIdentityField(field string) bool {
	switch field {
	case "concept", "location", "call.path", "call.method", "nodeID":
		return true
	default:
		return false
	}
}
