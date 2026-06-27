package resultpolicy

import (
	"fmt"
	"sync"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/parser"
)

type LifecyclePolicy struct {
	items map[string]bool
}

var (
	lifecycleOnce sync.Once
	lifecycleCfg  LifecyclePolicy
	lifecycleErr  error
)

func DefaultLifecycle() (LifecyclePolicy, error) {
	lifecycleOnce.Do(func() {
		lifecycleCfg, lifecycleErr = loadLifecyclePolicy()
	})
	return lifecycleCfg, lifecycleErr
}

func MustDefaultLifecycle() LifecyclePolicy {
	p, err := DefaultLifecycle()
	if err != nil {
		panic("resultpolicy: invalid policy resultLifecycle default: " + err.Error())
	}
	return p
}

func DefaultLifecycleContract() LifecyclePolicy {
	return LifecyclePolicy{items: map[string]bool{
		"flagWhen":      true,
		"candidateWhen": true,
		"findingWhen":   true,
		"checkWhen":     true,
	}}
}

func (p LifecyclePolicy) FlagWhenIssue(hasReview bool) bool {
	return p.has("flagWhen") && hasReview
}

func (p LifecyclePolicy) CandidateWhenMatchedRule(matched bool) bool {
	return p.has("candidateWhen") && matched
}

func (p LifecyclePolicy) FindingWhen(candidate, covered bool) bool {
	return p.has("findingWhen") && candidate && !covered
}

func (p LifecyclePolicy) CheckWhen(hasReview, explainsFinding bool) bool {
	return p.has("checkWhen") && (hasReview || explainsFinding)
}

func (p LifecyclePolicy) has(key string) bool {
	return p.items != nil && p.items[key]
}

func loadLifecyclePolicy() (LifecyclePolicy, error) {
	files, err := datadir.ReadVYQLDir("policies")
	if err != nil {
		return LifecyclePolicy{}, err
	}
	raw := make([]parser.V2DefinitionSource, 0, len(files))
	for _, file := range files {
		raw = append(raw, parser.V2DefinitionSource{Name: file.Name, Source: string(file.Data)})
	}
	decls, err := parser.ParseV2DefinitionSources(raw)
	if err != nil {
		return LifecyclePolicy{}, err
	}
	var policy *parser.V2PolicyDecl
	for _, decl := range decls {
		p, ok := decl.(*parser.V2PolicyDecl)
		if !ok || p.Kind != "resultLifecycle" || p.Name != "default" {
			continue
		}
		if policy != nil {
			return LifecyclePolicy{}, fmt.Errorf("duplicate policy resultLifecycle default")
		}
		policy = p
	}
	if policy == nil {
		return LifecyclePolicy{}, fmt.Errorf("missing policy resultLifecycle default")
	}
	return LifecyclePolicyFromDecl(policy)
}

func LifecyclePolicyFromDecl(p *parser.V2PolicyDecl) (LifecyclePolicy, error) {
	if p.Kind != "resultLifecycle" || p.Name != "default" {
		return LifecyclePolicy{}, fmt.Errorf("expected policy resultLifecycle default")
	}
	out := LifecyclePolicy{items: make(map[string]bool, len(p.Items))}
	for _, item := range p.Items {
		if len(item.Key) != 1 {
			continue
		}
		out.items[item.Key[0]] = true
	}
	required := []string{"flagWhen", "candidateWhen", "findingWhen", "checkWhen"}
	for _, key := range required {
		if !out.items[key] {
			return LifecyclePolicy{}, fmt.Errorf("missing item %s", key)
		}
	}
	return out, nil
}
