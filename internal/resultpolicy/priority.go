package resultpolicy

import (
	"fmt"
	"strings"
	"sync"

	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/parser"
)

type PriorityPolicy struct {
	Severity map[string]int
	Default  int
}

var (
	priorityOnce sync.Once
	priorityCfg  PriorityPolicy
	priorityErr  error
)

func DefaultPriority() (PriorityPolicy, error) {
	priorityOnce.Do(func() {
		priorityCfg, priorityErr = loadPriorityPolicy()
	})
	return priorityCfg, priorityErr
}

func MustDefaultPriority() PriorityPolicy {
	p, err := DefaultPriority()
	if err != nil {
		panic("resultpolicy: invalid policy priority default: " + err.Error())
	}
	return p
}

func SeverityRank(severity string) int {
	return MustDefaultPriority().SeverityRank(severity)
}

func (p PriorityPolicy) SeverityRank(severity string) int {
	key := strings.ToLower(strings.TrimSpace(severity))
	if rank, ok := p.Severity[key]; ok {
		return rank
	}
	return p.Default
}

func loadPriorityPolicy() (PriorityPolicy, error) {
	files, err := datadir.ReadVYQLDir("policies")
	if err != nil {
		return PriorityPolicy{}, err
	}
	raw := make([]parser.V2DefinitionSource, 0, len(files))
	for _, file := range files {
		raw = append(raw, parser.V2DefinitionSource{Name: file.Name, Source: string(file.Data)})
	}
	decls, err := parser.ParseV2DefinitionSources(raw)
	if err != nil {
		return PriorityPolicy{}, err
	}
	var policy *parser.V2PolicyDecl
	for _, decl := range decls {
		p, ok := decl.(*parser.V2PolicyDecl)
		if !ok || p.Kind != "priority" || p.Name != "default" {
			continue
		}
		if policy != nil {
			return PriorityPolicy{}, fmt.Errorf("duplicate policy priority default")
		}
		policy = p
	}
	if policy == nil {
		return PriorityPolicy{}, fmt.Errorf("missing policy priority default")
	}
	return PriorityPolicyFromDecl(policy)
}

func PriorityPolicyFromDecl(p *parser.V2PolicyDecl) (PriorityPolicy, error) {
	if p.Kind != "priority" || p.Name != "default" {
		return PriorityPolicy{}, fmt.Errorf("expected policy priority default")
	}
	out := PriorityPolicy{Severity: map[string]int{}, Default: 0}
	for _, item := range p.Items {
		if len(item.Key) != 2 || item.Key[0] != "score" || item.Key[1] != "severity" {
			continue
		}
		for _, score := range item.Block {
			if len(score.Key) != 1 {
				continue
			}
			value, ok := priorityPolicyInt(score.Value)
			if !ok {
				return PriorityPolicy{}, fmt.Errorf("score severity.%s must be an integer", score.Key[0])
			}
			key := strings.ToLower(score.Key[0])
			if key == "default" {
				out.Default = value
			} else {
				out.Severity[key] = value
			}
		}
	}
	if len(out.Severity) == 0 {
		return PriorityPolicy{}, fmt.Errorf("score severity must be declared")
	}
	return out, nil
}

func priorityPolicyInt(raw any) (int, bool) {
	switch x := raw.(type) {
	case int:
		return x, true
	case parser.V2LiteralExpr:
		v, ok := x.Value.(int)
		return v, ok
	default:
		return 0, false
	}
}
