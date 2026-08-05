package resultpolicy

import (
	"fmt"
	"strings"
	"sync"

	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/parser"
)

type ConfidencePolicy struct {
	Order []string
	rank  map[string]int
}

var (
	confidenceOnce sync.Once
	confidenceCfg  ConfidencePolicy
	confidenceErr  error
)

func DefaultConfidence() (ConfidencePolicy, error) {
	confidenceOnce.Do(func() {
		confidenceCfg, confidenceErr = loadConfidencePolicy()
	})
	return confidenceCfg, confidenceErr
}

func MustDefaultConfidence() ConfidencePolicy {
	p, err := DefaultConfidence()
	if err != nil {
		panic("resultpolicy: invalid policy confidence default: " + err.Error())
	}
	return p
}

func ConfidenceRank(conf string) int {
	return MustDefaultConfidence().Rank(conf)
}

func ConfidenceName(rank int) string {
	return MustDefaultConfidence().Name(rank)
}

func MaxConfidenceRank() int {
	return MustDefaultConfidence().MaxRank()
}

func (p ConfidencePolicy) Rank(conf string) int {
	if p.rank == nil {
		p = p.withRank()
	}
	return p.rank[strings.ToLower(conf)]
}

func (p ConfidencePolicy) Name(rank int) string {
	if len(p.Order) == 0 {
		return ""
	}
	if rank >= 1 && rank <= len(p.Order) {
		return p.Order[rank-1]
	}
	return p.Order[len(p.Order)-1]
}

func (p ConfidencePolicy) MaxRank() int {
	return len(p.Order)
}

func (p ConfidencePolicy) withRank() ConfidencePolicy {
	if p.rank != nil {
		return p
	}
	p.rank = make(map[string]int, len(p.Order))
	for i, value := range p.Order {
		p.rank[strings.ToLower(value)] = i + 1
	}
	return p
}

func loadConfidencePolicy() (ConfidencePolicy, error) {
	files, err := datadir.ReadVYQLDir("policies")
	if err != nil {
		return ConfidencePolicy{}, err
	}
	raw := make([]parser.V2DefinitionSource, 0, len(files))
	for _, file := range files {
		raw = append(raw, parser.V2DefinitionSource{Name: file.Name, Source: string(file.Data)})
	}
	decls, err := parser.ParseV2DefinitionSources(raw)
	if err != nil {
		return ConfidencePolicy{}, err
	}
	var policy *parser.V2PolicyDecl
	for _, decl := range decls {
		p, ok := decl.(*parser.V2PolicyDecl)
		if !ok || p.Kind != "confidence" || p.Name != "default" {
			continue
		}
		if policy != nil {
			return ConfidencePolicy{}, fmt.Errorf("duplicate policy confidence default")
		}
		policy = p
	}
	if policy == nil {
		return ConfidencePolicy{}, fmt.Errorf("missing policy confidence default")
	}
	return confidencePolicyFromDecl(policy)
}

func confidencePolicyFromDecl(p *parser.V2PolicyDecl) (ConfidencePolicy, error) {
	out := ConfidencePolicy{}
	for _, item := range p.Items {
		if len(item.Key) != 1 || item.Key[0] != "order" {
			continue
		}
		out.Order = identityPolicyStringList(item.Value)
	}
	if len(out.Order) == 0 {
		return ConfidencePolicy{}, fmt.Errorf("order must be a non-empty list")
	}
	seen := map[string]bool{}
	for _, value := range out.Order {
		key := strings.ToLower(value)
		if seen[key] {
			return ConfidencePolicy{}, fmt.Errorf("duplicate confidence level %q", value)
		}
		seen[key] = true
	}
	return out.withRank(), nil
}
