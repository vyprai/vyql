package resultpolicy

import (
	"fmt"
	"sync"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/parser"
)

type LifecyclePolicy struct {
	items map[string]parser.V2Expr
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
	return LifecyclePolicy{items: lifecycleDefaultExprs()}
}

func (p LifecyclePolicy) FlagWhenIssue(hasReview bool) bool {
	return p.eval("flagWhen", lifecycleEvalContext{
		emitted:   map[string]bool{"issue": true},
		hasReview: hasReview,
	})
}

func (p LifecyclePolicy) CandidateWhenMatchedRule(matched bool) bool {
	return p.eval("candidateWhen", lifecycleEvalContext{
		matched: map[string]bool{"rule": matched},
	})
}

func (p LifecyclePolicy) FindingWhen(candidate, covered bool) bool {
	return p.eval("findingWhen", lifecycleEvalContext{
		vars: map[string]bool{"candidate": candidate, "covered": covered},
	})
}

func (p LifecyclePolicy) CheckWhen(hasReview, explainsFinding bool) bool {
	return p.eval("checkWhen", lifecycleEvalContext{
		emitted:   map[string]bool{"check": true},
		vars:      map[string]bool{"explainsFinding": explainsFinding},
		hasReview: hasReview,
	})
}

func (p LifecyclePolicy) eval(key string, ctx lifecycleEvalContext) bool {
	if p.items == nil {
		return false
	}
	expr, ok := p.items[key]
	if !ok {
		return false
	}
	return evalLifecycleExpr(expr, ctx)
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
	out := LifecyclePolicy{items: make(map[string]parser.V2Expr, len(p.Items))}
	for _, item := range p.Items {
		if len(item.Key) != 1 {
			continue
		}
		expr, ok := item.Value.(parser.V2Expr)
		if !ok {
			return LifecyclePolicy{}, fmt.Errorf("item %s must be a predicate expression", item.Key[0])
		}
		out.items[item.Key[0]] = expr
	}
	required := []string{"flagWhen", "candidateWhen", "findingWhen", "checkWhen"}
	for _, key := range required {
		if _, ok := out.items[key]; !ok {
			return LifecyclePolicy{}, fmt.Errorf("missing item %s", key)
		}
	}
	return out, nil
}

type lifecycleEvalContext struct {
	vars      map[string]bool
	emitted   map[string]bool
	matched   map[string]bool
	hasReview bool
}

func lifecycleDefaultExprs() map[string]parser.V2Expr {
	return map[string]parser.V2Expr{
		"flagWhen": parser.V2BinaryExpr{
			Op:    "and",
			Left:  parser.V2CallExpr{Name: "emitted", Args: []parser.V2Expr{parser.V2RefExpr{Name: "issue"}}},
			Right: parser.V2CallExpr{Name: "hasReview", Args: []parser.V2Expr{parser.V2RefExpr{Name: "concept"}}},
		},
		"candidateWhen": parser.V2CallExpr{Name: "matched", Args: []parser.V2Expr{parser.V2RefExpr{Name: "rule"}}},
		"findingWhen": parser.V2BinaryExpr{
			Op:    "and",
			Left:  parser.V2RefExpr{Name: "candidate"},
			Right: parser.V2UnaryExpr{Op: "not", X: parser.V2RefExpr{Name: "covered"}},
		},
		"checkWhen": parser.V2BinaryExpr{
			Op:   "and",
			Left: parser.V2CallExpr{Name: "emitted", Args: []parser.V2Expr{parser.V2RefExpr{Name: "check"}}},
			Right: parser.V2BinaryExpr{
				Op:    "or",
				Left:  parser.V2CallExpr{Name: "hasReview", Args: []parser.V2Expr{parser.V2RefExpr{Name: "concept"}}},
				Right: parser.V2RefExpr{Name: "explainsFinding"},
			},
		},
	}
}

func evalLifecycleExpr(expr parser.V2Expr, ctx lifecycleEvalContext) bool {
	switch x := expr.(type) {
	case parser.V2LiteralExpr:
		v, _ := x.Value.(bool)
		return v
	case parser.V2RefExpr:
		return ctx.vars[x.Name]
	case parser.V2UnaryExpr:
		if x.Op == "not" {
			return !evalLifecycleExpr(x.X, ctx)
		}
	case parser.V2BinaryExpr:
		switch x.Op {
		case "and":
			return evalLifecycleExpr(x.Left, ctx) && evalLifecycleExpr(x.Right, ctx)
		case "or":
			return evalLifecycleExpr(x.Left, ctx) || evalLifecycleExpr(x.Right, ctx)
		}
	case parser.V2CallExpr:
		arg := lifecycleCallArgName(x.Args)
		switch x.Name {
		case "emitted":
			return ctx.emitted[arg]
		case "matched":
			return ctx.matched[arg]
		case "hasReview":
			return arg == "concept" && ctx.hasReview
		}
	}
	return false
}

func lifecycleCallArgName(args []parser.V2Expr) string {
	if len(args) != 1 {
		return ""
	}
	ref, ok := args[0].(parser.V2RefExpr)
	if !ok {
		return ""
	}
	return ref.Name
}
