package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
)

// polkitGateFunctionTokens extracts one JavaScript source, lowers it, and
// returns the per-function context token sets: one entry per
// analysis.function.context node, so a case can assert which rule's callback
// carries a fact rather than only that the fact exists somewhere.
func polkitGateFunctionTokens(t *testing.T, src string) []string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rule.js")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.function.context" {
			out = append(out, n.Prop("str_args"))
		}
	}
	if len(out) == 0 {
		t.Fatal("no function context node was lowered from the rule")
	}
	return out
}

func anyFunctionHas(tokens []string, want string) bool {
	for _, set := range tokens {
		if strings.Contains(set, want) {
			return true
		}
	}
	return false
}

// CVE-2025-27512: zincati's polkit rule lost the parenthesis binding its
// subject test to the granted actions, so `(deploy || finalize) && subject.user
// == "zincati"` became `(deploy || finalize) || cleanup && subject.user ==
// "zincati"` — `&&` binds tighter than `||`, so deploy and finalize were
// granted with no subject test at all. The discriminating fact is relational —
// WHICH `||` arm the subject test binds to, and whether every granted action
// sits inside that arm — which no data-layer query over the lowered graph can
// state; the frontend has to emit it, the way it emits
// fail_open_policy_declaration_guard's sibling-conjunct relation. Every
// repaired or unrelated spelling of the same operands must stay unmarked, or
// the token says nothing a binding can pair with the polkit API.
func TestPolkitSubjectGateNotConjunctiveObservation(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{
			// The regression as commit 28a43aa2 wrote it: the `&&` reflowed
			// onto the new cleanup arm alone.
			name: "regressed rule",
			src: `polkit.addRule(function(action, subject) {
    if ((action.id == "org.projectatomic.rpmostree1.deploy" ||
         action.id == "org.projectatomic.rpmostree1.finalize-deployment") ||
         action.id == "org.projectatomic.rpmostree1.cleanup" &&
        subject.user == "zincati") {
        return polkit.Result.YES;
    }
});
`,
			want: true,
		},
		{
			// The same rule as it shipped to v0.0.29, rebase arm added: still
			// one bound arm beside three unbound ones.
			name: "rule as shipped to v0.0.29",
			src: `polkit.addRule(function(action, subject) {
    if ((action.id == "org.projectatomic.rpmostree1.deploy" ||
         action.id == "org.projectatomic.rpmostree1.finalize-deployment") ||
         action.id == "org.projectatomic.rpmostree1.cleanup" ||
         action.id == "org.projectatomic.rpmostree1.rebase" &&
        subject.user == "zincati") {
        return polkit.Result.YES;
    }
});
`,
			want: true,
		},
		{
			// The pre-regression rule: the subject test conjoined with the
			// whole action chain.
			name: "conjoined rule",
			src: `polkit.addRule(function(action, subject) {
    if ((action.id == "org.projectatomic.rpmostree1.deploy" ||
         action.id == "org.projectatomic.rpmostree1.finalize-deployment") &&
        subject.user == "zincati") {
        return polkit.Result.YES;
    }
});
`,
			want: false,
		},
		{
			// The repairing commit's spelling: the subject test stands in its
			// own if inside the action gate — conjoined by control flow.
			name: "repaired nested rule",
			src: `polkit.addRule(function(action, subject) {
    if (action.id == "org.projectatomic.rpmostree1.deploy" ||
        action.id == "org.projectatomic.rpmostree1.finalize-deployment") {
        if (subject.user == "zincati") {
            return polkit.Result.YES;
        }
    }
});
`,
			want: false,
		},
		{
			// zincati's second rule, correct all along: one action, one
			// subject test, conjoined.
			name: "correctly conjoined single action",
			src: `polkit.addRule(function(action, subject) {
    if (action.id == "org.coreos.zincati.deadend" &&
        subject.user == "zincati") {
        return polkit.Result.YES;
    }
});
`,
			want: false,
		},
		{
			// The anchor is the polkit authorization decision: the same
			// mis-conjoined boolean shape deciding anything else is ordinary
			// code, and marking it would make the token noise.
			name: "same shape outside polkit",
			src: `rules.add(function(action, subject) {
    if ((action.id == "deploy" || action.id == "finalize") ||
         action.id == "cleanup" && subject.user == "zincati") {
        return allow.YES;
    }
});
`,
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := anyFunctionHas(polkitGateFunctionTokens(t, tc.src), "polkit_subject_gate_not_conjunctive=true")
			if got != tc.want {
				t.Errorf("polkit_subject_gate_not_conjunctive marked = %v, want %v", got, tc.want)
			}
		})
	}

	// The file as zincati actually shipped it: the regressed rule and the
	// correct deadend rule side by side. The token has to ride the regressed
	// rule's callback only — the deadend callback beside it is the control that
	// keeps the token from meaning "a polkit rule was parsed".
	t.Run("both rules as shipped", func(t *testing.T) {
		src := `// Allow Zincati to deploy, finalize, and cleanup a staged deployment through rpm-ostree.
polkit.addRule(function(action, subject) {
    if ((action.id == "org.projectatomic.rpmostree1.deploy" ||
         action.id == "org.projectatomic.rpmostree1.finalize-deployment") ||
         action.id == "org.projectatomic.rpmostree1.cleanup" ||
         action.id == "org.projectatomic.rpmostree1.rebase" &&
        subject.user == "zincati") {
        return polkit.Result.YES;
    }
});

// Allow Zincati to write dead-end release information as an MOTD fragment.
polkit.addRule(function(action, subject) {
    if (action.id == "org.coreos.zincati.deadend" &&
        subject.user == "zincati") {
        return polkit.Result.YES;
    }
});
`
		sets := polkitGateFunctionTokens(t, src)
		if !anyFunctionHas(sets, "polkit_subject_gate_not_conjunctive=true") {
			t.Errorf("the regressed rule's callback was not marked")
		}
		for _, set := range sets {
			if strings.Contains(set, "org.coreos.zincati.deadend") && strings.Contains(set, "polkit_subject_gate_not_conjunctive=true") {
				t.Errorf("the correctly conjoined deadend rule's callback carries the token")
			}
		}
	})
}
