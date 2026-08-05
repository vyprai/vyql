package solvers

import (
	"strings"

	"github.com/vyprai/vyql/internal/usg"
)

// AccessGrant is one edge in an effective-permission chain: a principal/role
// granted an ability over the next node.
type AccessGrant struct {
	From    string
	To      string
	Ability string
}

// AccessPath is an effective permission: a principal can perform an action on a
// resource, possibly via assumed roles. Grants is the granting chain; the final
// grant's ability matches the requested action (docs/09 §"can_access").
type AccessPath struct {
	PrincipalID string
	ResourceID  string
	Action      string
	Grants      []AccessGrant
}

func (p AccessPath) Source() string { return p.PrincipalID }
func (p AccessPath) Target() string { return p.ResourceID }
func (p AccessPath) Witness() []string {
	w := make([]string, 0, len(p.Grants)+1)
	for i, g := range p.Grants {
		if i == 0 {
			w = append(w, g.From)
		}
		w = append(w, g.To)
	}
	return w
}

// ViaRoles returns the intermediate (assumed-role) node ids on the chain — the
// "via assumed role X" part of the witness.
func (p AccessPath) ViaRoles() []string {
	if len(p.Grants) < 2 {
		return nil
	}
	var roles []string
	for _, g := range p.Grants[:len(p.Grants)-1] {
		roles = append(roles, g.To)
	}
	return roles
}

// actionMatches reports whether a granted ability pattern covers the requested
// action. A trailing "*" is a prefix wildcard (e.g. "s3:GetObject*" covers
// "s3:GetObject" and "s3:GetObjectAcl"); "*" alone covers anything; an empty
// requested action matches any grant.
func actionMatches(ability, action string) bool {
	if action == "" || ability == "*" {
		return true
	}
	if strings.HasSuffix(ability, "*") {
		return strings.HasPrefix(action, ability[:len(ability)-1])
	}
	return ability == action
}

// FindCanAccess computes effective permissions: which principals can perform
// `action` on a resource, traversing escalation/grant STEP edges (so access via
// an assumed role is found). The witness is the ability chain; a resource is
// accessible iff it is reached by an edge whose ability covers the action.
func FindCanAccess(store usg.Store, principalIDs, resourceIDs []string, action string) ([]AccessPath, error) {
	resources := map[string]bool{}
	for _, r := range resourceIDs {
		resources[r] = true
	}
	var out []AccessPath
	for _, p := range principalIDs {
		seen := map[string]bool{p: true}
		type item struct {
			id     string
			grants []AccessGrant
		}
		queue := []item{{p, nil}}
		reached := map[string][]AccessGrant{}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			edges, err := store.OutEdges(cur.id, "STEP")
			if err != nil {
				return nil, err
			}
			for _, e := range edges {
				grants := append(append([]AccessGrant{}, cur.grants...),
					AccessGrant{From: e.Src, To: e.Dst, Ability: e.Prop("ability")})
				if resources[e.Dst] && actionMatches(e.Prop("ability"), action) {
					if _, ok := reached[e.Dst]; !ok {
						reached[e.Dst] = grants
					}
				}
				if !seen[e.Dst] {
					seen[e.Dst] = true
					queue = append(queue, item{e.Dst, grants})
				}
			}
		}
		for r, grants := range reached {
			out = append(out, AccessPath{PrincipalID: p, ResourceID: r, Action: action, Grants: grants})
		}
	}
	return out, nil
}
