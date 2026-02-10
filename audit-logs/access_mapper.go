package main

import (
	"sort"
	"strings"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
)

//type ResourceVerbs map[string][]string // pod -> get , list , delete , felan

//type AccessEntry struct {
//	Namespace string        `json:"namespace"`  // target namespace (or "*" if you want)
//	Resources ResourceVerbs `json:"resources"`  // resource -> verbs
//	IsCluster bool          `json:"is_cluster"` // true if came from ClusterRoleBinding
//}

type Rule struct {
	Resource string   `json:"resource"`           // e.g. "pods", "*", "pods/log"
	Verbs    []string `json:"verbs"`              // e.g. ["get","list"] or ["*"]
	APIGroup string   `json:"apiGroup,omitempty"` // optional improvement
}

type ScopeEntry struct {
	Scope     string `json:"scope"`     // "cluster" or "namespaced"
	Namespace string `json:"namespace"` // actual namespace
	Rules     []Rule `json:"rules"`
}

type UserAccessReport struct {
	Type      string       `json:"type"` // e.g. "rbac_effective_permissions"
	Timestamp string       `json:"@timestamp"`
	Username  string       `json:"username"`
	Groups    []string     `json:"groups"`
	Scopes    []ScopeEntry `json:"scopes"`
}

// FlatPermission this class is creating another index in elasticsearch for filtering better on grafana dashboards for nested objects(resources and verbs and namespaces in Scope)
type FlatPermission struct {
	Timestamp string   `json:"@timestamp"`
	Type      string   `json:"type"`
	Username  string   `json:"username"`
	Groups    []string `json:"groups"`
	Namespace string   `json:"namespace"`
	Scope     string   `json:"scope"`    // "cluster" or "namespaced"
	Resource  string   `json:"resource"` // e.g. "pods/log"
	Verb      string   `json:"verb"`     // e.g. "get"
}

func FlattenReports(reports []UserAccessReport) []FlatPermission {
	out := make([]FlatPermission, 0, 1000)

	for _, r := range reports {
		for _, sc := range r.Scopes {
			for _, rule := range sc.Rules {
				for _, verb := range rule.Verbs {
					out = append(out, FlatPermission{
						Timestamp: r.Timestamp,
						Type:      "rbac_effective_permission_flat",
						Username:  r.Username,
						Groups:    r.Groups,
						Namespace: sc.Namespace,
						Scope:     sc.Scope,
						Resource:  rule.Resource,
						Verb:      verb,
					})
				}
			}
		}
	}
	return out
}

func BuildReportsForAllNamespaces(
	principals []Principal,
	records []Access,
	idx *roleIndex,
	namespaces []string,
) []UserAccessReport {

	out := make([]UserAccessReport, 0, len(principals))
	for _, p := range principals {
		scopes := aggregateForPrincipalAllNamespaces(p, records, idx, namespaces)

		out = append(out, UserAccessReport{
			Type:      "rbac_effective_permissions",
			Username:  p.Username,
			Groups:    p.Groups,
			Scopes:    scopes,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
	}
	return out
}

func aggregateForPrincipalAllNamespaces(
	p Principal,
	records []Access,
	idx *roleIndex,
	allNamespaces []string,
) []ScopeEntry {

	// Keys like: "User:mohammad.jafari", "Group:sre-production"
	subjectKeys := map[string]struct{}{
		"User:" + p.Username: {},
	}
	for _, g := range p.Groups {
		subjectKeys["Group:"+g] = struct{}{}
	}

	// ns -> resource -> verbSet
	agg := make(map[string]map[string]map[string]struct{})
	isClusterForNS := make(map[string]bool)

	ensureNS := func(ns string) {
		if _, ok := agg[ns]; !ok {
			agg[ns] = make(map[string]map[string]struct{})
		}
	}

	for _, rec := range records {
		subKey := rec.kind + ":" + rec.name
		if _, ok := subjectKeys[subKey]; !ok {
			continue
		}

		if rec.namespaced {
			// RoleBinding: applies only to its namespace
			ns := extractNamespaceFromBinding(rec.binding)
			if ns == "" {
				continue
			}
			ensureNS(ns)

			rules := resolveRules(idx, rec.roleRefKind, rec.roleRefName, ns)
			if len(rules) == 0 {
				continue
			}
			applyRulesToAgg(agg[ns], rules)

		} else {
			// ClusterRoleBinding: applies to all namespaces
			rules := resolveRules(idx, rec.roleRefKind, rec.roleRefName, "")
			if len(rules) == 0 {
				continue
			}
			for _, ns := range allNamespaces {
				ensureNS(ns)
				isClusterForNS[ns] = true
				applyRulesToAgg(agg[ns], rules)
			}
		}
	}

	// Convert agg to []ScopeEntry
	scopes := make([]ScopeEntry, 0, len(agg))
	for ns, res := range agg {
		scope := "namespaced"
		if isClusterForNS[ns] {
			scope = "cluster"
		}

		scopes = append(scopes, ScopeEntry{
			Scope:     scope,
			Namespace: ns,
			Rules:     finalizeRules(res), // <-- new function returns []Rule
		})
	}

	sort.Slice(scopes, func(i, j int) bool { return scopes[i].Namespace < scopes[j].Namespace })
	return scopes
	// Convert to []AccessEntry
	//entries := make([]AccessEntry, 0, len(agg))
	//for ns, res := range agg {
	//	entries = append(entries, AccessEntry{
	//		Namespace: ns,
	//		//Resources: finalizeResources(res),
	//		Resources: finalizeRules(res),
	//		IsCluster: isClusterForNS[ns],
	//	})
	//}
	//
	//sort.Slice(entries, func(i, j int) bool { return entries[i].Namespace < entries[j].Namespace })
	//return entries
}

func normalizeVerbs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

func resolveRules(idx *roleIndex, roleRefKind, roleRefName, bindingNamespace string) []rbacv1.PolicyRule {
	switch roleRefKind {
	case "ClusterRole":
		return idx.clusterRoleRules[roleRefName]
	case "Role":
		key := bindingNamespace + "/" + roleRefName
		return idx.roleRules[key]
	default:
		return nil
	}
}

//func finalizeResources(resourceVerbSet map[string]map[string]struct{}) ResourceVerbs {
//	out := make(ResourceVerbs, len(resourceVerbSet))
//	fullVerbSet := map[string]struct{}{
//		"create": {},
//		"delete": {},
//		"get":    {},
//		"list":   {},
//		"patch":  {},
//		"update": {},
//		"watch":  {},
//	}
//	for res, verbSet := range resourceVerbSet {
//
//		// If rule already contains "*", no need to check further
//		if _, hasWildcard := verbSet["*"]; hasWildcard {
//			out[res] = []string{"*"}
//			continue
//		}
//
//		// Check if verbSet contains all full verbs
//		hasAll := true
//		for v := range fullVerbSet {
//			if _, ok := verbSet[v]; !ok {
//				hasAll = false
//				break
//			}
//		}
//
//		if hasAll {
//			out[res] = []string{"*"}
//			continue
//		}
//
//		// Otherwise output sorted verbs normally
//		var verbs []string
//		for v := range verbSet {
//			verbs = append(verbs, v)
//		}
//		sort.Strings(verbs)
//		out[res] = verbs
//	}
//
//	// stable keys are handled by JSON marshaller order? not guaranteed, but fine.
//	return out
//}

func finalizeRules(resourceVerbSet map[string]map[string]struct{}) []Rule {
	out := make([]Rule, 0, len(resourceVerbSet))

	fullVerbSet := map[string]struct{}{
		"create": {}, "delete": {}, "get": {}, "list": {}, "patch": {}, "update": {}, "watch": {},
	}

	for res, verbSet := range resourceVerbSet {
		// If any wildcard verb exists, compress to "*"
		if _, hasWildcard := verbSet["*"]; hasWildcard {
			out = append(out, Rule{Resource: res, Verbs: []string{"*"}})
			continue
		}

		// If verbSet contains all common verbs, compress to "*"
		hasAll := true
		for v := range fullVerbSet {
			if _, ok := verbSet[v]; !ok {
				hasAll = false
				break
			}
		}
		if hasAll {
			out = append(out, Rule{Resource: res, Verbs: []string{"*"}})
			continue
		}

		verbs := make([]string, 0, len(verbSet))
		for v := range verbSet {
			verbs = append(verbs, v)
		}
		sort.Strings(verbs)
		out = append(out, Rule{Resource: res, Verbs: verbs})
	}

	// stable ordering for nice diffs / deterministic docs
	sort.Slice(out, func(i, j int) bool { return out[i].Resource < out[j].Resource })
	return out
}

// Adds rules into resource->verbSet.
// Note: This ignores APIGroup and non-resource URLs for now (you can add later).
func applyRulesToAgg(resourceVerbSet map[string]map[string]struct{}, rules []rbacv1.PolicyRule) {
	for _, rule := range rules {
		verbs := normalizeVerbs(rule.Verbs)

		// Resource rules
		for _, res := range rule.Resources {
			res = strings.TrimSpace(res)
			if res == "" {
				continue
			}
			if _, ok := resourceVerbSet[res]; !ok {
				resourceVerbSet[res] = make(map[string]struct{})
			}
			for _, v := range verbs {
				resourceVerbSet[res][v] = struct{}{}
			}
		}

		// (Optional later) NonResourceURLs support:
		// for _, url := range rule.NonResourceURLs { ... }
	}
}

func extractNamespaceFromBinding(binding string) string {
	// format is "RoleBinding/<ns>/<name>" or "ClusterRoleBinding/<name>"
	parts := strings.Split(binding, "/")
	if len(parts) >= 3 && parts[0] == "RoleBinding" {
		return parts[1]
	}
	return ""
}

type roleIndex struct {
	clusterRoleRules map[string][]rbacv1.PolicyRule // ClusterRole name -> rules
	roleRules        map[string][]rbacv1.PolicyRule // "ns/name" -> rules
}

func buildRoleIndex(clusterRoles *rbacv1.ClusterRoleList, roles *rbacv1.RoleList) *roleIndex {
	cr := make(map[string][]rbacv1.PolicyRule, len(clusterRoles.Items))
	for _, r := range clusterRoles.Items {
		cr[r.Name] = r.Rules
	}

	rr := make(map[string][]rbacv1.PolicyRule, len(roles.Items))
	for _, r := range roles.Items {
		key := r.Namespace + "/" + r.Name
		rr[key] = r.Rules
	}
	return &roleIndex{
		clusterRoleRules: cr,
		roleRules:        rr,
	}
}
