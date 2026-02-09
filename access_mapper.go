package main

import (
	"sort"
	"strings"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
)

type ResourceVerbs map[string][]string // pod -> get , list , delete , felan

type AccessEntry struct {
	Namespace string        `json:"namespace"`  // target namespace (or "*" if you want)
	Resources ResourceVerbs `json:"resources"`  // resource -> verbs
	IsCluster bool          `json:"is_cluster"` // true if came from ClusterRoleBinding
}

type UserAccessReport struct {
	Username  string        `json:"username"`
	Groups    []string      `json:"groups"`
	Accesses  []AccessEntry `json:"accesses"`
	Timestamp string        `json:"timestamp"`
}

func BuildReportsForAllNamespaces(
	principals []Principal,
	records []Access,
	idx *roleIndex,
	namespaces []string,
) []UserAccessReport {

	out := make([]UserAccessReport, 0, len(principals))
	for _, p := range principals {
		entries := aggregateForPrincipalAllNamespaces(p, records, idx, namespaces)

		out = append(out, UserAccessReport{
			Username:  p.Username,
			Groups:    p.Groups,
			Accesses:  entries,
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
) []AccessEntry {

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

	// Convert to []AccessEntry
	entries := make([]AccessEntry, 0, len(agg))
	for ns, res := range agg {
		entries = append(entries, AccessEntry{
			Namespace: ns,
			Resources: finalizeResources(res),
			IsCluster: isClusterForNS[ns],
		})
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Namespace < entries[j].Namespace })
	return entries
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

func finalizeResources(resourceVerbSet map[string]map[string]struct{}) ResourceVerbs {
	out := make(ResourceVerbs, len(resourceVerbSet))
	fullVerbSet := map[string]struct{}{
		"create": {},
		"delete": {},
		"get":    {},
		"list":   {},
		"patch":  {},
		"update": {},
		"watch":  {},
	}
	for res, verbSet := range resourceVerbSet {

		// If rule already contains "*", no need to check further
		if _, hasWildcard := verbSet["*"]; hasWildcard {
			out[res] = []string{"*"}
			continue
		}

		// Check if verbSet contains all full verbs
		hasAll := true
		for v := range fullVerbSet {
			if _, ok := verbSet[v]; !ok {
				hasAll = false
				break
			}
		}

		if hasAll {
			out[res] = []string{"*"}
			continue
		}

		// Otherwise output sorted verbs normally
		var verbs []string
		for v := range verbSet {
			verbs = append(verbs, v)
		}
		sort.Strings(verbs)
		out[res] = verbs
	}

	// stable keys are handled by JSON marshaller order? not guaranteed, but fine.
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
