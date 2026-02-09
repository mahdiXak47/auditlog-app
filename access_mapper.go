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
	clusterRoles *rbacv1.ClusterRoleList,
	roles *rbacv1.RoleList,
	namespaces []string,
	now time.Time,
) []UserAccessReport {

	idx := buildRoleIndex(clusterRoles, roles)

	out := make([]UserAccessReport, 0, len(principals))
	for _, p := range principals {
		entries := aggregateForPrincipalAllNamespaces(p, records, idx, namespaces)

		out = append(out, UserAccessReport{
			Username:  p.Username,
			Groups:    p.Groups,
			Accesses:  entries,
			Timestamp: now.UTC().Format(time.RFC3339),
		})
	}
	return out
}

func aggregateForPrincipalAllNamespaces(
	p Principal,
	records []Access,
	idx roleIndex,
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

// creating the reports per user for one specify namespace
func reportForNamespaceAccess(
	principals []Principal,
	records []Access,
	clusterRoles *rbacv1.ClusterRoleList,
	roles *rbacv1.RoleList,
	selectedNamespace string,
	now time.Time,
) ([]UserAccessReport, error) {

	roleIndex := buildRoleIndex(clusterRoles, roles)
	out := make([]UserAccessReport, 0, len(principals))
	for _, p := range principals {
		allowed := aggregateForPrincipal(p, records, roleIndex, selectedNamespace)

		out = append(out, UserAccessReport{
			Username:  p.Username,
			Groups:    p.Groups,
			Accesses:  allowed,
			Timestamp: now.UTC().Format(time.RFC3339),
		})
	}
	return out, nil
}

func aggregateForPrincipal(p Principal, records []Access, index roleIndex, selectedNamespace string) []AccessEntry {
	// subject match keys for this principal
	subjectKeys := make(map[string]struct{}, 1+len(p.Groups))
	subjectKeys["User:"+p.Username] = struct{}{}
	for _, g := range p.Groups {
		subjectKeys["Group:"+g] = struct{}{}
	}

	// namespace -> resource -> verbSet
	agg := make(map[string]map[string]map[string]struct{})
	// namespace -> isCluster (if ANY entry came from cluster scope)
	isClusterForNS := make(map[string]bool)

	for _, rec := range records {
		k := rec.kind + ":" + rec.name
		if _, ok := subjectKeys[k]; !ok {
			continue
		}

		// Determine binding namespace
		bindingNS := ""
		if rec.namespaced {
			bindingNS = extractNamespaceFromBinding(rec.binding) // RoleBinding/ns/name
			if bindingNS == "" {
				// If parsing fails, skip to avoid wrong results
				continue
			}
		}

		// Only produce output for the selected namespace.
		// - RoleBinding applies only to its namespace => include only if matches selectedNamespace
		// - ClusterRoleBinding applies to all namespaces => include always (mapped onto selectedNamespace)
		targetNS := selectedNamespace
		if rec.namespaced && bindingNS != selectedNamespace {
			continue
		}

		rules := resolveRules(index, rec.roleRefKind, rec.roleRefName, bindingNS)
		if len(rules) == 0 {
			// RoleRef not found (could be deleted or missing perms to list Roles)
			continue
		}

		if _, ok := agg[targetNS]; !ok {
			agg[targetNS] = make(map[string]map[string]struct{})
		}

		if !rec.namespaced {
			isClusterForNS[targetNS] = true
		}

		applyRulesToAgg(agg[targetNS], rules)
	}
	// Convert agg map to []AccessEntry
	var entries []AccessEntry
	for ns, resources := range agg {
		entries = append(entries, AccessEntry{
			Namespace: ns,
			Resources: finalizeResources(resources),
			IsCluster: isClusterForNS[ns],
		})
	}

	// stable output
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

func resolveRules(idx roleIndex, roleRefKind, roleRefName, bindingNamespace string) []rbacv1.PolicyRule {
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
	for res, verbSet := range resourceVerbSet {
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

func buildRoleIndex(clusterRoles *rbacv1.ClusterRoleList, roles *rbacv1.RoleList) roleIndex {
	cr := make(map[string][]rbacv1.PolicyRule, len(clusterRoles.Items))
	for _, r := range clusterRoles.Items {
		cr[r.Name] = r.Rules
	}

	rr := make(map[string][]rbacv1.PolicyRule, len(roles.Items))
	for _, r := range roles.Items {
		key := r.Namespace + "/" + r.Name
		rr[key] = r.Rules
	}
	return roleIndex{clusterRoleRules: cr, roleRules: rr}
}
