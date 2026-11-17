package k8s

import (
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Admission policies and their bindings have no namespace: they are the
// cluster's. One made by an account that is limited to namespaces is marked
// with the namespaces it is for, and kept from reaching anything else:
//
//   - the policy matches namespaced resources only. A binding's namespace
//     selector does not hold a policy back from cluster-scoped ones (nodes,
//     cluster roles, namespaces themselves), so without this a rule meant for
//     one team would be enforced on the whole cluster's;
//   - the binding selects namespaces by name, with the label the API server
//     sets and nobody can change, and only among those of its policy.
//
// The mark is what lets another account of the same namespaces see and change
// the policy, and what keeps one of other namespaces from doing so.
const AnnotationNamespaces = "sentinel.io/namespaces"

// namespaceNameLabel is on every namespace, set by the API server to its name.
const namespaceNameLabel = "kubernetes.io/metadata.name"

// OwnerNamespaces returns the namespaces an admission policy or binding is
// marked for, or nil when it is the cluster's.
func OwnerNamespaces(obj *unstructured.Unstructured) []string {
	var out []string
	for _, ns := range strings.Split(obj.GetAnnotations()[AnnotationNamespaces], ",") {
		if ns = strings.TrimSpace(ns); ns != "" {
			out = append(out, ns)
		}
	}
	return out
}

// SetOwnerNamespaces marks an admission policy or binding.
func SetOwnerNamespaces(obj *unstructured.Unstructured, namespaces []string) {
	ann := obj.GetAnnotations()
	if ann == nil {
		ann = map[string]string{}
	}
	sorted := append([]string(nil), namespaces...)
	sort.Strings(sorted)
	ann[AnnotationNamespaces] = strings.Join(sorted, ",")
	obj.SetAnnotations(ann)
}

// keepOwnerNamespaces carries the mark over from the stored object when the
// new one has none: a manifest rebuilt by the form does not have it, and
// saving it must not hand a team's policy to the cluster.
func keepOwnerNamespaces(obj, existing *unstructured.Unstructured) {
	if len(OwnerNamespaces(obj)) == 0 {
		if owner := OwnerNamespaces(existing); len(owner) > 0 {
			SetOwnerNamespaces(obj, owner)
		}
	}
}

// namespacedOnly makes every resource rule of a policy match namespaced
// resources only.
func namespacedOnly(obj *unstructured.Unstructured) {
	for _, field := range []string{"resourceRules", "excludeResourceRules"} {
		rules, found, _ := unstructured.NestedSlice(obj.Object, "spec", "matchConstraints", field)
		if !found {
			continue
		}
		for _, r := range rules {
			if rule, ok := r.(map[string]any); ok {
				rule["scope"] = "Namespaced"
			}
		}
		_ = unstructured.SetNestedSlice(obj.Object, rules, "spec", "matchConstraints", field)
	}
}

// PinnedNamespaces returns the namespaces a binding is held to, when its
// namespace selector does nothing but name them: one matchLabels entry on the
// name label, or one "In" expression on it. Anything else (no selector, another
// label, NotIn, several conditions) is not pinned, since a namespace's other
// labels are its owner's to change.
func PinnedNamespaces(binding *unstructured.Unstructured) ([]string, bool) {
	sel, found, _ := unstructured.NestedMap(binding.Object, "spec", "matchResources", "namespaceSelector")
	if !found {
		return nil, false
	}
	labels, _ := sel["matchLabels"].(map[string]any)
	exprs, _ := sel["matchExpressions"].([]any)
	for key := range sel {
		if key != "matchLabels" && key != "matchExpressions" {
			return nil, false
		}
	}
	switch {
	case len(labels) == 1 && len(exprs) == 0:
		name, ok := labels[namespaceNameLabel].(string)
		if !ok || name == "" {
			return nil, false
		}
		return []string{name}, true
	case len(labels) == 0 && len(exprs) == 1:
		expr, _ := exprs[0].(map[string]any)
		values, _ := expr["values"].([]any)
		if expr["key"] != namespaceNameLabel || expr["operator"] != "In" || len(values) == 0 {
			return nil, false
		}
		out := make([]string, 0, len(values))
		for _, v := range values {
			name, ok := v.(string)
			if !ok || name == "" {
				return nil, false
			}
			out = append(out, name)
		}
		return out, true
	}
	return nil, false
}
