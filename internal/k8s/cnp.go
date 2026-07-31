package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/yaml"
)

var (
	cnpGVR = schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumnetworkpolicies",
	}
	ccnpGVR = schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumclusterwidenetworkpolicies",
	}
)

// CNPRecord is a Cilium network policy flattened for the UI.
type CNPRecord struct {
	Name         string `json:"name"`
	Namespace    string `json:"namespace"` // empty for cluster-wide policies
	Scope        string `json:"scope"`     // "namespace" | "cluster"
	Selector     string `json:"selector"`  // human-readable endpointSelector
	IngressRules int    `json:"ingressRules"`
	EgressRules  int    `json:"egressRules"`
	HasL7        bool   `json:"hasL7"`       // any rule carries toPorts[].rules
	DefaultDeny  string `json:"defaultDeny"` // "ingress" | "egress" | "both" | ""
	CreatedBy    string `json:"createdBy"`
	CreatedAt    string `json:"createdAt"`
	RawYAML      string `json:"rawYaml"`
}

func cnpResource(scope string) schema.GroupVersionResource {
	if scope == "cluster" {
		return ccnpGVR
	}
	return cnpGVR
}

// CiliumPolicyCRDAvailable reports whether the Cilium policy CRDs are installed.
func (s *Store) CiliumPolicyCRDAvailable(ctx context.Context) bool {
	if s.client == nil {
		return false
	}
	_, err := s.client.Resource(cnpGVR).Namespace("").List(ctx, metav1.ListOptions{Limit: 1})
	return err == nil
}

// ListCNP returns all namespaced and cluster-wide Cilium network policies.
// Returns ErrCiliumCRDMissing when the CRDs are not installed.
func (s *Store) ListCNP(ctx context.Context) ([]CNPRecord, error) {
	if s.client == nil {
		return nil, fmt.Errorf("kubernetes client not initialised")
	}
	records := []CNPRecord{}

	nsList, nsErr := s.client.Resource(cnpGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if nsErr == nil {
		for _, item := range nsList.Items {
			records = append(records, toCNPRecord(item, "namespace"))
		}
	}
	cwList, cwErr := s.client.Resource(ccnpGVR).List(ctx, metav1.ListOptions{})
	if cwErr == nil {
		for _, item := range cwList.Items {
			records = append(records, toCNPRecord(item, "cluster"))
		}
	}
	// Both failing means the CRDs are absent (or RBAC is missing) — surface it
	// so the UI can explain instead of showing a misleading empty list.
	if nsErr != nil && cwErr != nil {
		return nil, fmt.Errorf("list Cilium network policies: %w", nsErr)
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].Namespace != records[j].Namespace {
			return records[i].Namespace < records[j].Namespace
		}
		return records[i].Name < records[j].Name
	})
	return records, nil
}

func (s *Store) GetCNP(ctx context.Context, scope, namespace, name string) (CNPRecord, error) {
	gvr := cnpResource(scope)
	var (
		item *unstructured.Unstructured
		err  error
	)
	if scope == "cluster" {
		item, err = s.client.Resource(gvr).Get(ctx, name, metav1.GetOptions{})
	} else {
		item, err = s.client.Resource(gvr).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	}
	if err != nil {
		return CNPRecord{}, fmt.Errorf("get Cilium network policy %q: %w", name, err)
	}
	return toCNPRecord(*item, scope), nil
}

// ApplyCNPRaw creates or updates a Cilium network policy from raw YAML.
// Scope is derived from the manifest kind, so the caller does not pass it.
func (s *Store) ApplyCNPRaw(ctx context.Context, rawYAML, createdBy string) error {
	jsonBytes, err := yaml.YAMLToJSON([]byte(rawYAML))
	if err != nil {
		return fmt.Errorf("invalid YAML: %w", err)
	}
	obj := &unstructured.Unstructured{}
	if err := json.Unmarshal(jsonBytes, &obj.Object); err != nil {
		return fmt.Errorf("unmarshal YAML: %w", err)
	}

	kind := obj.GetKind()
	var gvr schema.GroupVersionResource
	switch kind {
	case "CiliumNetworkPolicy":
		gvr = cnpGVR
	case "CiliumClusterwideNetworkPolicy":
		gvr = ccnpGVR
	default:
		return fmt.Errorf("unsupported kind %q — expected CiliumNetworkPolicy or CiliumClusterwideNetworkPolicy", kind)
	}
	clusterScoped := gvr == ccnpGVR

	name := obj.GetName()
	if name == "" {
		return fmt.Errorf("metadata.name is required")
	}
	ns := obj.GetNamespace()
	if clusterScoped {
		// Cluster-wide policies must not carry a namespace
		obj.SetNamespace("")
	} else if ns == "" {
		return fmt.Errorf("metadata.namespace is required for CiliumNetworkPolicy")
	}

	setCreatedByAnnotation(obj, createdBy)
	obj.SetResourceVersion("")
	obj.SetUID("")
	obj.SetManagedFields(nil)

	ri := s.client.Resource(gvr)
	if clusterScoped {
		_, err = ri.Create(ctx, obj, metav1.CreateOptions{})
	} else {
		_, err = ri.Namespace(ns).Create(ctx, obj, metav1.CreateOptions{})
	}
	if err == nil {
		return nil
	}
	if !k8serrors.IsAlreadyExists(err) {
		return err
	}

	var existing *unstructured.Unstructured
	if clusterScoped {
		existing, err = ri.Get(ctx, name, metav1.GetOptions{})
	} else {
		existing, err = ri.Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	}
	if err != nil {
		return err
	}
	obj.SetResourceVersion(existing.GetResourceVersion())
	preserveCreatedBy(obj, existing)
	if clusterScoped {
		_, err = ri.Update(ctx, obj, metav1.UpdateOptions{})
	} else {
		_, err = ri.Namespace(ns).Update(ctx, obj, metav1.UpdateOptions{})
	}
	return err
}

func (s *Store) DeleteCNP(ctx context.Context, scope, namespace, name string) error {
	gvr := cnpResource(scope)
	var err error
	if scope == "cluster" {
		err = s.client.Resource(gvr).Delete(ctx, name, metav1.DeleteOptions{})
	} else {
		err = s.client.Resource(gvr).Namespace(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	}
	if err != nil {
		return fmt.Errorf("delete Cilium network policy %q: %w", name, err)
	}
	return nil
}

func toCNPRecord(item unstructured.Unstructured, scope string) CNPRecord {
	rawYAML := ""
	if rawJSON, err := json.Marshal(item.Object); err == nil {
		if y, err := yaml.JSONToYAML(rawJSON); err == nil {
			rawYAML = string(y)
		}
	}

	// Cilium accepts either a single `specs[]` list or one `spec` object.
	specs := collectSpecs(item.Object)

	ingress, egress := 0, 0
	hasL7 := false
	denyIngress, denyEgress := false, false
	for _, spec := range specs {
		if in, ok, _ := unstructured.NestedSlice(spec, "ingress"); ok {
			ingress += len(in)
			denyIngress = true // any ingress rule switches the endpoint to default-deny
			if rulesPresent(in) {
				hasL7 = true
			}
		}
		if eg, ok, _ := unstructured.NestedSlice(spec, "egress"); ok {
			egress += len(eg)
			denyEgress = true
			if rulesPresent(eg) {
				hasL7 = true
			}
		}
		// Explicit deny rules also imply default-deny for that direction
		if d, ok, _ := unstructured.NestedSlice(spec, "ingressDeny"); ok && len(d) > 0 {
			ingress += len(d)
			denyIngress = true
		}
		if d, ok, _ := unstructured.NestedSlice(spec, "egressDeny"); ok && len(d) > 0 {
			egress += len(d)
			denyEgress = true
		}
	}

	defaultDeny := ""
	switch {
	case denyIngress && denyEgress:
		defaultDeny = "both"
	case denyIngress:
		defaultDeny = "ingress"
	case denyEgress:
		defaultDeny = "egress"
	}

	createdAt := ""
	if ts := item.GetCreationTimestamp(); !ts.IsZero() {
		createdAt = ts.UTC().Format("2006-01-02T15:04:05Z")
	}
	createdBy := "k8s-apply"
	if v := item.GetAnnotations()[annotationCreatedBy]; v != "" {
		createdBy = v
	}

	return CNPRecord{
		Name:         item.GetName(),
		Namespace:    item.GetNamespace(),
		Scope:        scope,
		Selector:     describeSelector(specs),
		IngressRules: ingress,
		EgressRules:  egress,
		HasL7:        hasL7,
		DefaultDeny:  defaultDeny,
		CreatedBy:    createdBy,
		CreatedAt:    createdAt,
		RawYAML:      rawYAML,
	}
}

// collectSpecs normalizes the spec/specs duality into a single slice.
func collectSpecs(obj map[string]interface{}) []map[string]interface{} {
	var out []map[string]interface{}
	if spec, ok, _ := unstructured.NestedMap(obj, "spec"); ok && spec != nil {
		out = append(out, spec)
	}
	if specs, ok, _ := unstructured.NestedSlice(obj, "specs"); ok {
		for _, s := range specs {
			if m, ok := s.(map[string]interface{}); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

// rulesPresent reports whether any toPorts entry carries L7 rules.
func rulesPresent(rules []interface{}) bool {
	for _, r := range rules {
		m, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		toPorts, ok, _ := unstructured.NestedSlice(m, "toPorts")
		if !ok {
			continue
		}
		for _, tp := range toPorts {
			tpm, ok := tp.(map[string]interface{})
			if !ok {
				continue
			}
			if l7, ok, _ := unstructured.NestedMap(tpm, "rules"); ok && len(l7) > 0 {
				return true
			}
		}
	}
	return false
}

// describeSelector renders endpointSelector / nodeSelector as "k=v, k2=v2",
// or "all endpoints" when the selector is empty (which matches everything).
func describeSelector(specs []map[string]interface{}) string {
	for _, spec := range specs {
		for _, field := range []string{"endpointSelector", "nodeSelector"} {
			sel, ok, _ := unstructured.NestedMap(spec, field)
			if !ok {
				continue
			}
			labels, hasLabels, _ := unstructured.NestedStringMap(sel, "matchLabels")
			if hasLabels && len(labels) > 0 {
				keys := make([]string, 0, len(labels))
				for k := range labels {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				parts := make([]string, 0, len(keys))
				for _, k := range keys {
					parts = append(parts, k+"="+labels[k])
				}
				return strings.Join(parts, ", ")
			}
			if expr, ok, _ := unstructured.NestedSlice(sel, "matchExpressions"); ok && len(expr) > 0 {
				return fmt.Sprintf("%d match expression(s)", len(expr))
			}
			return "all endpoints"
		}
	}
	return "—"
}
