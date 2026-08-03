package k8s

import (
	"context"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Hubble only names a policy when an explicit ingressDeny/egressDeny rule fired.
// The far more common allowlist policy — an `ingress`/`egress` section that
// switches the endpoint to default-deny — blocks traffic by the *absence* of an
// allow rule, so Hubble has no rule to report. Without the lookup in this file
// those denials would produce no Security Event at all, even though the user
// created the policy that caused them.
//
// So when correlation gives nothing, we work out which of the user's own
// policies govern the denied pod in the denied direction, and attribute to
// those. It is a claim about which policy is responsible, never an invention:
// if no policy matches, no event is produced.

// policySelector is one policy's endpoint selector, reduced to what attribution
// needs.
type policySelector struct {
	Name        string
	Namespace   string // empty for cluster-wide policies
	MatchLabels map[string]string
	// Whether the policy carries rules in each direction. A policy with no
	// egress section cannot be responsible for an egress denial.
	HasIngress bool
	HasEgress  bool
	// Selectors using matchExpressions are not evaluated; attributing on a
	// partial match would name the wrong policy.
	Unevaluatable bool
}

type attributionData struct {
	policies  []policySelector
	podLabels map[string]map[string]string // "ns/pod" → labels
	// Hubble flows do not carry a container name, so it is resolved here from
	// the pod list this cache already fetches. Only recorded when the pod has
	// exactly one container: with several, the flow does not say which one
	// opened the connection and naming one would be a guess.
	podContainer map[string]string // "ns/pod" → sole container name
}

// cachedAttribution refreshes policy selectors and pod labels at most every 30s,
// matching the other lookup caches.
func (s *Store) cachedAttribution(ctx context.Context) attributionData {
	s.attrMu.RLock()
	if time.Now().Before(s.attrExpiry) && s.attrData != nil {
		d := *s.attrData
		s.attrMu.RUnlock()
		return d
	}
	s.attrMu.RUnlock()

	fresh := s.loadAttributionData(ctx)
	s.attrMu.Lock()
	s.attrData = &fresh
	s.attrExpiry = time.Now().Add(30 * time.Second)
	s.attrMu.Unlock()
	return fresh
}

func (s *Store) loadAttributionData(ctx context.Context) attributionData {
	d := attributionData{
		podLabels:    map[string]map[string]string{},
		podContainer: map[string]string{},
	}
	if s.typed == nil || s.client == nil {
		return d
	}

	if pods, err := s.typed.CoreV1().Pods("").List(ctx, metav1.ListOptions{}); err == nil {
		for _, p := range pods.Items {
			key := p.Namespace + "/" + p.Name
			d.podLabels[key] = p.Labels
			if len(p.Spec.Containers) == 1 {
				d.podContainer[key] = p.Spec.Containers[0].Name
			}
		}
	}

	// Cilium allows either one `spec` or a list of `specs`, and each spec carries
	// its own endpointSelector and its own rules. Merging them into one selector
	// let the last spec's labels win and pooled every spec's directions
	// together — so a policy whose specs govern different workloads was
	// attributed to the wrong one. Each spec is therefore its own candidate.
	collect := func(items []unstructured.Unstructured, clusterWide bool) {
		for _, item := range items {
			ns := ""
			if !clusterWide {
				ns = item.GetNamespace()
			}
			for _, spec := range collectSpecs(item.Object) {
				sel := policySelector{Name: item.GetName(), Namespace: ns}
				if v, ok, _ := unstructured.NestedSlice(spec, "ingress"); ok && len(v) > 0 {
					sel.HasIngress = true
				}
				if v, ok, _ := unstructured.NestedSlice(spec, "ingressDeny"); ok && len(v) > 0 {
					sel.HasIngress = true
				}
				if v, ok, _ := unstructured.NestedSlice(spec, "egress"); ok && len(v) > 0 {
					sel.HasEgress = true
				}
				if v, ok, _ := unstructured.NestedSlice(spec, "egressDeny"); ok && len(v) > 0 {
					sel.HasEgress = true
				}
				if labels, ok, _ := unstructured.NestedStringMap(spec, "endpointSelector", "matchLabels"); ok {
					sel.MatchLabels = labels
				}
				if expr, ok, _ := unstructured.NestedSlice(spec, "endpointSelector", "matchExpressions"); ok && len(expr) > 0 {
					sel.Unevaluatable = true
				}
				d.policies = append(d.policies, sel)
			}
		}
	}

	if list, err := s.client.Resource(cnpGVR).Namespace("").List(ctx, metav1.ListOptions{}); err == nil {
		collect(list.Items, false)
	}
	if list, err := s.client.Resource(ccnpGVR).List(ctx, metav1.ListOptions{}); err == nil {
		collect(list.Items, true)
	}
	return d
}

// matches reports whether this policy selects the given pod. Cilium's selector
// is a subset match: every label in the selector must be present on the pod.
func (p policySelector) matches(podNs string, podLabels map[string]string) bool {
	if p.Unevaluatable {
		return false
	}
	// A namespaced policy only governs pods in its own namespace.
	if p.Namespace != "" && p.Namespace != podNs {
		return false
	}
	for k, want := range p.MatchLabels {
		// Cilium prefixes Kubernetes labels with "k8s:" in some selectors, and
		// exposes the pod's namespace as a pseudo-label.
		key := strings.TrimPrefix(k, "k8s:")
		if key == "io.kubernetes.pod.namespace" {
			if want != podNs {
				return false
			}
			continue
		}
		if podLabels[key] != want {
			return false
		}
	}
	// An empty selector matches every endpoint in scope, which is intentional
	// in Cilium (e.g. namespace-wide isolation).
	return true
}

// attributePolicyDenial names the policies that govern the denied pod in the
// denied direction. Returns an empty string when none match, so the caller can
// skip the event rather than report a policy that does not exist.
func (s *Store) AttributePolicyDenial(ctx context.Context, podNs, pod, direction string) string {
	if pod == "" {
		return ""
	}
	d := s.cachedAttribution(ctx)
	labels, known := d.podLabels[podNs+"/"+pod]
	if !known {
		return "" // pod already gone; cannot verify which policy selects it
	}

	var names []string
	seen := map[string]bool{}
	for _, p := range d.policies {
		switch direction {
		case "egress":
			if !p.HasEgress {
				continue
			}
		case "ingress":
			if !p.HasIngress {
				continue
			}
		default:
			// Direction unknown: still require the policy to carry rules
			// somewhere, so a policy that cannot deny anything is never named.
			if !p.HasIngress && !p.HasEgress {
				continue
			}
		}
		if p.matches(podNs, labels) && !seen[p.Name] {
			seen[p.Name] = true
			names = append(names, p.Name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	// Several policies can govern one pod in one direction, and a default-deny
	// drop cannot be pinned to one of them. Naming all candidates is the honest
	// answer; naming an arbitrary one would send the operator to the wrong rule.
	return joinSorted(names)
}

// joinSorted renders a deterministic, comma-separated policy list.
func joinSorted(names []string) string {
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// PodContainer returns the pod's container name when it has exactly one, so a
// network event can carry the same Pod / Container detail as a Tetragon event.
// Empty for multi-container pods, where the flow does not identify which
// container opened the connection.
func (s *Store) PodContainer(ctx context.Context, podNs, pod string) string {
	if pod == "" {
		return ""
	}
	return s.cachedAttribution(ctx).podContainer[podNs+"/"+pod]
}
