package k8s

import (
	"context"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"
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
	// Hubble flows do not carry a container name, so it is resolved here from the
	// pod list this cache already fetches. Every container of the pod is listed,
	// because all of them share one network namespace and one IP: the flow cannot
	// say which opened the connection, so they are all candidates and singling
	// one out would be a guess. An absent key means the pod was not in the cache
	// at all — a different problem, worth telling apart.
	podContainer map[string]string // "ns/pod" → container names, comma-separated
	// What it takes to recognise a kubelet health probe: the node the pod runs
	// on, and the ports its probes target. A connection from that node to one of
	// those ports is the kubelet checking the pod, not traffic worth graphing.
	podProbes map[string]podProbeTargets // "ns/pod"
}

type podProbeTargets struct {
	node  string
	ports map[string]bool
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
		podProbes:    map[string]podProbeTargets{},
	}
	if s.typed == nil || s.client == nil {
		return d
	}

	pods, err := s.typed.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	switch {
	case err != nil:
		// Previously discarded. A failed list leaves both policy attribution and
		// the container lookup empty, so a denial silently loses its policy name
		// and its container with nothing said about why.
		log.Printf("attribution: list pods: %v — denials will be missing their policy and container", err)
	case len(pods.Items) == 0:
		log.Printf("attribution: pod list returned nothing — check the ClusterRole grants pods/list cluster-wide")
	default:
		for _, p := range pods.Items {
			key := p.Namespace + "/" + p.Name
			d.podLabels[key] = p.Labels
			running := runningContainers(p)
			names := make([]string, 0, len(running))
			for _, c := range running {
				names = append(names, c.Name)
			}
			d.podContainer[key] = strings.Join(names, ", ")

			probe := podProbeTargets{node: p.Spec.NodeName, ports: map[string]bool{}}
			for _, c := range running {
				for _, pr := range []*corev1.Probe{c.LivenessProbe, c.ReadinessProbe, c.StartupProbe} {
					if port := probePort(pr, c); port != "" {
						probe.ports[port] = true
					}
				}
			}
			if len(probe.ports) > 0 {
				d.podProbes[key] = probe
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

// runningContainers returns the containers that live for the pod's whole life:
// its ordinary containers, plus native sidecars.
//
// A native sidecar is an init container with restartPolicy Always — a
// Kubernetes 1.29 feature, and how Istio injects its proxy on recent clusters.
// It shares the pod's network namespace and carries probes of its own, so
// reading spec.containers alone missed the sidecar's readiness probe on 15021
// entirely: the kubelet checking it looked like ordinary workload traffic that
// no filter could hide. The same omission left the sidecar out of the container
// list reported for the pod's flows.
//
// Ordinary init containers are excluded: they have finished by the time any
// flow is observed, and Kubernetes only permits probes on restartable ones.
func runningContainers(p corev1.Pod) []corev1.Container {
	out := make([]corev1.Container, 0, len(p.Spec.Containers)+1)
	out = append(out, p.Spec.Containers...)
	for _, c := range p.Spec.InitContainers {
		if c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			out = append(out, c)
		}
	}
	return out
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

// PodContainer returns the pod's containers, so a network event can carry the
// same Pod / Container detail as a Tetragon event. All of them are listed when
// the pod has several: they share one network namespace, so the flow cannot
// identify which opened the connection and every one is a candidate.
func (s *Store) PodContainer(ctx context.Context, podNs, pod string) string {
	if pod == "" {
		return ""
	}
	key := podNs + "/" + pod
	d := s.cachedAttribution(ctx)
	name, known := d.podContainer[key]
	// A pod the cache has never heard of, while the cache itself is populated,
	// is the one case that is neither by design nor already reported by the load
	// above. Say so once per pod: this runs per flow, and a workload retrying a
	// denied connection in a loop would otherwise fill the log with one line.
	if !known && len(d.podContainer) > 0 {
		if _, warned := s.warnedPods.LoadOrStore(key, true); !warned {
			log.Printf("attribution: pod %s absent from a cache of %d pods — no container name for its flows", key, len(d.podContainer))
		}
	}
	return name
}

// probePort returns the port a probe targets, resolving a named port against the
// container's own declarations. Exec probes have no port and are not network
// traffic at all.
func probePort(p *corev1.Probe, c corev1.Container) string {
	var target intstr.IntOrString
	switch {
	case p == nil:
		return ""
	case p.HTTPGet != nil:
		target = p.HTTPGet.Port
	case p.TCPSocket != nil:
		target = p.TCPSocket.Port
	case p.GRPC != nil:
		return strconv.Itoa(int(p.GRPC.Port))
	default:
		return ""
	}
	if target.Type == intstr.Int {
		return strconv.Itoa(int(target.IntVal))
	}
	for _, cp := range c.Ports {
		if cp.Name == target.StrVal {
			return strconv.Itoa(int(cp.ContainerPort))
		}
	}
	return ""
}

// IsHealthProbe reports whether a connection is the kubelet checking a pod:
// coming from the node that pod runs on, to a port one of its probes targets.
// Both conditions matter — the same port reached from anywhere else is ordinary
// traffic, and the same node reaching another port is not a probe.
func (s *Store) IsHealthProbe(ctx context.Context, srcNode, podNs, pod, port string) bool {
	if srcNode == "" || pod == "" || port == "" {
		return false
	}
	probe, ok := s.cachedAttribution(ctx).podProbes[podNs+"/"+pod]
	return ok && probe.node == srcNode && probe.ports[port]
}
