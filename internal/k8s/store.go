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
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"

	"github.com/cooloo9871/sentinel/internal/policy"
)

// PolicyRecord is a policy as returned by the list/get API.
type PolicyRecord struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Scope     string `json:"scope"`  // "cluster" or "namespaced"
	Mode      string `json:"mode"`   // "Monitoring", "Protect", or "Mixed"
	CreatedAt string `json:"createdAt"`
	RawYAML   string `json:"rawYaml"`
}

// Store manages TracingPolicy and TracingPolicyNamespaced CRDs.
type Store struct {
	client     dynamic.Interface
	typed      *kubernetes.Clientset
	restConfig *rest.Config
}

// NewStore creates a Store wrapping the given clients.
func NewStore(client dynamic.Interface, typed *kubernetes.Clientset, cfg *rest.Config) *Store {
	return &Store{client: client, typed: typed, restConfig: cfg}
}

// List returns all cluster-wide and namespaced policies.
func (s *Store) List(ctx context.Context) ([]PolicyRecord, error) {
	var records []PolicyRecord

	clusterList, err := s.client.Resource(tracingPolicyGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list TracingPolicy: %w", err)
	}
	for _, item := range clusterList.Items {
		r, err := toRecord(item, "cluster")
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}

	nsList, err := s.client.Resource(tracingPolicyNamespacedGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list TracingPolicyNamespaced: %w", err)
	}
	for _, item := range nsList.Items {
		r, err := toRecord(item, "namespaced")
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}

	return records, nil
}

// Get returns a single policy by name and optional namespace.
func (s *Store) Get(ctx context.Context, name, namespace string) (PolicyRecord, error) {
	var item *unstructured.Unstructured
	var err error
	scope := "cluster"

	if namespace != "" {
		scope = "namespaced"
		item, err = s.client.Resource(tracingPolicyNamespacedGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	} else {
		item, err = s.client.Resource(tracingPolicyGVR).Get(ctx, name, metav1.GetOptions{})
	}
	if err != nil {
		return PolicyRecord{}, fmt.Errorf("get policy %q: %w", name, err)
	}
	return toRecord(*item, scope)
}

// Apply creates or updates a policy from a TracingPolicy struct.
func (s *Store) Apply(ctx context.Context, tp policy.TracingPolicy) error {
	data, err := json.Marshal(tp)
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}
	obj := &unstructured.Unstructured{}
	if err := json.Unmarshal(data, &obj.Object); err != nil {
		return fmt.Errorf("unmarshal to unstructured: %w", err)
	}

	name := tp.Metadata.Name
	ns := tp.Metadata.Namespace

	if ns != "" {
		return s.applyNamespaced(ctx, ns, name, obj)
	}
	return s.applyCluster(ctx, name, obj)
}

// ApplyRaw applies a raw YAML string to the cluster, detecting scope from the namespace field.
func (s *Store) ApplyRaw(ctx context.Context, rawYAML string) error {
	jsonBytes, err := yaml.YAMLToJSON([]byte(rawYAML))
	if err != nil {
		return fmt.Errorf("invalid YAML: %w", err)
	}
	obj := &unstructured.Unstructured{}
	if err := json.Unmarshal(jsonBytes, &obj.Object); err != nil {
		return fmt.Errorf("unmarshal YAML: %w", err)
	}

	name := obj.GetName()
	ns := obj.GetNamespace()

	if ns != "" {
		return s.applyNamespaced(ctx, ns, name, obj)
	}
	return s.applyCluster(ctx, name, obj)
}

// Delete removes a policy by name and optional namespace.
func (s *Store) Delete(ctx context.Context, name, namespace string) error {
	var err error
	if namespace != "" {
		err = s.client.Resource(tracingPolicyNamespacedGVR).Namespace(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	} else {
		err = s.client.Resource(tracingPolicyGVR).Delete(ctx, name, metav1.DeleteOptions{})
	}
	if err != nil {
		return fmt.Errorf("delete policy %q: %w", name, err)
	}
	return nil
}

// SecurityEvent is a security-relevant Kubernetes event returned by the API.
type SecurityEvent struct {
	Namespace         string `json:"namespace"`
	InvolvedKind      string `json:"involvedKind"`
	InvolvedName      string `json:"involvedName"`
	InvolvedNamespace string `json:"involvedNamespace"`
	Reason            string `json:"reason"`
	Message           string `json:"message"`
	Type              string `json:"type"`
	Count             int64  `json:"count"`
	FirstTime         string `json:"firstTime"`
	LastTime          string `json:"lastTime"`
	Source            string `json:"source"`
}

// ListSecurityEvents returns Warning-type events and Tetragon events across all namespaces.
func (s *Store) ListSecurityEvents(ctx context.Context) ([]SecurityEvent, error) {
	list, err := s.client.Resource(eventsGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}

	var events []SecurityEvent
	for _, item := range list.Items {
		evType, _, _ := unstructured.NestedString(item.Object, "type")
		source, _, _ := unstructured.NestedString(item.Object, "source", "component")

		isTetragon := strings.Contains(strings.ToLower(source), "tetragon")
		if evType != "Warning" && !isTetragon {
			continue
		}

		reason, _, _ := unstructured.NestedString(item.Object, "reason")
		message, _, _ := unstructured.NestedString(item.Object, "message")
		involvedKind, _, _ := unstructured.NestedString(item.Object, "involvedObject", "kind")
		involvedName, _, _ := unstructured.NestedString(item.Object, "involvedObject", "name")
		involvedNS, _, _ := unstructured.NestedString(item.Object, "involvedObject", "namespace")
		firstTime, _, _ := unstructured.NestedString(item.Object, "firstTimestamp")
		lastTime, _, _ := unstructured.NestedString(item.Object, "lastTimestamp")

		var count int64
		if v, ok, _ := unstructured.NestedFieldNoCopy(item.Object, "count"); ok {
			if n, ok := v.(int64); ok {
				count = n
			}
		}

		events = append(events, SecurityEvent{
			Namespace:         item.GetNamespace(),
			InvolvedKind:      involvedKind,
			InvolvedName:      involvedName,
			InvolvedNamespace: involvedNS,
			Reason:            reason,
			Message:           message,
			Type:              evType,
			Count:             count,
			FirstTime:         firstTime,
			LastTime:          lastTime,
			Source:            source,
		})
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].LastTime > events[j].LastTime
	})

	return events, nil
}

// ListNamespaces returns all namespace names in the cluster.
func (s *Store) ListNamespaces(ctx context.Context) ([]string, error) {
	list, err := s.client.Resource(namespaceGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}
	names := make([]string, 0, len(list.Items))
	for _, item := range list.Items {
		names = append(names, item.GetName())
	}
	return names, nil
}

// GetMode scans all policies and returns "Monitoring", "Protect", or "Mixed".
func (s *Store) GetMode(ctx context.Context) (string, error) {
	records, err := s.List(ctx)
	if err != nil {
		return "", err
	}
	if len(records) == 0 {
		return "Monitoring", nil
	}

	postCount, killCount := 0, 0
	for _, r := range records {
		var tp policy.TracingPolicy
		if err := yaml.Unmarshal([]byte(r.RawYAML), &tp); err != nil {
			continue
		}
		for _, kp := range tp.Spec.KProbes {
			for _, sel := range kp.Selectors {
				for _, act := range sel.MatchActions {
					switch act.Action {
					case policy.ActionPost:
						postCount++
					case policy.ActionSigkill:
						killCount++
					}
				}
			}
		}
	}

	if killCount == 0 {
		return "Monitoring", nil
	}
	if postCount == 0 {
		return "Protect", nil
	}
	return "Mixed", nil
}

// SetMode updates all policies to use either "Post" (Monitoring) or "Sigkill" (Protect).
func (s *Store) SetMode(ctx context.Context, mode string) error {
	action := policy.ActionPost
	if mode == "Protect" {
		action = policy.ActionSigkill
	}

	records, err := s.List(ctx)
	if err != nil {
		return err
	}

	for _, r := range records {
		var tp policy.TracingPolicy
		if err := yaml.Unmarshal([]byte(r.RawYAML), &tp); err != nil {
			return fmt.Errorf("parse policy %q: %w", r.Name, err)
		}
		for i := range tp.Spec.KProbes {
			for j := range tp.Spec.KProbes[i].Selectors {
				for k := range tp.Spec.KProbes[i].Selectors[j].MatchActions {
					tp.Spec.KProbes[i].Selectors[j].MatchActions[k].Action = action
				}
			}
		}
		if err := s.Apply(ctx, tp); err != nil {
			return fmt.Errorf("apply policy %q: %w", r.Name, err)
		}
	}
	return nil
}

func (s *Store) applyCluster(ctx context.Context, name string, obj *unstructured.Unstructured) error {
	_, err := s.client.Resource(tracingPolicyGVR).Create(ctx, obj, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !k8serrors.IsAlreadyExists(err) {
		return err
	}
	existing, err := s.client.Resource(tracingPolicyGVR).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	obj.SetResourceVersion(existing.GetResourceVersion())
	_, err = s.client.Resource(tracingPolicyGVR).Update(ctx, obj, metav1.UpdateOptions{})
	return err
}

func (s *Store) applyNamespaced(ctx context.Context, ns, name string, obj *unstructured.Unstructured) error {
	_, err := s.client.Resource(tracingPolicyNamespacedGVR).Namespace(ns).Create(ctx, obj, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !k8serrors.IsAlreadyExists(err) {
		return err
	}
	existing, err := s.client.Resource(tracingPolicyNamespacedGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	obj.SetResourceVersion(existing.GetResourceVersion())
	_, err = s.client.Resource(tracingPolicyNamespacedGVR).Namespace(ns).Update(ctx, obj, metav1.UpdateOptions{})
	return err
}

func toRecord(item unstructured.Unstructured, scope string) (PolicyRecord, error) {
	rawJSON, err := json.Marshal(item.Object)
	if err != nil {
		return PolicyRecord{}, err
	}
	rawYAML, err := yaml.JSONToYAML(rawJSON)
	if err != nil {
		return PolicyRecord{}, err
	}
	createdAt := ""
	if ts := item.GetCreationTimestamp(); !ts.IsZero() {
		createdAt = ts.UTC().Format("2006-01-02T15:04:05Z")
	}
	return PolicyRecord{
		Name:      item.GetName(),
		Namespace: item.GetNamespace(),
		Scope:     scope,
		Mode:      detectMode(string(rawYAML)),
		CreatedAt: createdAt,
		RawYAML:   string(rawYAML),
	}, nil
}

// detectMode returns "Monitoring", "Protect", or "Mixed" based on kprobe actions.
func detectMode(rawYAML string) string {
	var tp policy.TracingPolicy
	if err := yaml.Unmarshal([]byte(rawYAML), &tp); err != nil {
		return "Monitoring"
	}
	post, kill := 0, 0
	for _, kp := range tp.Spec.KProbes {
		for _, sel := range kp.Selectors {
			for _, act := range sel.MatchActions {
				switch act.Action {
				case policy.ActionSigkill:
					kill++
				case policy.ActionPost:
					post++
				// Unknown actions are intentionally ignored — they don't
				// contribute to either counter, matching GetMode's behaviour.
				}
			}
		}
	}
	if kill == 0 {
		return "Monitoring"
	}
	if post == 0 {
		return "Protect"
	}
	return "Mixed"
}

// SetPolicyMode updates all kprobe actions in a single policy.
func (s *Store) SetPolicyMode(ctx context.Context, name, namespace, mode string) error {
	action := policy.ActionPost
	if mode == "Protect" {
		action = policy.ActionSigkill
	}

	record, err := s.Get(ctx, name, namespace)
	if err != nil {
		return err
	}

	var tp policy.TracingPolicy
	if err := yaml.Unmarshal([]byte(record.RawYAML), &tp); err != nil {
		return fmt.Errorf("parse policy %q: %w", name, err)
	}
	for i := range tp.Spec.KProbes {
		for j := range tp.Spec.KProbes[i].Selectors {
			for k := range tp.Spec.KProbes[i].Selectors[j].MatchActions {
				tp.Spec.KProbes[i].Selectors[j].MatchActions[k].Action = action
			}
		}
	}
	return s.Apply(ctx, tp)
}

const discoveryPolicyName = "sentinel-discovery"

// discoveryPolicyYAML is a cluster-wide catch-all TracingPolicy that captures
// all file access and network connections across every pod — no selectors means
// every call is logged with action Post (Monitoring mode).
const discoveryPolicyYAML = `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: sentinel-discovery
spec:
  kprobes:
  - call: "security_file_permission"
    syscall: false
    args:
    - index: 0
      type: "file"
    - index: 1
      type: "int"
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
`

// labelsToSkip contains auto-generated Kubernetes labels that are too noisy
// or pod-instance-specific to be useful in a TracingPolicy podSelector.
var labelsToSkip = map[string]bool{
	"pod-template-hash":                   true,
	"controller-revision-hash":            true,
	"statefulset.kubernetes.io/pod-name":  true,
	"batch.kubernetes.io/job-completion-index": true,
}

// GetPodLabels returns the labels of a pod, filtering out noisy auto-generated ones.
func (s *Store) GetPodLabels(ctx context.Context, namespace, name string) (map[string]string, error) {
	pod, err := s.typed.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get pod %s/%s: %w", namespace, name, err)
	}
	result := make(map[string]string)
	for k, v := range pod.Labels {
		if !labelsToSkip[k] {
			result[k] = v
		}
	}
	return result, nil
}

// IsDiscoveryEnabled reports whether the sentinel-discovery policy is active.
func (s *Store) IsDiscoveryEnabled(ctx context.Context) bool {
	_, err := s.client.Resource(tracingPolicyGVR).Get(ctx, discoveryPolicyName, metav1.GetOptions{})
	return err == nil
}

// EnableDiscovery creates (or updates) the catch-all discovery policy.
func (s *Store) EnableDiscovery(ctx context.Context) error {
	return s.ApplyRaw(ctx, discoveryPolicyYAML)
}

// DisableDiscovery removes the catch-all discovery policy.
func (s *Store) DisableDiscovery(ctx context.Context) error {
	err := s.client.Resource(tracingPolicyGVR).Delete(ctx, discoveryPolicyName, metav1.DeleteOptions{})
	if k8serrors.IsNotFound(err) {
		return nil
	}
	return err
}
