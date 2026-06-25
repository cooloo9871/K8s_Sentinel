package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"

	"github.com/cooloo9871/sentinel/internal/policy"
)

const annotationCreatedBy = "sentinel.io/created-by"

// PolicyRecord is a policy as returned by the list/get API.
type PolicyRecord struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Scope     string `json:"scope"`      // "cluster" or "namespaced"
	Mode      string `json:"mode"`       // "Monitoring", "Protect", or "Mixed"
	CreatedBy string `json:"createdBy"`  // sentinel username or "k8s-apply"
	CreatedAt string `json:"createdAt"`
	RawYAML   string `json:"rawYaml"`
}

// Store manages TracingPolicy and TracingPolicyNamespaced CRDs.
type Store struct {
	client     dynamic.Interface
	typed      *kubernetes.Clientset
	restConfig *rest.Config
	modeMu     sync.RWMutex
	globalMode string // explicitly set by user; never auto-derived from policies
	Discovery  *DiscoveryProfileStore
	Templates  *TemplateStore
	containers *containerResolver
}

// NewStore creates a Store wrapping the given clients.
func NewStore(client dynamic.Interface, typed *kubernetes.Clientset, cfg *rest.Config) *Store {
	templatesFile := "/data/sentinel/templates.json"
	return &Store{
		client:     client,
		typed:      typed,
		restConfig: cfg,
		globalMode: "Monitoring",
		Discovery:  NewDiscoveryProfileStore(),
		Templates:  NewTemplateStore(templatesFile),
		containers: newContainerResolver(),
	}
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
func (s *Store) Apply(ctx context.Context, tp policy.TracingPolicy, createdBy string) error {
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
		return s.applyNamespaced(ctx, ns, name, obj, createdBy)
	}
	return s.applyCluster(ctx, name, obj, createdBy)
}

// ApplyRaw applies a raw YAML string to the cluster, detecting scope from the namespace field.
func (s *Store) ApplyRaw(ctx context.Context, rawYAML string, createdBy string) error {
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
		return s.applyNamespaced(ctx, ns, name, obj, createdBy)
	}
	return s.applyCluster(ctx, name, obj, createdBy)
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

// noisyLabelPrefixes are auto-generated labels that are not useful as pod selectors.
var noisyLabelPrefixes = []string{
	"pod-template-hash",
	"controller-revision-hash",
	"statefulset.kubernetes.io/pod-name",
}

// GetPodLabels returns the meaningful labels of a pod, filtering auto-generated noise.
func (s *Store) GetPodLabels(ctx context.Context, namespace, name string) (map[string]string, error) {
	pod, err := s.typed.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get pod %s/%s: %w", namespace, name, err)
	}
	labels := make(map[string]string)
outer:
	for k, v := range pod.Labels {
		for _, noisy := range noisyLabelPrefixes {
			if strings.HasPrefix(k, noisy) {
				continue outer
			}
		}
		labels[k] = v
	}
	return labels, nil
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

// IPInfo holds the resolved identity for a cluster IP.
type IPInfo struct {
	IP        string
	Name      string
	Namespace string
	Kind      string // "pod" | "service"
}

// ListClusterIPs returns a map of IP → IPInfo for all pods and services in the cluster.
// Used by the network topology handler to resolve destination IPs to workload names.
func (s *Store) ListClusterIPs(ctx context.Context) (map[string]IPInfo, error) {
	result := make(map[string]IPInfo)

	pods, err := s.typed.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, p := range pods.Items {
			if p.Status.PodIP != "" {
				result[p.Status.PodIP] = IPInfo{
					IP:        p.Status.PodIP,
					Name:      p.Name,
					Namespace: p.Namespace,
					Kind:      "pod",
				}
			}
		}
	}

	svcs, err := s.typed.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, svc := range svcs.Items {
			if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != "None" {
				result[svc.Spec.ClusterIP] = IPInfo{
					IP:        svc.Spec.ClusterIP,
					Name:      svc.Name,
					Namespace: svc.Namespace,
					Kind:      "service",
				}
			}
		}
	}

	return result, nil
}

// GetMode returns the explicitly set global enforcement mode.
// It never auto-derives the mode from policy actions.
func (s *Store) GetMode(ctx context.Context) (string, error) {
	s.modeMu.RLock()
	defer s.modeMu.RUnlock()
	return s.globalMode, nil
}

// SetMode applies the enforcement mode to all policies first, then updates the
// cached globalMode. If any policy apply fails the cache is not updated, so
// the displayed mode stays consistent with what was actually applied.
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
		if err := s.Apply(ctx, tp, ""); err != nil {
			return fmt.Errorf("apply policy %q: %w", r.Name, err)
		}
	}

	// Only update cached mode after all policies are successfully applied.
	s.modeMu.Lock()
	s.globalMode = mode
	s.modeMu.Unlock()
	return nil
}

func setCreatedByAnnotation(obj *unstructured.Unstructured, createdBy string) {
	if createdBy == "" {
		return
	}
	ann := obj.GetAnnotations()
	if ann == nil {
		ann = map[string]string{}
	}
	ann[annotationCreatedBy] = createdBy
	obj.SetAnnotations(ann)
}

func preserveCreatedBy(obj, existing *unstructured.Unstructured) {
	if v := existing.GetAnnotations()[annotationCreatedBy]; v != "" {
		ann := obj.GetAnnotations()
		if ann == nil {
			ann = map[string]string{}
		}
		ann[annotationCreatedBy] = v
		obj.SetAnnotations(ann)
	}
}

func (s *Store) applyCluster(ctx context.Context, name string, obj *unstructured.Unstructured, createdBy string) error {
	setCreatedByAnnotation(obj, createdBy)
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
	preserveCreatedBy(obj, existing)
	_, err = s.client.Resource(tracingPolicyGVR).Update(ctx, obj, metav1.UpdateOptions{})
	return err
}

func (s *Store) applyNamespaced(ctx context.Context, ns, name string, obj *unstructured.Unstructured, createdBy string) error {
	setCreatedByAnnotation(obj, createdBy)
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
	preserveCreatedBy(obj, existing)
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
	createdBy := "k8s-apply"
	if v := item.GetAnnotations()[annotationCreatedBy]; v != "" {
		createdBy = v
	}
	return PolicyRecord{
		Name:      item.GetName(),
		Namespace: item.GetNamespace(),
		Scope:     scope,
		Mode:      detectMode(string(rawYAML)),
		CreatedBy: createdBy,
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
	return s.Apply(ctx, tp, "")
}
