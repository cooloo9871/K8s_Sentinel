package vulngate

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// Status is how the gate stands in the cluster, for the page.
type Status struct {
	// When the list was last written, or the gate last removed.
	UpdatedAt string `json:"updatedAt,omitempty"`
	// Why the last attempt failed. The cluster then still has what the attempt
	// before it wrote.
	Error string `json:"error,omitempty"`
	// Images over the limit, worst first.
	Images []ScannedImage `json:"images"`
	// Over the limit but not enforced: the list was full.
	LeftOut int `json:"leftOut"`
}

// ListGVR is the kind the list is kept in. deploy/sentinel.yaml defines it.
var ListGVR = schema.GroupVersionResource{Group: "sentinel.io", Version: "v1", Resource: "vulnerabilitygates"}

// Gate owns the three objects in the cluster and keeps them matching the
// settings and the scan results.
type Gate struct {
	client    kubernetes.Interface
	dyn       dynamic.Interface
	namespace string
	path      string
	// Every image a scan has a result for, from wherever results are kept.
	scanned func(ctx context.Context) []ScannedImage

	mu       sync.Mutex
	settings Settings
	status   Status
	wake     chan struct{}
}

// New loads the settings kept at path. namespace is Sentinel's own, which the
// gate never applies to.
func New(client kubernetes.Interface, dyn dynamic.Interface, namespace, path string, scanned func(ctx context.Context) []ScannedImage) *Gate {
	g := &Gate{
		client: client, dyn: dyn, namespace: namespace, path: path, scanned: scanned,
		settings: DefaultSettings(), status: Status{Images: []ScannedImage{}},
		wake: make(chan struct{}, 1),
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return g
	}
	var s Settings
	if err := json.Unmarshal(data, &s); err != nil {
		// The next save would replace the file, so keep what is there.
		log.Printf("vulngate: %s is not valid JSON (%v); kept as %s.corrupt", path, err, path)
		_ = os.Rename(path, path+".corrupt")
		return g
	}
	if s.Validate() == nil {
		g.settings = s
	}
	return g
}

func (g *Gate) Settings() Settings {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.settings
}

func (g *Gate) Status() Status {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.status
}

// Save stores new settings and has them applied straight away.
func (g *Gate) Save(s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := g.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, g.path); err != nil {
		return err
	}
	g.mu.Lock()
	g.settings = s
	g.mu.Unlock()
	g.Refresh()
	return nil
}

// Refresh asks for the list to be worked out again now, for a caller that knows
// the scan results just changed.
func (g *Gate) Refresh() {
	select {
	case g.wake <- struct{}{}:
	default:
	}
}

// Run keeps the cluster in step until ctx ends: at once, whenever asked, and
// every two minutes for scan results that changed without anyone saying.
func (g *Gate) Run(ctx context.Context) {
	tick := time.NewTicker(2 * time.Minute)
	defer tick.Stop()
	for {
		g.reconcile(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-g.wake:
		}
	}
}

func (g *Gate) reconcile(ctx context.Context) {
	if g.client == nil || g.dyn == nil {
		return
	}
	s := g.Settings()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	st := Status{Images: []ScannedImage{}}
	var err error
	if !s.Enabled {
		err = g.remove(ctx)
	} else {
		list := Build(g.scanned(ctx), s)
		st.Images, st.LeftOut = list.Images, list.LeftOut
		err = g.apply(ctx, s, list)
	}
	if ctx.Err() != nil && err == nil {
		return
	}
	st.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err != nil {
		log.Printf("vulngate: %v", err)
		st.Error = err.Error()
	}
	g.mu.Lock()
	g.status = st
	g.mu.Unlock()
}

// remove takes the gate out of the cluster. The binding goes first: it is what
// enforces, and a policy or a list without it does nothing.
func (g *Gate) remove(ctx context.Context) error {
	adm := g.client.AdmissionregistrationV1()
	gone := func(err error) error {
		if k8serrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	if err := gone(adm.ValidatingAdmissionPolicyBindings().Delete(ctx, Name, metav1.DeleteOptions{})); err != nil {
		return fmt.Errorf("remove the binding: %w", err)
	}
	if err := gone(adm.ValidatingAdmissionPolicies().Delete(ctx, Name, metav1.DeleteOptions{})); err != nil {
		return fmt.Errorf("remove the policy: %w", err)
	}
	// With the kind itself not installed there is no list to remove either.
	if err := gone(g.dyn.Resource(ListGVR).Delete(ctx, Name, metav1.DeleteOptions{})); err != nil && !noSuchKind(err) {
		return fmt.Errorf("remove the list: %w", err)
	}
	return nil
}

// apply writes the list, then the policy, then the binding, so that nothing
// enforces before there is something to enforce with.
func (g *Gate) apply(ctx context.Context, s Settings, list List) error {
	lists := g.dyn.Resource(ListGVR)
	images := make(map[string]any, len(list.Data))
	for k, v := range list.Data {
		images[k] = v
	}
	cur, err := lists.Get(ctx, Name, metav1.GetOptions{})
	switch {
	case noSuchKind(err):
		return fmt.Errorf("the VulnerabilityGate kind is not installed: apply deploy/sentinel.yaml again, which defines it")
	case k8serrors.IsNotFound(err):
		obj := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": ListGVR.Group + "/" + ListGVR.Version,
			"kind":       "VulnerabilityGate",
			"metadata":   map[string]any{"name": Name, "labels": map[string]any{"app.kubernetes.io/managed-by": "k8s-sentinel"}},
			"spec":       map[string]any{"images": images},
		}}
		if _, err := lists.Create(ctx, obj, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("write the list: %w", err)
		}
	case err != nil:
		return fmt.Errorf("read the list: %w", err)
	default:
		have, _, _ := unstructured.NestedStringMap(cur.Object, "spec", "images")
		if !sameData(have, list.Data) {
			if err := unstructured.SetNestedMap(cur.Object, images, "spec", "images"); err != nil {
				return fmt.Errorf("write the list: %w", err)
			}
			if _, err := lists.Update(ctx, cur, metav1.UpdateOptions{}); err != nil {
				return fmt.Errorf("write the list: %w", err)
			}
		}
	}

	adm := g.client.AdmissionregistrationV1()
	wantPolicy := policy()
	if cur, err := adm.ValidatingAdmissionPolicies().Get(ctx, Name, metav1.GetOptions{}); k8serrors.IsNotFound(err) {
		if _, err := adm.ValidatingAdmissionPolicies().Create(ctx, wantPolicy, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("write the policy: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("read the policy: %w", err)
	} else {
		// Written every time rather than compared: the stored spec carries the
		// API server's defaults, so it never equals the one built here, and an
		// update that changes nothing costs nothing.
		cur.Spec = wantPolicy.Spec
		if _, err := adm.ValidatingAdmissionPolicies().Update(ctx, cur, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("write the policy: %w", err)
		}
	}

	wantBinding := binding(s, g.namespace)
	if cur, err := adm.ValidatingAdmissionPolicyBindings().Get(ctx, Name, metav1.GetOptions{}); k8serrors.IsNotFound(err) {
		if _, err := adm.ValidatingAdmissionPolicyBindings().Create(ctx, wantBinding, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("write the binding: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("read the binding: %w", err)
	} else {
		cur.Spec = wantBinding.Spec
		if _, err := adm.ValidatingAdmissionPolicyBindings().Update(ctx, cur, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("write the binding: %w", err)
		}
	}
	return nil
}

// noSuchKind reports the API server not serving the list's kind at all, which
// is what a missing CRD looks like, as opposed to the one object being absent.
func noSuchKind(err error) bool {
	if err == nil {
		return false
	}
	if st, ok := err.(k8serrors.APIStatus); ok && k8serrors.IsNotFound(err) {
		if d := st.Status().Details; d != nil && d.Name == "" {
			return true
		}
	}
	return strings.Contains(err.Error(), "the server could not find the requested resource")
}

func sameData(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func labels() map[string]string {
	return map[string]string{"app.kubernetes.io/managed-by": "k8s-sentinel"}
}

// policy is the rule itself. It looks only at objects a person or a pipeline
// submits: a workload, or a pod nothing owns. What a controller creates from a
// workload already admitted, a ReplicaSet's pods when a node restarts for one,
// is left alone, so an image that goes over the limit tomorrow does not stop
// what is running today from coming back up.
func policy() *admissionv1.ValidatingAdmissionPolicy {
	// A list that cannot be evaluated admits: the gate must not be what stops a
	// cluster from deploying.
	ignore := admissionv1.Ignore
	forbidden := metav1.StatusReasonForbidden
	writes := []admissionv1.OperationType{admissionv1.Create, admissionv1.Update}
	rule := func(group string, resources ...string) admissionv1.NamedRuleWithOperations {
		return admissionv1.NamedRuleWithOperations{RuleWithOperations: admissionv1.RuleWithOperations{
			Operations: writes,
			Rule:       admissionv1.Rule{APIGroups: []string{group}, APIVersions: []string{"v1"}, Resources: resources},
		}}
	}
	return &admissionv1.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:   Name,
			Labels: labels(),
			Annotations: map[string]string{
				"sentinel.io/created-by": "sentinel-vulnerability-gate",
			},
		},
		Spec: admissionv1.ValidatingAdmissionPolicySpec{
			FailurePolicy: &ignore,
			ParamKind:     &admissionv1.ParamKind{APIVersion: ListGVR.Group + "/" + ListGVR.Version, Kind: "VulnerabilityGate"},
			MatchConstraints: &admissionv1.MatchResources{
				ResourceRules: []admissionv1.NamedRuleWithOperations{
					rule("", "pods"),
					rule("apps", "deployments", "statefulsets", "daemonsets", "replicasets"),
					rule("batch", "jobs", "cronjobs"),
				},
			},
			MatchConditions: []admissionv1.MatchCondition{{
				Name:       "not-created-by-a-controller",
				Expression: "!has(object.metadata.ownerReferences) || size(object.metadata.ownerReferences) == 0",
			}},
			Variables: []admissionv1.Variable{
				{
					Name:       "podSpec",
					Expression: "object.kind == 'Pod' ? object.spec : (object.kind == 'CronJob' ? object.spec.jobTemplate.spec.template.spec : object.spec.template.spec)",
				},
				{
					Name:       "images",
					Expression: "(variables.podSpec.containers + (has(variables.podSpec.initContainers) ? variables.podSpec.initContainers : [])).map(c, c.image)",
				},
				{
					Name:       "over",
					Expression: "has(params.spec) && has(params.spec.images) ? variables.images.filter(i, i in params.spec.images) : []",
				},
			},
			Validations: []admissionv1.Validation{{
				Expression: "size(variables.over) == 0",
				MessageExpression: "'image ' + variables.over[0] + ' is over the vulnerability limit set in K8s Sentinel: ' + " +
					"params.spec.images[variables.over[0]]",
				Reason: &forbidden,
			}},
		},
	}
}

// binding switches the policy on, in the mode and for the namespaces chosen.
func binding(s Settings, ownNamespace string) *admissionv1.ValidatingAdmissionPolicyBinding {
	// No list is no limit: with the object missing, everything is admitted.
	allow := admissionv1.AllowAction
	actions := []admissionv1.ValidationAction{admissionv1.Warn, admissionv1.Audit}
	if s.Mode == "deny" {
		actions = []admissionv1.ValidationAction{admissionv1.Deny}
	}
	// The cluster's own components and Sentinel's are never held back: a gate
	// that refused a system pod its restart would be an outage of its own making.
	excluded := map[string]bool{"kube-system": true, ownNamespace: true}
	for _, ns := range s.ExcludeNamespaces {
		excluded[ns] = true
	}
	values := make([]string, 0, len(excluded))
	for ns := range excluded {
		values = append(values, ns)
	}
	sort.Strings(values)
	return &admissionv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: Name, Labels: labels()},
		Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName:        Name,
			ValidationActions: actions,
			ParamRef: &admissionv1.ParamRef{
				Name: Name, ParameterNotFoundAction: &allow,
			},
			MatchResources: &admissionv1.MatchResources{
				NamespaceSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "kubernetes.io/metadata.name",
						Operator: metav1.LabelSelectorOpNotIn,
						Values:   values,
					}},
				},
			},
		},
	}
}
