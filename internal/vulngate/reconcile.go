package vulngate

import (
	"context"
	"fmt"
	"log"
	"reflect"
	"regexp"
	"strings"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// ListGVR is the kind the list is kept in. deploy/sentinel.yaml defines it.
var ListGVR = schema.GroupVersionResource{Group: "sentinel.io", Version: "v1", Resource: "vulnerabilitygates"}

// Gate keeps the list in the cluster matching the scan results.
type Gate struct {
	client    kubernetes.Interface
	dyn       dynamic.Interface
	namespace string
	// Every image a scan has a result for, from wherever results are kept.
	// named is the vulnerabilities some policy refuses by ID; each image comes
	// back with the ones among them it has. ok is false when the results could
	// not be read, which is not the same as there being none.
	scanned func(ctx context.Context, named map[string]bool) (images []ScannedImage, ok bool)
	wake    chan struct{}

	legacyGone bool
	lastErr    string
}

// New makes the gate. namespace is Sentinel's own, which the policies never
// apply to.
func New(client kubernetes.Interface, dyn dynamic.Interface, namespace string, scanned func(ctx context.Context, named map[string]bool) ([]ScannedImage, bool)) *Gate {
	return &Gate{client: client, dyn: dyn, namespace: namespace, scanned: scanned, wake: make(chan struct{}, 1)}
}

// Refresh has the list worked out again now, for a caller that knows a policy
// just changed which vulnerabilities are named.
func (g *Gate) Refresh() {
	if g == nil {
		return
	}
	select {
	case g.wake <- struct{}{}:
	default:
	}
}

// NamedVariable is the policy variable that lists the vulnerabilities a policy
// refuses by ID, as a CEL list of quoted strings. The Admission Policy page
// writes it; this reads it back to know what to look for in the scan results.
const NamedVariable = "blockedCVEs"

var quoted = regexp.MustCompile(`'([^']+)'`)

// named is every vulnerability ID some policy in the cluster refuses.
func (g *Gate) named(ctx context.Context) (map[string]bool, error) {
	policies, err := g.client.AdmissionregistrationV1().ValidatingAdmissionPolicies().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("read the admission policies: %w", err)
	}
	out := map[string]bool{}
	for _, p := range policies.Items {
		if p.Spec.ParamKind == nil || p.Spec.ParamKind.Kind != "VulnerabilityGate" {
			continue
		}
		for _, v := range p.Spec.Variables {
			if v.Name != NamedVariable {
				continue
			}
			for _, m := range quoted.FindAllStringSubmatch(v.Expression, -1) {
				out[m[1]] = true
			}
		}
	}
	return out, nil
}

// Run keeps the list in step with the scan results until ctx ends.
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

func (g *Gate) reconcile(parent context.Context) {
	if g.client == nil || g.dyn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(parent, time.Minute)
	defer cancel()

	if !g.legacyGone {
		if err := g.removeLegacy(ctx); err != nil {
			log.Printf("vulngate: %v", err)
		} else {
			g.legacyGone = true
		}
	}
	named, err := g.named(ctx)
	var list List
	if err == nil {
		// Reading the results has its own time limit, so the write gets a
		// fresh one rather than what the read left of this one.
		images, ok := g.scanned(ctx, named)
		if !ok {
			// The list in the cluster stays as it is: emptying it because the
			// results could not be read would admit everything it refuses.
			err = fmt.Errorf("the scan results could not be read; the list is left as it was")
		} else {
			list = Build(images)
			wctx, wcancel := context.WithTimeout(parent, time.Minute)
			err = g.write(wctx, list)
			wcancel()
		}
	}
	if parent.Err() != nil {
		return // shutting down
	}
	// Said once per change, not every two minutes.
	msg := ""
	if err != nil {
		msg = err.Error()
	} else if list.LeftOut > 0 {
		msg = fmt.Sprintf("the list is full: %d scanned images with the fewest vulnerabilities are not in it and are admitted", list.LeftOut)
	}
	if msg != g.lastErr {
		if msg != "" {
			log.Printf("vulngate: %s", msg)
		}
		g.lastErr = msg
	}
}

// removeLegacy takes out the policy and binding v0.65.0 made by itself. They
// read the list in a form it no longer has. The policies made on the Admission
// Policy page carry no such label and are left alone.
func (g *Gate) removeLegacy(ctx context.Context) error {
	adm := g.client.AdmissionregistrationV1()
	ours := func(m metav1.ObjectMeta) bool { return m.Labels["app.kubernetes.io/managed-by"] == "k8s-sentinel" }
	// The binding goes first: it is what enforces.
	if b, err := adm.ValidatingAdmissionPolicyBindings().Get(ctx, Name, metav1.GetOptions{}); err == nil && ours(b.ObjectMeta) {
		if err := adm.ValidatingAdmissionPolicyBindings().Delete(ctx, Name, metav1.DeleteOptions{}); err != nil && !k8serrors.IsNotFound(err) {
			return fmt.Errorf("remove the v0.65.0 binding: %w", err)
		}
		log.Printf("vulngate: removed the binding v0.65.0 made; make the policy again on the Admission Policy page")
	} else if err != nil && !k8serrors.IsNotFound(err) {
		return fmt.Errorf("read the v0.65.0 binding: %w", err)
	}
	if p, err := adm.ValidatingAdmissionPolicies().Get(ctx, Name, metav1.GetOptions{}); err == nil && ours(p.ObjectMeta) {
		if err := adm.ValidatingAdmissionPolicies().Delete(ctx, Name, metav1.DeleteOptions{}); err != nil && !k8serrors.IsNotFound(err) {
			return fmt.Errorf("remove the v0.65.0 policy: %w", err)
		}
	} else if err != nil && !k8serrors.IsNotFound(err) {
		return fmt.Errorf("read the v0.65.0 policy: %w", err)
	}
	return nil
}

// spec is the list as the object holds it.
func (g *Gate) spec(list List) map[string]any {
	images := make(map[string]any, len(list.Data))
	for k, c := range list.Data {
		images[k] = map[string]any{
			"critical": int64(c.Critical), "high": int64(c.High),
			"fixableCritical": int64(c.FixableCritical), "fixableHigh": int64(c.FixableHigh),
		}
		if ids := list.CVEs[k]; len(ids) > 0 {
			cves := make([]any, len(ids))
			for i, id := range ids {
				cves[i] = id
			}
			images[k].(map[string]any)["cves"] = cves
		}
	}
	// The cluster's own components and Sentinel's are never held back: a policy
	// that refused the scanner its next Job would leave the list stale for good.
	exempt := []any{"kube-system"}
	if g.namespace != "" && g.namespace != "kube-system" {
		exempt = append(exempt, g.namespace)
	}
	return map[string]any{"exemptNamespaces": exempt, "images": images}
}

func (g *Gate) write(ctx context.Context, list List) error {
	lists := g.dyn.Resource(ListGVR)
	want := g.spec(list)
	cur, err := lists.Get(ctx, Name, metav1.GetOptions{})
	switch {
	case noSuchKind(err):
		return fmt.Errorf("the VulnerabilityGate kind is not installed: apply deploy/sentinel.yaml again, which defines it")
	case k8serrors.IsNotFound(err):
		obj := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": ListGVR.Group + "/" + ListGVR.Version,
			"kind":       "VulnerabilityGate",
			"metadata":   map[string]any{"name": Name, "labels": map[string]any{"app.kubernetes.io/managed-by": "k8s-sentinel"}},
			"spec":       want,
		}}
		if _, err := lists.Create(ctx, obj, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("write the list (if the kind is from v0.65.0, apply deploy/sentinel.yaml again): %w", err)
		}
	case err != nil:
		return fmt.Errorf("read the list: %w", err)
	default:
		if reflect.DeepEqual(cur.Object["spec"], want) {
			return nil
		}
		cur.Object["spec"] = want
		got, err := lists.Update(ctx, cur, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("write the list (if the kind is from v0.65.0, apply deploy/sentinel.yaml again): %w", err)
		}
		// An older definition of the kind drops the fields it does not know,
		// and a policy that reads them then admits everything.
		if !reflect.DeepEqual(got.Object["spec"], want) {
			return fmt.Errorf("the VulnerabilityGate kind is older than this Sentinel and did not keep every count: apply deploy/sentinel.yaml again")
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
