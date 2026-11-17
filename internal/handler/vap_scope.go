package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	"github.com/cooloo9871/K8s_Sentinel/internal/k8s"
	"github.com/cooloo9871/K8s_Sentinel/internal/vulngate"
)

// An admission policy is the cluster's, yet an admin of some namespaces may
// make one for them. What it writes is checked here and marked with its
// namespaces; internal/k8s/vap_scope.go says what the mark then guarantees.

// refusal is an error with the HTTP status it should be answered with.
type refusal struct {
	status int
	msg    string
}

func (r *refusal) Error() string { return r.msg }

func refuse(status int, format string, args ...any) error {
	return &refusal{status, fmt.Sprintf(format, args...)}
}

func writeRefusal(w http.ResponseWriter, err error) {
	var r *refusal
	if errors.As(err, &r) {
		http.Error(w, r.msg, r.status)
		return
	}
	http.Error(w, err.Error(), http.StatusBadRequest)
}

// manages reports whether something marked for the given namespaces is the
// account's to see and change: it is marked, and for no namespace outside.
func (s scope) manages(namespaces []string) bool {
	if s.cluster() {
		return true
	}
	if len(namespaces) == 0 {
		return false
	}
	for _, ns := range namespaces {
		if !s.allows(ns) {
			return false
		}
	}
	return true
}

// vapReader is what the checks read from the cluster.
type vapReader interface {
	GetVAP(ctx context.Context, name string) (k8s.VAPRecord, error)
	GetVAPBinding(ctx context.Context, name string) (k8s.VAPBindingRecord, error)
	ListVAPBindings(ctx context.Context) ([]k8s.VAPBindingRecord, error)
}

func parseManifest(rawYAML, kind string) (*unstructured.Unstructured, error) {
	jsonBytes, err := yaml.YAMLToJSON([]byte(rawYAML))
	if err != nil {
		return nil, refuse(http.StatusBadRequest, "invalid YAML: %v", err)
	}
	obj := &unstructured.Unstructured{}
	if err := json.Unmarshal(jsonBytes, &obj.Object); err != nil {
		return nil, refuse(http.StatusBadRequest, "invalid YAML: %v", err)
	}
	if obj.GetKind() != kind {
		return nil, refuse(http.StatusBadRequest, "kind must be %s", kind)
	}
	if obj.GetName() == "" {
		return nil, refuse(http.StatusBadRequest, "metadata.name is required")
	}
	return obj, nil
}

func manifestYAML(obj *unstructured.Unstructured) (string, error) {
	out, err := yaml.Marshal(obj.Object)
	return string(out), err
}

// limitPolicy checks a policy an account limited to namespaces wants to write,
// and returns it marked for those namespaces.
func limitPolicy(ctx context.Context, store vapReader, sc scope, rawYAML string) (string, error) {
	obj, err := parseManifest(rawYAML, "ValidatingAdmissionPolicy")
	if err != nil {
		return "", err
	}
	name := obj.GetName()
	owner := []string(sc)
	existing, err := store.GetVAP(ctx, name)
	switch {
	case err == nil:
		if !sc.manages(existing.Namespaces) {
			// The name is taken by a policy the account cannot see, which it
			// has to be told: names are the cluster's, and nothing on its
			// own pages would explain the refusal.
			return "", refuse(http.StatusConflict, "An admission policy named %q already exists. Choose another name.", name)
		}
		// It stays whose it was: a save cannot take it from the others it is for.
		owner = existing.Namespaces
	case k8serrors.IsNotFound(err):
		// A binding waiting for a policy of this name would start enforcing
		// it, wherever that binding points.
		bindings, err := store.ListVAPBindings(ctx)
		if err != nil {
			return "", err
		}
		for _, b := range bindings {
			if b.PolicyName == name {
				return "", refuse(http.StatusConflict, "The name %q is already in use by a binding. Choose another name.", name)
			}
		}
		// It may be made for fewer namespaces than the account has.
		if asked := k8s.OwnerNamespaces(obj); len(asked) > 0 && sc.manages(asked) {
			owner = asked
		}
	default:
		return "", err
	}

	// Parameters are read with Sentinel's own access and can be echoed in a
	// refusal message: a policy could be written to read out any object. The
	// one kind allowed is the scan counts, which the vulnerability rules need.
	if kind, found, _ := unstructured.NestedMap(obj.Object, "spec", "paramKind"); found {
		if kind["apiVersion"] != "sentinel.io/v1" || kind["kind"] != "VulnerabilityGate" {
			return "", refuse(http.StatusForbidden, "this account's policies cannot take parameters other than the vulnerability counts")
		}
	}
	k8s.SetOwnerNamespaces(obj, owner)
	return manifestYAML(obj)
}

// limitBinding checks a binding an account limited to namespaces wants to
// write, and returns it marked.
func limitBinding(ctx context.Context, store vapReader, sc scope, rawYAML string) (string, error) {
	obj, err := parseManifest(rawYAML, "ValidatingAdmissionPolicyBinding")
	if err != nil {
		return "", err
	}
	name := obj.GetName()
	if existing, err := store.GetVAPBinding(ctx, name); err == nil {
		if !sc.manages(existing.Namespaces) {
			return "", refuse(http.StatusConflict, "A binding named %q already exists. Choose another name.", name)
		}
	} else if !k8serrors.IsNotFound(err) {
		return "", err
	}

	policyName, _, _ := unstructured.NestedString(obj.Object, "spec", "policyName")
	policy, err := store.GetVAP(ctx, policyName)
	if err != nil || !sc.manages(policy.Namespaces) {
		// The same answer whether it is missing or another's, so that this
		// does not tell which names are taken.
		return "", refuse(http.StatusForbidden, "admission policy %q is not one this account can bind", policyName)
	}

	held, ok := k8s.PinnedNamespaces(obj)
	if !ok {
		return "", refuse(http.StatusForbidden, "this account's bindings must name the namespaces they apply in (Only these namespaces)")
	}
	for _, ns := range held {
		if !sc.allows(ns) {
			return "", refuse(http.StatusForbidden, "this account has no access to namespace %q", ns)
		}
		if !(scope(policy.Namespaces)).allows(ns) {
			return "", refuse(http.StatusForbidden, "admission policy %q is not for namespace %q", policyName, ns)
		}
	}

	if ref, found, _ := unstructured.NestedMap(obj.Object, "spec", "paramRef"); found {
		_, otherNs := ref["namespace"]
		_, selector := ref["selector"]
		if ref["name"] != vulngate.Name || otherNs || selector {
			return "", refuse(http.StatusForbidden, "this account's bindings cannot pass parameters other than the vulnerability counts")
		}
	}
	k8s.SetOwnerNamespaces(obj, held)
	return manifestYAML(obj)
}
