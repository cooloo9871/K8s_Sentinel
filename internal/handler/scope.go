package handler

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

// scope is the namespaces a signed-in account is limited to. Empty is the
// whole cluster.
//
// A limited account sees and changes what lives in its namespaces and nothing
// that belongs to the cluster as a whole: cluster-wide policies, the settings,
// the other accounts. The one thing it sees whole is the Network Topology,
// where it can still act only on its own pods.
type scope []string

func scopeOf(r *http.Request) scope {
	if c := claimsFromCtx(r); c != nil {
		return c.Namespaces
	}
	return nil
}

func (s scope) cluster() bool { return len(s) == 0 }

// allows reports whether something in the given namespace is the account's to
// see. A thing with no namespace belongs to the cluster.
func (s scope) allows(namespace string) bool {
	if s.cluster() {
		return true
	}
	for _, ns := range s {
		if ns == namespace {
			return true
		}
	}
	return false
}

// inScope keeps the items whose namespace the account may see.
func inScope[T any](s scope, items []T, namespace func(T) string) []T {
	if s.cluster() {
		return items
	}
	kept := make([]T, 0, len(items))
	for _, it := range items {
		if s.allows(namespace(it)) {
			kept = append(kept, it)
		}
	}
	return kept
}

// clusterWide refuses an account that is limited to namespaces: what is behind
// it belongs to the cluster.
func clusterWide(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !scopeOf(r).cluster() {
			writeError(w, http.StatusForbidden, "this account is limited to its namespaces")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// refuseOutside writes the refusal for a namespace the account may not touch
// and reports whether it did.
func refuseOutside(w http.ResponseWriter, r *http.Request, namespace string) bool {
	if scopeOf(r).allows(namespace) {
		return false
	}
	if namespace == "" {
		writeError(w, http.StatusForbidden, "this account is limited to its namespaces and cannot reach what is cluster-wide")
	} else {
		writeError(w, http.StatusForbidden, fmt.Sprintf("this account has no access to namespace %q", namespace))
	}
	return true
}

// cleanNamespaces trims, de-duplicates and sorts a list of namespaces, and
// refuses a name Kubernetes would not accept.
func cleanNamespaces(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, ns := range in {
		ns = strings.TrimSpace(ns)
		if ns == "" || seen[ns] {
			continue
		}
		if errs := validation.IsDNS1123Label(ns); len(errs) > 0 {
			return nil, fmt.Errorf("%q is not a namespace name: %s", ns, errs[0])
		}
		seen[ns] = true
		out = append(out, ns)
	}
	sort.Strings(out)
	return out, nil
}
