package vulngate

import (
	"context"
	"strconv"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
)

// An image no limit could refuse is not worth a place in the list.
func TestImagesWithCriticalOrHighAreListedWithTheirCounts(t *testing.T) {
	list := Build([]ScannedImage{
		{Ref: "quay.io/org/bad:1", Counts: Counts{Critical: 1}},
		{Ref: "quay.io/org/clean:1"},
		{Ref: "quay.io/org/highs:1", Counts: Counts{High: 11}},
	})
	if got := list.Data["quay.io/org/bad:1"]; got != (Counts{Critical: 1}) {
		t.Errorf("bad = %+v", got)
	}
	if got := list.Data["quay.io/org/highs:1"]; got != (Counts{High: 11}) {
		t.Errorf("highs = %+v", got)
	}
	if _, ok := list.Data["quay.io/org/clean:1"]; ok {
		t.Error("a clean image was listed")
	}
}

// The policy compares strings, and a pod spec may write a Docker Hub image
// several ways. A scan of any one of them has to stop all of them.
func TestEverySpellingOfADockerHubImageIsListed(t *testing.T) {
	for _, scannedAs := range []string{
		"nginx", "nginx:latest", "docker.io/library/nginx:latest", "registry.hub.docker.com/library/nginx",
	} {
		list := Build([]ScannedImage{{Ref: scannedAs, Counts: Counts{Critical: 3}}})
		for _, written := range []string{
			"nginx", "nginx:latest", "library/nginx", "docker.io/nginx", "docker.io/library/nginx:latest",
			"index.docker.io/library/nginx",
		} {
			if _, ok := list.Data[written]; !ok {
				t.Errorf("scanned as %q: a pod writing %q is not stopped", scannedAs, written)
			}
		}
		if _, ok := list.Data["nginx:1.27"]; ok {
			t.Errorf("scanned as %q: another tag was listed", scannedAs)
		}
	}
}

func TestOrganisationAndPrivateRegistryImages(t *testing.T) {
	list := Build([]ScannedImage{
		{Ref: "bitnami/redis:7", Counts: Counts{Critical: 1}},
		{Ref: "harbor.internal:8443/team/app:v1", Counts: Counts{Critical: 1}},
		{Ref: "quay.io/org/app@sha256:abc", Counts: Counts{Critical: 1}},
	})
	for _, written := range []string{
		"bitnami/redis:7", "docker.io/bitnami/redis:7",
		"harbor.internal:8443/team/app:v1", "quay.io/org/app@sha256:abc",
	} {
		if _, ok := list.Data[written]; !ok {
			t.Errorf("%q is not stopped", written)
		}
	}
	if _, ok := list.Data["library/bitnami/redis:7"]; ok {
		t.Error("an organisation image was given the library/ prefix")
	}
}

// The same image scanned twice: the worse result stands.
func TestTheWorseOfTwoResultsForOneImageWins(t *testing.T) {
	list := Build([]ScannedImage{
		{Ref: "nginx:1.25", Counts: Counts{Critical: 0, High: 2}},
		{Ref: "docker.io/library/nginx:1.25", Counts: Counts{Critical: 4}},
	})
	if got := list.Data["nginx:1.25"]; got.Critical != 4 {
		t.Fatalf("counts = %+v", got)
	}
}

// One scan knows of the criticals, the other of the highs and of what can be
// fixed: a policy on any of the four counts has to see the higher figure.
func TestEachCountIsTheHigherOfTheTwoResults(t *testing.T) {
	list := Build([]ScannedImage{
		{Ref: "quay.io/a/b:1", Counts: Counts{Critical: 5, High: 3}},
		{Ref: "quay.io/a/b:1", Counts: Counts{Critical: 1, High: 50, FixableCritical: 1, FixableHigh: 50}},
	})
	if got, want := list.Data["quay.io/a/b:1"], (Counts{Critical: 5, High: 50, FixableCritical: 1, FixableHigh: 50}); got != want {
		t.Errorf("counts = %+v, want %+v", got, want)
	}
}

// Charts and Renovate pin "repo:tag@sha256:...". The policy compares the string
// the pod spec has, so that spelling has to be listed, and the bare digest too.
func TestATagWithADigestIsListedBothWays(t *testing.T) {
	list := Build([]ScannedImage{{Ref: "nginx:1.27@sha256:abc", Counts: Counts{Critical: 1}}})
	for _, written := range []string{"nginx:1.27@sha256:abc", "nginx@sha256:abc", "docker.io/library/nginx:1.27@sha256:abc"} {
		if _, ok := list.Data[written]; !ok {
			t.Errorf("%q is not stopped", written)
		}
	}
	// The tag alone may have moved on to another image.
	if _, ok := list.Data["nginx:1.27"]; ok {
		t.Error("the tag without its digest was listed")
	}
}

func TestHostsAreNotCaseSensitiveAndDockerHubHasManyNames(t *testing.T) {
	list := Build([]ScannedImage{
		{Ref: "QUAY.IO/org/app:v2", Counts: Counts{Critical: 1}},
		{Ref: "nginx:1.27", Counts: Counts{Critical: 1}},
	})
	for _, written := range []string{
		"quay.io/org/app:v2",
		"registry-1.docker.io/library/nginx:1.27", "registry.hub.docker.com/library/nginx:1.27", "index.docker.io/nginx:1.27",
	} {
		if _, ok := list.Data[written]; !ok {
			t.Errorf("%q is not stopped", written)
		}
	}
}

// With the list full, what a policy refuses by name is the last to go.
func TestNamedVulnerabilitiesAreListedAheadOfCounts(t *testing.T) {
	var scanned []ScannedImage
	long := strings.Repeat("x", 200)
	for i := 0; i < 6000; i++ {
		scanned = append(scanned, ScannedImage{Ref: "quay.io/" + long + "/img:" + strconv.Itoa(i), Counts: Counts{Critical: 9}})
	}
	scanned = append(scanned, ScannedImage{Ref: "quay.io/a/named:1", CVEs: []string{"CVE-2024-3094"}})
	list := Build(scanned)
	if list.LeftOut == 0 {
		t.Fatal("the list was not full")
	}
	if len(list.CVEs["quay.io/a/named:1"]) != 1 {
		t.Error("an image refused by name was left out of a full list")
	}
}

// What does not fit is counted, and it is the least vulnerable that go.
func TestAListThatIsFullSaysWhatItLeftOut(t *testing.T) {
	var scanned []ScannedImage
	long := strings.Repeat("x", 200)
	for i := 0; i < 6000; i++ {
		scanned = append(scanned, ScannedImage{Ref: "quay.io/" + long + "/img:" + strconv.Itoa(i), Counts: Counts{Critical: 1 + i%3}})
	}
	list := Build(scanned)
	if list.LeftOut == 0 {
		t.Fatal("6000 long names fit in one object?")
	}
	if len(list.Data)+list.LeftOut != 6000 {
		t.Errorf("listed %d + left out %d != 6000", len(list.Data), list.LeftOut)
	}
	size, threes := 0, 0
	for k, c := range list.Data {
		size += keyBytes*len(k) + entryBytes
		if c.Critical == 3 {
			threes++
		}
	}
	if size > maxListBytes {
		t.Errorf("list is %d bytes", size)
	}
	if want := min(len(list.Data), 2000); threes != want {
		t.Errorf("%d of the %d listed are among the 2000 worst", threes, want)
	}
}

func newDyn() *dynfake.FakeDynamicClient {
	return dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{ListGVR: "VulnerabilityGateList"})
}

func spec(t *testing.T, g *Gate) map[string]any {
	t.Helper()
	obj, err := g.dyn.Resource(ListGVR).Get(context.Background(), Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	m, _, _ := unstructured.NestedMap(obj.Object, "spec")
	return m
}

func TestTheListIsWrittenAndKeptInStep(t *testing.T) {
	client := fake.NewSimpleClientset()
	scanned := []ScannedImage{{Ref: "nginx:1.25", Counts: Counts{Critical: 7, High: 50, FixableCritical: 3}}}
	g := New(client, newDyn(), "sentinel-system", func(context.Context, map[string]bool) ([]ScannedImage, bool) { return scanned, true })
	ctx := context.Background()
	g.reconcile(ctx)

	s := spec(t, g)
	if c, _, _ := unstructured.NestedInt64(s, "images", "nginx:1.25", "critical"); c != 7 {
		t.Errorf("spec = %v", s)
	}
	if f, _, _ := unstructured.NestedInt64(s, "images", "nginx:1.25", "fixableCritical"); f != 3 {
		t.Errorf("spec = %v", s)
	}
	if h, _, _ := unstructured.NestedInt64(s, "images", "nginx:1.25", "high"); h != 50 {
		t.Errorf("spec = %v", s)
	}
	exempt, _, _ := unstructured.NestedStringSlice(s, "exemptNamespaces")
	if strings.Join(exempt, ",") != "kube-system,sentinel-system" {
		t.Errorf("exempt namespaces = %v", exempt)
	}

	// A result that is gone leaves the list.
	scanned = nil
	g.reconcile(ctx)
	if images, _, _ := unstructured.NestedMap(spec(t, g), "images"); len(images) != 0 {
		t.Errorf("the list kept an image no scan reports any more: %v", images)
	}
}

// v0.65.0 made a policy and a binding of its own, which read the list in a
// form it no longer has. They go; a policy an administrator gave the same name
// stays.
func TestWhatV0650MadeIsRemovedAndNothingElse(t *testing.T) {
	ctx := context.Background()
	managed := map[string]string{"app.kubernetes.io/managed-by": "k8s-sentinel"}
	for _, labels := range []map[string]string{managed, nil} {
		client := fake.NewSimpleClientset(
			&admissionv1.ValidatingAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: Name, Labels: labels}},
			&admissionv1.ValidatingAdmissionPolicyBinding{ObjectMeta: metav1.ObjectMeta{Name: Name, Labels: labels}},
		)
		g := New(client, newDyn(), "sentinel-system", func(context.Context, map[string]bool) ([]ScannedImage, bool) { return nil, true })
		g.reconcile(ctx)
		_, perr := client.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, Name, metav1.GetOptions{})
		_, berr := client.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, Name, metav1.GetOptions{})
		if gone := k8serrors.IsNotFound(perr) && k8serrors.IsNotFound(berr); gone != (labels != nil) {
			t.Errorf("labels %v: removed = %v (policy %v, binding %v)", labels, gone, perr, berr)
		}
	}
}

// A policy names vulnerabilities in a variable; the images that have them are
// listed with them, whatever their counts.
func TestImagesWithANamedVulnerabilityAreListedWithIt(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(
		&admissionv1.ValidatingAdmissionPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "no-xz"},
			Spec: admissionv1.ValidatingAdmissionPolicySpec{
				ParamKind: &admissionv1.ParamKind{APIVersion: "sentinel.io/v1", Kind: "VulnerabilityGate"},
				Variables: []admissionv1.Variable{{Name: NamedVariable, Expression: "['CVE-2024-3094', 'GHSA-aaaa-bbbb-cccc']"}},
			},
		},
		// Another kind of parameter: not ours to read.
		&admissionv1.ValidatingAdmissionPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "other"},
			Spec: admissionv1.ValidatingAdmissionPolicySpec{
				ParamKind: &admissionv1.ParamKind{APIVersion: "v1", Kind: "ConfigMap"},
				Variables: []admissionv1.Variable{{Name: NamedVariable, Expression: "['CVE-1-1']"}},
			},
		},
	)
	var asked map[string]bool
	g := New(client, newDyn(), "sentinel-system", func(_ context.Context, named map[string]bool) ([]ScannedImage, bool) {
		asked = named
		return []ScannedImage{
			{Ref: "quay.io/a/medium-only:1", CVEs: []string{"CVE-2024-3094", "CVE-2024-3094"}},
			{Ref: "quay.io/a/clean:1"},
			{Ref: "quay.io/a/twice:1", Counts: Counts{Critical: 1}},
			{Ref: "quay.io/a/twice:1", CVEs: []string{"GHSA-aaaa-bbbb-cccc"}},
		}, true
	})
	g.reconcile(ctx)
	if len(asked) != 2 || !asked["CVE-2024-3094"] || !asked["GHSA-aaaa-bbbb-cccc"] {
		t.Fatalf("asked for %v", asked)
	}
	s := spec(t, g)
	if ids, _, _ := unstructured.NestedStringSlice(s, "images", "quay.io/a/medium-only:1", "cves"); len(ids) != 1 || ids[0] != "CVE-2024-3094" {
		t.Errorf("medium-only = %v", s["images"])
	}
	if _, ok, _ := unstructured.NestedMap(s, "images", "quay.io/a/clean:1"); ok {
		t.Error("an image with nothing to refuse was listed")
	}
	// Two results for one image: the counts of one and the named ID of the other.
	ids, _, _ := unstructured.NestedStringSlice(s, "images", "quay.io/a/twice:1", "cves")
	c, _, _ := unstructured.NestedInt64(s, "images", "quay.io/a/twice:1", "critical")
	if len(ids) != 1 || c != 1 {
		t.Errorf("twice = cves %v critical %d", ids, c)
	}
}

// A read that failed is not a cluster with nothing vulnerable in it: the list
// stays, or every policy would admit what it refused a minute ago.
func TestResultsThatCouldNotBeReadLeaveTheListAlone(t *testing.T) {
	ctx := context.Background()
	ok := true
	g := New(fake.NewSimpleClientset(), newDyn(), "sentinel-system", func(context.Context, map[string]bool) ([]ScannedImage, bool) {
		if !ok {
			return nil, false
		}
		return []ScannedImage{{Ref: "nginx:1.25", Counts: Counts{Critical: 7}}}, true
	})
	g.reconcile(ctx)
	ok = false
	g.reconcile(ctx)
	if c, _, _ := unstructured.NestedInt64(spec(t, g), "images", "nginx:1.25", "critical"); c != 7 {
		t.Errorf("the list was emptied: %v", spec(t, g))
	}
}
