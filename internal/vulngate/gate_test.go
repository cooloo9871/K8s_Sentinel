package vulngate

import (
	"context"
	"path/filepath"
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

func limits(critical, high int) Settings {
	return Settings{Enabled: true, Mode: "deny", CriticalLimit: critical, HighLimit: high}
}

func TestOnlyImagesOverTheLimitAreListed(t *testing.T) {
	scanned := []ScannedImage{
		{Ref: "quay.io/org/bad:1", Critical: 1},
		{Ref: "quay.io/org/clean:1"},
		{Ref: "quay.io/org/highs:1", High: 11},
		{Ref: "quay.io/org/fewhighs:1", High: 10},
	}
	list := Build(scanned, limits(0, 10))
	for image, want := range map[string]bool{
		"quay.io/org/bad:1": true, "quay.io/org/clean:1": false,
		"quay.io/org/highs:1": true, "quay.io/org/fewhighs:1": false,
	} {
		if _, got := list.Data[(image)]; got != want {
			t.Errorf("%s listed = %v, want %v", image, got, want)
		}
	}
	if got := list.Data[("quay.io/org/bad:1")]; got != "1 critical, 0 high" {
		t.Errorf("reason = %q", got)
	}
}

// -1 switches a severity off, so highs alone do not list an image.
func TestASeverityWithoutALimitIsNotCounted(t *testing.T) {
	list := Build([]ScannedImage{{Ref: "quay.io/a/b:1", High: 500}}, limits(0, -1))
	if len(list.Data) != 0 {
		t.Errorf("listed on highs with no high limit: %v", list.Data)
	}
}

// The policy compares strings, and a pod spec may write a Docker Hub image
// four ways. A scan of any one of them has to stop all of them.
func TestEverySpellingOfADockerHubImageIsListed(t *testing.T) {
	for _, scannedAs := range []string{
		"nginx", "nginx:latest", "docker.io/library/nginx:latest", "registry.hub.docker.com/library/nginx",
	} {
		list := Build([]ScannedImage{{Ref: scannedAs, Critical: 3}}, limits(0, -1))
		for _, written := range []string{
			"nginx", "nginx:latest", "library/nginx", "docker.io/nginx", "docker.io/library/nginx:latest",
			"index.docker.io/library/nginx",
		} {
			if _, ok := list.Data[(written)]; !ok {
				t.Errorf("scanned as %q: a pod writing %q is not stopped", scannedAs, written)
			}
		}
		if _, ok := list.Data[("nginx:1.27")]; ok {
			t.Errorf("scanned as %q: another tag was listed", scannedAs)
		}
		if len(list.Images) != 1 {
			t.Errorf("scanned as %q: counted as %d images", scannedAs, len(list.Images))
		}
	}
}

func TestOrganisationAndPrivateRegistryImages(t *testing.T) {
	list := Build([]ScannedImage{
		{Ref: "bitnami/redis:7", Critical: 1},
		{Ref: "harbor.internal:8443/team/app:v1", Critical: 1},
		{Ref: "quay.io/org/app@sha256:abc", Critical: 1},
	}, limits(0, -1))
	for _, written := range []string{
		"bitnami/redis:7", "docker.io/bitnami/redis:7",
		"harbor.internal:8443/team/app:v1", "quay.io/org/app@sha256:abc",
	} {
		if _, ok := list.Data[(written)]; !ok {
			t.Errorf("%q is not stopped", written)
		}
	}
	if _, ok := list.Data[("library/bitnami/redis:7")]; ok {
		t.Error("an organisation image was given the library/ prefix")
	}
}

// The same image scanned twice: the result that puts it over the limit stands.
func TestTheWorseOfTwoResultsForOneImageWins(t *testing.T) {
	list := Build([]ScannedImage{
		{Ref: "nginx:1.25", Critical: 0, Source: "registry"},
		{Ref: "docker.io/library/nginx:1.25", Critical: 4, Source: "workload"},
	}, limits(0, -1))
	if len(list.Images) != 1 || list.Images[0].Critical != 4 {
		t.Fatalf("images = %+v", list.Images)
	}
}

// What does not fit is counted, worst images first into the list.
func TestAListThatIsFullSaysWhatItLeftOut(t *testing.T) {
	var scanned []ScannedImage
	long := strings.Repeat("x", 200)
	for i := 0; i < 6000; i++ {
		scanned = append(scanned, ScannedImage{Ref: "quay.io/" + long + "/img:" + string(rune('a'+i%26)) + strings.Repeat("0", i%7) + "-" + itoa(i), Critical: 1 + i%3})
	}
	list := Build(scanned, limits(0, -1))
	if list.LeftOut == 0 {
		t.Fatal("6000 long names fit in a ConfigMap?")
	}
	if len(list.Images)+list.LeftOut != 6000 {
		t.Errorf("listed %d + left out %d != 6000", len(list.Images), list.LeftOut)
	}
	size := 0
	for k, v := range list.Data {
		size += len(k) + len(v)
	}
	if size > maxListBytes {
		t.Errorf("list is %d bytes", size)
	}
	if list.Images[0].Critical != 3 {
		t.Errorf("the worst images were not listed first: %+v", list.Images[0])
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for ; i > 0; i /= 10 {
		s = string(rune('0'+i%10)) + s
	}
	return s
}

func TestSettingsValidation(t *testing.T) {
	for name, s := range map[string]Settings{
		"unknown mode":       {Mode: "block"},
		"enabled, no limits": {Enabled: true, Mode: "deny", CriticalLimit: -1, HighLimit: -1},
		"negative limit":     {Mode: "warn", CriticalLimit: -2},
		"bad namespace":      {Mode: "warn", ExcludeNamespaces: []string{"a b"}},
	} {
		if s.Validate() == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	s := Settings{Mode: "warn", ExcludeNamespaces: []string{" b ", "a", "b", ""}}
	if err := s.Validate(); err != nil || strings.Join(s.ExcludeNamespaces, ",") != "a,b" {
		t.Errorf("namespaces = %v, err %v", s.ExcludeNamespaces, err)
	}
}

func newDyn() *dynfake.FakeDynamicClient {
	return dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{ListGVR: "VulnerabilityGateList"})
}

func listed(t *testing.T, g *Gate) map[string]string {
	t.Helper()
	obj, err := g.dyn.Resource(ListGVR).Get(context.Background(), Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	m, _, _ := unstructured.NestedStringMap(obj.Object, "spec", "images")
	return m
}

func newGate(t *testing.T, scanned []ScannedImage) (*Gate, *fake.Clientset) {
	t.Helper()
	client := fake.NewSimpleClientset()
	g := New(client, newDyn(), "sentinel-system", filepath.Join(t.TempDir(), "gate.json"),
		func(context.Context) []ScannedImage { return scanned })
	return g, client
}

func TestEnablingWritesTheListThePolicyAndTheBinding(t *testing.T) {
	g, client := newGate(t, []ScannedImage{{Ref: "nginx:1.25", Critical: 7, High: 50}})
	ctx := context.Background()
	if err := g.Save(Settings{Enabled: true, Mode: "deny", CriticalLimit: 0, HighLimit: -1, ExcludeNamespaces: []string{"istio-system"}}); err != nil {
		t.Fatal(err)
	}
	g.reconcile(ctx)

	if got := listed(t, g); got["nginx:1.25"] != "7 critical, 50 high" {
		t.Errorf("list = %v", got)
	}
	if _, err := client.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, Name, metav1.GetOptions{}); err != nil {
		t.Fatal(err)
	}
	b, err := client.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Spec.ValidationActions) != 1 || b.Spec.ValidationActions[0] != admissionv1.Deny {
		t.Errorf("actions = %v", b.Spec.ValidationActions)
	}
	got := strings.Join(b.Spec.MatchResources.NamespaceSelector.MatchExpressions[0].Values, ",")
	if got != "istio-system,kube-system,sentinel-system" {
		t.Errorf("excluded namespaces = %s", got)
	}
	if st := g.Status(); st.Error != "" || len(st.Images) != 1 {
		t.Errorf("status = %+v", st)
	}

	// Warn mode must not deny, and a result that changed must reach the list.
	g.scanned = func(context.Context) []ScannedImage { return nil }
	if err := g.Save(Settings{Enabled: true, Mode: "warn", CriticalLimit: 0, HighLimit: -1}); err != nil {
		t.Fatal(err)
	}
	g.reconcile(ctx)
	b, _ = client.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, Name, metav1.GetOptions{})
	for _, a := range b.Spec.ValidationActions {
		if a == admissionv1.Deny {
			t.Error("warn mode still denies")
		}
	}
	if got := listed(t, g); len(got) != 0 {
		t.Errorf("the list kept an image no scan reports any more: %v", got)
	}
}

func TestDisablingRemovesEverything(t *testing.T) {
	g, client := newGate(t, []ScannedImage{{Ref: "nginx:1.25", Critical: 7}})
	ctx := context.Background()
	_ = g.Save(limits(0, -1))
	g.reconcile(ctx)
	_ = g.Save(Settings{Enabled: false, Mode: "deny", CriticalLimit: 0, HighLimit: -1})
	g.reconcile(ctx)
	if _, err := client.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, Name, metav1.GetOptions{}); !k8serrors.IsNotFound(err) {
		t.Errorf("binding still there: %v", err)
	}
	if _, err := client.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, Name, metav1.GetOptions{}); !k8serrors.IsNotFound(err) {
		t.Errorf("policy still there: %v", err)
	}
	if _, err := g.dyn.Resource(ListGVR).Get(ctx, Name, metav1.GetOptions{}); !k8serrors.IsNotFound(err) {
		t.Errorf("list still there: %v", err)
	}
	if st := g.Status(); st.Error != "" {
		t.Errorf("removing what is not there is not an error: %v", st.Error)
	}
}

// Settings survive a restart.
func TestSettingsAreKept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gate.json")
	scanned := func(context.Context) []ScannedImage { return nil }
	g := New(fake.NewSimpleClientset(), newDyn(), "sentinel-system", path, scanned)
	if g.Settings().Enabled {
		t.Fatal("the gate is on before anyone switched it on")
	}
	want := Settings{Enabled: true, Mode: "deny", CriticalLimit: 2, HighLimit: 30, ExcludeNamespaces: []string{"dev"}}
	if err := g.Save(want); err != nil {
		t.Fatal(err)
	}
	got := New(fake.NewSimpleClientset(), newDyn(), "sentinel-system", path, scanned).Settings()
	if got.Mode != "deny" || !got.Enabled || got.CriticalLimit != 2 || got.HighLimit != 30 || len(got.ExcludeNamespaces) != 1 {
		t.Errorf("reloaded %+v", got)
	}
}
