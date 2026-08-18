package k8s

import (
	"context"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"

	"github.com/cooloo9871/K8s_Sentinel/internal/policy"
)

// Created By decides whether Edit opens the form or the YAML editor, so it has
// to survive every write path a policy goes through: the form update and the
// YAML update both pass an empty createdBy (the author does not change on
// edit), and losing the annotation there silently reclassifies the policy as
// kubectl-applied — after which the UI refuses to open the form for it.
func TestCreatedBySurvivesEveryEditPath(t *testing.T) {
	scheme := runtime.NewScheme()
	client := dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{
		tracingPolicyGVR:           "TracingPolicyList",
		tracingPolicyNamespacedGVR: "TracingPolicyNamespacedList",
	})
	s := NewStore(client, nil, nil, "")
	ctx := context.Background()

	form := policy.PolicyFormInput{
		Name:        "watch-nginx",
		PodSelector: map[string]string{"run": "test"},
		ProcessMode: "whitelist",
		Process:     []policy.ProcessRule{{Binaries: []string{"/usr/sbin/nginx"}}},
	}
	tp, err := policy.Build(form, policy.ActionPost)
	if err != nil {
		t.Fatal(err)
	}

	// Created in Sentinel, by admin.
	if err := s.Apply(ctx, tp, "admin"); err != nil {
		t.Fatal(err)
	}
	assertCreatedBy(t, s, "watch-nginx", "admin", "after create")

	// Edited through the form — the handler passes no author on update.
	form.Process[0].Binaries = append(form.Process[0].Binaries, "/usr/sbin/nginx-debug")
	tp, err = policy.Build(form, policy.ActionPost)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(ctx, tp, ""); err != nil {
		t.Fatal(err)
	}
	assertCreatedBy(t, s, "watch-nginx", "admin", "after a form edit")

	// Edited through the YAML editor — the manifest is whatever the cluster
	// returned, author still absent from the request.
	rec, err := s.Get(ctx, "watch-nginx", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyRaw(ctx, rec.RawYAML, ""); err != nil {
		t.Fatal(err)
	}
	assertCreatedBy(t, s, "watch-nginx", "admin", "after a YAML edit")

	// And a YAML edit that REMOVES the annotation block entirely — an operator
	// pruning metadata they did not recognise.
	pruned := strings.ReplaceAll(rec.RawYAML, "sentinel.io/created-by: admin", "pruned: 'true'")
	if err := s.ApplyRaw(ctx, pruned, ""); err != nil {
		t.Fatal(err)
	}
	assertCreatedBy(t, s, "watch-nginx", "admin", "after a YAML edit that dropped the annotation")
}

// Policies created before the annotation existed have none, display as
// k8s-apply, and the UI refuses them the form. A save from Sentinel adopts
// such a policy — the editor becomes its recorded author — while a policy
// that already names an author never has it overwritten by a later editor.
func TestAnEditAdoptsAnUnattributedPolicy(t *testing.T) {
	scheme := runtime.NewScheme()
	client := dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{
		tracingPolicyGVR:           "TracingPolicyList",
		tracingPolicyNamespacedGVR: "TracingPolicyNamespacedList",
	}, tracingPolicy("pre-annotation"))
	s := NewStore(client, nil, nil, "")
	ctx := context.Background()

	form := policy.PolicyFormInput{
		Name:        "pre-annotation",
		PodSelector: map[string]string{"run": "test"},
		ProcessMode: "whitelist",
		Process:     []policy.ProcessRule{{Binaries: []string{"/usr/sbin/nginx"}}},
	}
	tp, err := policy.Build(form, policy.ActionPost)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(ctx, tp, "editor"); err != nil {
		t.Fatal(err)
	}
	assertCreatedBy(t, s, "pre-annotation", "editor", "after an edit adopted it")

	// A second editor does not steal it.
	if err := s.Apply(ctx, tp, "someone-else"); err != nil {
		t.Fatal(err)
	}
	assertCreatedBy(t, s, "pre-annotation", "editor", "after a second editor saved")
}

func assertCreatedBy(t *testing.T, s *Store, name, want, when string) {
	t.Helper()
	rec, err := s.Get(context.Background(), name, "")
	if err != nil {
		t.Fatalf("%s: %v", when, err)
	}
	if rec.CreatedBy != want {
		t.Errorf("%s: createdBy = %q, want %q", when, rec.CreatedBy, want)
	}
}
