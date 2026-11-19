package k8s

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
)

// tracingPolicy builds an unstructured TracingPolicy carrying fields Sentinel's
// own struct does not model, which is the whole point of these tests.
func tracingPolicy(name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cilium.io/v1alpha1",
		"kind":       "TracingPolicy",
		"metadata": map[string]any{
			"name":   name,
			"labels": map[string]any{"team": "platform"},
		},
		"spec": map[string]any{
			// Modelled: the action here is what a mode switch is meant to change.
			"kprobes": []any{map[string]any{
				"call":    "sys_execve",
				"syscall": true,
				"message": "process executed",
				"tags":    []any{"observability"},
				"selectors": []any{map[string]any{
					"matchNamespaces": []any{map[string]any{
						"namespace": "Pid", "operator": "In", "values": []any{"host_ns"},
					}},
					"matchActions": []any{map[string]any{"action": "Post"}},
				}},
			}},
			// Unmodelled entirely: this whole section used to disappear.
			"tracepoints": []any{map[string]any{
				"subsystem": "raw_syscalls",
				"event":     "sys_enter",
				"selectors": []any{map[string]any{
					"matchActions": []any{map[string]any{"action": "Post"}},
				}},
			}},
			"options": []any{map[string]any{"name": "disable-kprobe-multi", "value": "1"}},
		},
	}}
}

func modeStore(objs ...runtime.Object) *Store {
	scheme := runtime.NewScheme()
	client := dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{
		tracingPolicyGVR:           "TracingPolicyList",
		tracingPolicyNamespacedGVR: "TracingPolicyNamespacedList",
	}, objs...)
	return NewStore(client, nil, nil, "")
}

// Switching the enforcement mode used to round-trip the policy through
// policy.TracingPolicy, a struct that models only podSelector and kprobes. Every
// other field was silently deleted from the cluster — and a policy applied with
// kubectl is exactly the kind that carries them.
func TestSwitchingModeKeepsFieldsSentinelDoesNotModel(t *testing.T) {
	store := modeStore(tracingPolicy("watch-exec"))

	if err := store.SetPolicyMode(context.Background(), "watch-exec", "", "Protect"); err != nil {
		t.Fatalf("SetPolicyMode: %v", err)
	}

	got, err := store.client.Resource(tracingPolicyGVR).Get(context.Background(), "watch-exec", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get after mode switch: %v", err)
	}
	spec, _ := got.Object["spec"].(map[string]any)

	if _, ok := spec["tracepoints"]; !ok {
		t.Error("the tracepoints section was deleted by a mode switch")
	}
	if _, ok := spec["options"]; !ok {
		t.Error("spec.options was deleted by a mode switch")
	}
	kprobe := spec["kprobes"].([]any)[0].(map[string]any)
	if kprobe["message"] != "process executed" {
		t.Error("the kprobe's message was deleted by a mode switch")
	}
	if _, ok := kprobe["tags"]; !ok {
		t.Error("the kprobe's tags were deleted by a mode switch")
	}
	sel := kprobe["selectors"].([]any)[0].(map[string]any)
	if _, ok := sel["matchNamespaces"]; !ok {
		t.Error("the selector's matchNamespaces was deleted by a mode switch")
	}
	if labels := got.GetLabels(); labels["team"] != "platform" {
		t.Error("metadata labels were deleted by a mode switch")
	}

	// And it still did the job it was asked to do.
	act := sel["matchActions"].([]any)[0].(map[string]any)
	if act["action"] != "Sigkill" {
		t.Errorf("kprobe action = %v, want Sigkill", act["action"])
	}
}

// The mode has to reach every section that can enforce, not just kprobes.
func TestSwitchingModeReachesTracepoints(t *testing.T) {
	pol := tracingPolicy("watch-exec")
	tpSel := pol.Object["spec"].(map[string]any)["tracepoints"].([]any)[0].(map[string]any)["selectors"].([]any)[0].(map[string]any)
	tpSel["matchArgs"] = []any{map[string]any{"index": int64(4), "operator": "Equal", "values": []any{"59"}}}
	store := modeStore(pol)
	if err := store.SetPolicyMode(context.Background(), "watch-exec", "", "Protect"); err != nil {
		t.Fatalf("SetPolicyMode: %v", err)
	}
	got, _ := store.client.Resource(tracingPolicyGVR).Get(context.Background(), "watch-exec", metav1.GetOptions{})
	tp := got.Object["spec"].(map[string]any)["tracepoints"].([]any)[0].(map[string]any)
	act := tp["selectors"].([]any)[0].(map[string]any)["matchActions"].([]any)[0].(map[string]any)
	if act["action"] != "Sigkill" {
		t.Errorf("tracepoint action = %v, want Sigkill — the mode switch did not reach it", act["action"])
	}
}

// Actions that are neither Post nor Sigkill say something about what the probe
// does, not about the enforcement mode. Rewriting them all indiscriminately —
// which is what the old code did — changed behaviour the user never asked to change.
func TestSwitchingModeLeavesOtherActionsAlone(t *testing.T) {
	pol := tracingPolicy("with-override")
	sel := pol.Object["spec"].(map[string]any)["kprobes"].([]any)[0].(map[string]any)["selectors"].([]any)[0].(map[string]any)
	sel["matchActions"] = []any{
		map[string]any{"action": "Post"},
		map[string]any{"action": "Override", "argError": int64(-1)},
	}
	store := modeStore(pol)

	if err := store.SetPolicyMode(context.Background(), "with-override", "", "Protect"); err != nil {
		t.Fatalf("SetPolicyMode: %v", err)
	}
	got, _ := store.client.Resource(tracingPolicyGVR).Get(context.Background(), "with-override", metav1.GetOptions{})
	acts := got.Object["spec"].(map[string]any)["kprobes"].([]any)[0].(map[string]any)["selectors"].([]any)[0].(map[string]any)["matchActions"].([]any)
	if a := acts[0].(map[string]any)["action"]; a != "Sigkill" {
		t.Errorf("Post action = %v, want Sigkill", a)
	}
	if a := acts[1].(map[string]any)["action"]; a != "Override" {
		t.Errorf("Override action = %v, want it left alone", a)
	}
}

// The list column and the mode switch have to agree about what a policy is doing.
// Reading kprobes alone reported a killing tracepoint policy as Monitoring.
func TestDetectModeSeesTracepoints(t *testing.T) {
	obj := map[string]any{"spec": map[string]any{
		"tracepoints": []any{map[string]any{
			"selectors": []any{map[string]any{
				"matchActions": []any{map[string]any{"action": "Sigkill"}},
			}},
		}},
	}}
	if got := detectMode(obj); got != "Protect" {
		t.Errorf("detectMode = %q, want Protect", got)
	}
}

func TestDetectModeReportsMixed(t *testing.T) {
	obj := map[string]any{"spec": map[string]any{
		"kprobes": []any{map[string]any{
			"selectors": []any{
				map[string]any{"matchActions": []any{map[string]any{"action": "Post"}}},
				map[string]any{"matchActions": []any{map[string]any{"action": "Sigkill"}}},
			},
		}},
	}}
	if got := detectMode(obj); got != "Mixed" {
		t.Errorf("detectMode = %q, want Mixed", got)
	}
}

// A policy with nothing to switch must not be written back at all — an Update
// with no change is a pointless resourceVersion bump on every mode toggle.
func TestSwitchingModeSkipsAPolicyWithNoActions(t *testing.T) {
	pol := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cilium.io/v1alpha1",
		"kind":       "TracingPolicy",
		"metadata":   map[string]any{"name": "empty"},
		"spec":       map[string]any{},
	}}
	store := modeStore(pol)
	before, _ := store.client.Resource(tracingPolicyGVR).Get(context.Background(), "empty", metav1.GetOptions{})

	if err := store.SetPolicyMode(context.Background(), "empty", "", "Protect"); err != nil {
		t.Fatalf("SetPolicyMode: %v", err)
	}
	after, _ := store.client.Resource(tracingPolicyGVR).Get(context.Background(), "empty", metav1.GetOptions{})
	if before.GetResourceVersion() != after.GetResourceVersion() {
		t.Error("a policy with no actions was written back anyway")
	}
}

func actionsOf(t *testing.T, store *Store, name, field string) []string {
	t.Helper()
	got, err := store.client.Resource(tracingPolicyGVR).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get %s: %v", name, err)
	}
	var out []string
	for _, p := range got.Object["spec"].(map[string]any)[field].([]any) {
		for _, sel := range p.(map[string]any)["selectors"].([]any) {
			for _, a := range sel.(map[string]any)["matchActions"].([]any) {
				out = append(out, a.(map[string]any)["action"].(string))
			}
		}
	}
	return out
}

// observeAll is the shape of "report every exec": a selector with an action and
// nothing to match on. As Sigkill it kills every process in every pod selected.
func observeAll(name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cilium.io/v1alpha1",
		"kind":       "TracingPolicy",
		"metadata":   map[string]any{"name": name},
		"spec": map[string]any{"kprobes": []any{map[string]any{
			"call": "sys_execve", "syscall": true,
			"selectors": []any{map[string]any{
				"matchActions": []any{map[string]any{"action": "Post"}},
			}},
		}}},
	}}
}

func TestProtectLeavesASelectorWithNoConditionsReporting(t *testing.T) {
	ctx := context.Background()
	store := modeStore(observeAll("monitor-all-exec"), tracingPolicy("watch-exec"))

	if err := store.SetPolicyMode(ctx, "watch-exec", "", "Protect"); err != nil {
		t.Fatalf("SetPolicyMode: %v", err)
	}
	// In one policy the selectors are judged one by one.
	if got := actionsOf(t, store, "watch-exec", "kprobes"); got[0] != "Sigkill" {
		t.Errorf("a selector with conditions = %v, want Sigkill", got)
	}
	if got := actionsOf(t, store, "watch-exec", "tracepoints"); got[0] != "Post" {
		t.Errorf("a selector with no conditions = %v, want Post", got)
	}

	// The same holds when one policy is switched on its own, and it is said.
	if err := store.SetPolicyMode(ctx, "monitor-all-exec", "", "Protect"); err != ErrUnconditional {
		t.Errorf("SetPolicyMode = %v, want ErrUnconditional", err)
	}

	records, _ := store.List(ctx)
	for _, r := range records {
		if !r.Unconditional {
			t.Errorf("%s is not marked as holding a selector with no conditions", r.Name)
		}
	}
}

// A policy somebody wrote to kill on every call can still be turned back.
func TestMonitoringUndoesAKillWithNoConditions(t *testing.T) {
	pol := observeAll("kill-all")
	sel := pol.Object["spec"].(map[string]any)["kprobes"].([]any)[0].(map[string]any)["selectors"].([]any)[0].(map[string]any)
	sel["matchActions"] = []any{map[string]any{"action": "Sigkill"}}
	store := modeStore(pol)

	if err := store.SetPolicyMode(context.Background(), "kill-all", "", "Monitoring"); err != nil {
		t.Fatalf("SetPolicyMode: %v", err)
	}
	if got := actionsOf(t, store, "kill-all", "kprobes"); got[0] != "Post" {
		t.Errorf("action = %v, want Post", got)
	}
}

// The one switch over all policies turns enforcement off, and the count of
// enforcing policies is read from the policies, so it cannot disagree with them.
func TestStopEnforcingSetsEveryPolicyToMonitoring(t *testing.T) {
	ctx := context.Background()
	a, b := tracingPolicy("a"), tracingPolicy("b")
	store := modeStore(a, b, observeAll("c"))
	for _, n := range []string{"a", "b"} {
		if err := store.SetPolicyMode(ctx, n, "", "Protect"); err != nil {
			t.Fatalf("SetPolicyMode %s: %v", n, err)
		}
	}
	if n, total, _ := store.Enforcing(ctx); n != 2 || total != 3 {
		t.Fatalf("Enforcing = %d of %d, want 2 of 3", n, total)
	}
	if err := store.StopEnforcing(ctx); err != nil {
		t.Fatalf("StopEnforcing: %v", err)
	}
	if n, total, _ := store.Enforcing(ctx); n != 0 || total != 3 {
		t.Errorf("Enforcing = %d of %d after stopping, want 0 of 3", n, total)
	}
}
