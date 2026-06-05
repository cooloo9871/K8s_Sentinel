package policy_test

import (
	"testing"

	"github.com/brobridge/sentinel/internal/policy"
	"sigs.k8s.io/yaml"
)

func TestBuildProcessPolicy(t *testing.T) {
	input := policy.PolicyFormInput{
		Name:    "block-shells",
		Process: []policy.ProcessRule{{Binaries: []string{"/bin/bash", "/bin/sh"}}},
	}

	got, err := policy.Build(input, policy.ActionPost)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	if got.Kind != "TracingPolicy" {
		t.Errorf("kind = %q, want TracingPolicy", got.Kind)
	}
	if len(got.Spec.KProbes) != 1 {
		t.Fatalf("kprobes len = %d, want 1", len(got.Spec.KProbes))
	}
	kp := got.Spec.KProbes[0]
	if kp.Call != "sys_execve" {
		t.Errorf("call = %q, want sys_execve", kp.Call)
	}
	if !kp.Syscall {
		t.Error("syscall should be true for process rule")
	}
}

func TestBuildMultipleProcessRulesCombined(t *testing.T) {
	input := policy.PolicyFormInput{
		Name: "block-shells",
		Process: []policy.ProcessRule{
			{Binaries: []string{"/bin/bash"}},
			{Binaries: []string{"/bin/sh"}},
		},
	}

	got, err := policy.Build(input, policy.ActionPost)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	// Multiple process rules must be combined into ONE kprobe to avoid BPF pin conflict
	if len(got.Spec.KProbes) != 1 {
		t.Fatalf("kprobes len = %d, want 1 (all binaries must be in one kprobe)", len(got.Spec.KProbes))
	}
	binaries := got.Spec.KProbes[0].Selectors[0].MatchBinaries[0].Values
	if len(binaries) != 2 {
		t.Errorf("binaries len = %d, want 2", len(binaries))
	}
}

func TestBuildFilePolicy(t *testing.T) {
	input := policy.PolicyFormInput{
		Name: "watch-files",
		File: []policy.FileRule{{Paths: []string{"/etc/shadow"}}},
	}

	got, err := policy.Build(input, policy.ActionPost)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	if len(got.Spec.KProbes) != 1 {
		t.Fatalf("kprobes len = %d, want 1", len(got.Spec.KProbes))
	}
	kp := got.Spec.KProbes[0]
	if kp.Call != "security_file_permission" {
		t.Errorf("call = %q, want security_file_permission", kp.Call)
	}
	if kp.Syscall {
		t.Error("syscall should be false for security_file_permission")
	}
	if kp.Selectors[0].MatchArgs[0].Values[0] != "/etc/shadow" {
		t.Errorf("path = %q, want /etc/shadow", kp.Selectors[0].MatchArgs[0].Values[0])
	}
}

func TestBuildMultipleFileRulesCombined(t *testing.T) {
	input := policy.PolicyFormInput{
		Name: "watch-files",
		File: []policy.FileRule{
			{Paths: []string{"/etc/shadow"}},
			{Paths: []string{"/root"}},
		},
	}

	got, err := policy.Build(input, policy.ActionPost)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	// Multiple file rules must be combined into ONE kprobe to avoid BPF pin conflict
	if len(got.Spec.KProbes) != 1 {
		t.Fatalf("kprobes len = %d, want 1 (all paths must be in one kprobe)", len(got.Spec.KProbes))
	}
	paths := got.Spec.KProbes[0].Selectors[0].MatchArgs[0].Values
	if len(paths) != 2 {
		t.Errorf("paths len = %d, want 2", len(paths))
	}
}

func TestBuildNamespacedPolicy(t *testing.T) {
	input := policy.PolicyFormInput{
		Name:      "ns-policy",
		Namespace: "production",
		Process:   []policy.ProcessRule{{Binaries: []string{"/bin/bash"}}},
	}

	got, err := policy.Build(input, policy.ActionPost)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	if got.Kind != "TracingPolicyNamespaced" {
		t.Errorf("kind = %q, want TracingPolicyNamespaced", got.Kind)
	}
	if got.Metadata.Namespace != "production" {
		t.Errorf("namespace = %q, want production", got.Metadata.Namespace)
	}
}

func TestBuildMultipleRules(t *testing.T) {
	input := policy.PolicyFormInput{
		Name:    "multi",
		Process: []policy.ProcessRule{{Binaries: []string{"/bin/bash"}}},
		File:    []policy.FileRule{{Paths: []string{"/etc"}}},
	}

	got, err := policy.Build(input, policy.ActionPost)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	// One kprobe for sys_execve, one for security_file_permission
	if len(got.Spec.KProbes) != 2 {
		t.Errorf("kprobes len = %d, want 2", len(got.Spec.KProbes))
	}
	if got.Spec.KProbes[0].Call != "sys_execve" {
		t.Errorf("kprobes[0].call = %q, want sys_execve", got.Spec.KProbes[0].Call)
	}
	if got.Spec.KProbes[1].Call != "security_file_permission" {
		t.Errorf("kprobes[1].call = %q, want security_file_permission", got.Spec.KProbes[1].Call)
	}
}

func TestBuildYAMLRoundtrip(t *testing.T) {
	input := policy.PolicyFormInput{
		Name:    "roundtrip",
		Process: []policy.ProcessRule{{Binaries: []string{"/bin/sh"}}},
	}

	tp, err := policy.Build(input, policy.ActionPost)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	b, err := yaml.Marshal(tp)
	if err != nil {
		t.Fatalf("yaml.Marshal() error: %v", err)
	}
	if len(b) == 0 {
		t.Error("expected non-empty YAML")
	}
	var out policy.TracingPolicy
	if err := yaml.Unmarshal(b, &out); err != nil {
		t.Fatalf("yaml.Unmarshal() error: %v", err)
	}
	if out.Metadata.Name != "roundtrip" {
		t.Errorf("name after roundtrip = %q, want roundtrip", out.Metadata.Name)
	}
}
