package policy_test

import (
	"strings"
	"testing"

	"github.com/cooloo9871/K8s_Sentinel/internal/policy"
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
	args := got.Spec.KProbes[0].Selectors[0].MatchArgs
	if len(args) == 0 {
		t.Fatal("expected matchArgs for process rule")
	}
	// No ProcessMode set means whitelist, which acts on anything NOT listed.
	if args[0].Operator != "NotEqual" {
		t.Errorf("operator = %q, want NotEqual (whitelist is the default)", args[0].Operator)
	}
	// The path is matched exactly, as typed. Suffix matching let a whitelist be
	// walked past by a binary at a path ending in an allowed one.
	want := []string{"/bin/bash", "/bin/sh"}
	if len(args[0].Values) != len(want) {
		t.Fatalf("binaries = %v, want %v", args[0].Values, want)
	}
	for i, w := range want {
		if args[0].Values[i] != w {
			t.Errorf("binaries[%d] = %q, want %q", i, args[0].Values[i], w)
		}
	}
}

// Blacklist inverts the operator: act on paths that ARE one of those listed.
func TestBuildProcessBlacklistOperator(t *testing.T) {
	got, err := policy.Build(policy.PolicyFormInput{
		Name:        "block-shells",
		ProcessMode: "blacklist",
		Process:     []policy.ProcessRule{{Binaries: []string{"/bin/bash"}}},
	}, policy.ActionSigkill)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	if op := got.Spec.KProbes[0].Selectors[0].MatchArgs[0].Operator; op != "Equal" {
		t.Errorf("operator = %q, want Equal", op)
	}
}

// A bare name is refused rather than quietly widened. As a whitelist entry it
// would mean "any binary called nginx, anywhere" — including one dropped in
// /tmp — which is not what someone typing a program name is asking for.
func TestBuildRejectsARelativeBinaryPath(t *testing.T) {
	_, err := policy.Build(policy.PolicyFormInput{
		Name:    "allow-nginx",
		Process: []policy.ProcessRule{{Binaries: []string{"nginx"}}},
	}, policy.ActionSigkill)
	if err == nil {
		t.Fatal("a bare binary name was accepted")
	}
	if !strings.Contains(err.Error(), "absolute path") {
		t.Errorf("error = %q, want it to say an absolute path is required", err)
	}
}

// Surrounding space is a typo, not a different path.
func TestBuildTrimsBinaryPaths(t *testing.T) {
	got, err := policy.Build(policy.PolicyFormInput{
		Name:    "allow-nginx",
		Process: []policy.ProcessRule{{Binaries: []string{"  /usr/sbin/nginx  ", ""}}},
	}, policy.ActionSigkill)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	vals := got.Spec.KProbes[0].Selectors[0].MatchArgs[0].Values
	if len(vals) != 1 || vals[0] != "/usr/sbin/nginx" {
		t.Errorf("values = %v, want the trimmed path alone", vals)
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
	// Each rule keeps its own selector, because ExceptBinaries and the
	// read/write permission are per-rule and cannot be merged into one.
	sels := got.Spec.KProbes[0].Selectors
	if len(sels) != 2 {
		t.Fatalf("selectors len = %d, want 2 (one per file rule)", len(sels))
	}
	for i, wantPath := range []string{"/etc/shadow", "/root"} {
		got := sels[i].MatchArgs[0].Values
		if len(got) != 1 || got[0] != wantPath {
			t.Errorf("selector[%d] paths = %v, want [%s]", i, got, wantPath)
		}
	}
}

// A per-rule exception must land on that rule's selector only, which is the
// reason the rules are not merged.
func TestBuildFileRuleExceptBinariesStayPerRule(t *testing.T) {
	got, err := policy.Build(policy.PolicyFormInput{
		Name: "watch-files",
		File: []policy.FileRule{
			{Paths: []string{"/etc/shadow"}, ExceptBinaries: []string{"/usr/bin/sshd"}},
			{Paths: []string{"/root"}},
		},
	}, policy.ActionPost)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	sels := got.Spec.KProbes[0].Selectors
	if len(sels) != 2 {
		t.Fatalf("selectors len = %d, want 2", len(sels))
	}
	if len(sels[0].MatchBinaries) != 1 || sels[0].MatchBinaries[0].Operator != "NotIn" {
		t.Errorf("rule 0 should carry a NotIn matchBinaries, got %+v", sels[0].MatchBinaries)
	}
	if len(sels[1].MatchBinaries) != 0 {
		t.Errorf("rule 1 has no exceptions, but got %+v", sels[1].MatchBinaries)
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

// A form with nothing in it produced spec: {}. Applied over an existing policy
// that replaces working rules with a policy that does nothing, and reports
// success — which is how the monitor-all-exec template could have been wiped.
func TestBuildRejectsAPolicyWithNoRules(t *testing.T) {
	_, err := policy.Build(policy.PolicyFormInput{
		Name:        "empty",
		PodSelector: map[string]string{"app": "web"},
	}, policy.ActionPost)
	if err == nil {
		t.Fatal("a form with no rules produced a policy")
	}
	if !strings.Contains(err.Error(), "at least one") {
		t.Errorf("error = %q, want it to say a rule is required", err)
	}
}

// File rules default to blacklist (Prefix: block the listed paths) and switch to
// NotPrefix under whitelist mode (act on paths NOT listed).
func TestBuildFileWhitelistOperator(t *testing.T) {
	blk, err := policy.Build(policy.PolicyFormInput{
		Name: "f", File: []policy.FileRule{{Paths: []string{"/etc/shadow"}}},
	}, policy.ActionPost)
	if err != nil {
		t.Fatal(err)
	}
	if op := blk.Spec.KProbes[0].Selectors[0].MatchArgs[0].Operator; op != "Prefix" {
		t.Errorf("default (blacklist) operator = %q, want Prefix", op)
	}

	wl, err := policy.Build(policy.PolicyFormInput{
		Name: "f", FileMode: "whitelist", File: []policy.FileRule{{Paths: []string{"/etc/shadow"}}},
	}, policy.ActionPost)
	if err != nil {
		t.Fatal(err)
	}
	if op := wl.Spec.KProbes[0].Selectors[0].MatchArgs[0].Operator; op != "NotPrefix" {
		t.Errorf("whitelist operator = %q, want NotPrefix", op)
	}
}

// Whitelist with multiple excluded paths must produce ONE selector with all
// paths in a single NotPrefix, plus one merged NotIn for exception binaries.
// Separate selectors would be OR-ed and the exclusion would silently fail.
func TestBuildFileWhitelistMergesIntoOneSelector(t *testing.T) {
	got, err := policy.Build(policy.PolicyFormInput{
		Name:     "watch",
		FileMode: "whitelist",
		File: []policy.FileRule{
			{Paths: []string{"/etc/passwd"}, ExceptBinaries: []string{"/usr/bin/allowed"}},
			{Paths: []string{"/etc/shadow"}},
		},
	}, policy.ActionPost)
	if err != nil {
		t.Fatal(err)
	}
	sels := got.Spec.KProbes[0].Selectors
	if len(sels) != 1 {
		t.Fatalf("selectors = %d, want 1 (whitelist must be a single selector)", len(sels))
	}
	arg := sels[0].MatchArgs[0]
	if arg.Operator != "NotPrefix" {
		t.Errorf("operator = %q, want NotPrefix", arg.Operator)
	}
	if len(arg.Values) != 2 || arg.Values[0] != "/etc/passwd" || arg.Values[1] != "/etc/shadow" {
		t.Errorf("values = %v, want [/etc/passwd /etc/shadow]", arg.Values)
	}
	if len(sels[0].MatchBinaries) != 1 || sels[0].MatchBinaries[0].Operator != "NotIn" ||
		len(sels[0].MatchBinaries[0].Values) != 1 || sels[0].MatchBinaries[0].Values[0] != "/usr/bin/allowed" {
		t.Errorf("matchBinaries = %+v, want one NotIn [/usr/bin/allowed]", sels[0].MatchBinaries)
	}
}
