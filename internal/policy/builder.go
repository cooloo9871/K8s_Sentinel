package policy

import "strings"

// Build converts PolicyFormInput into a TracingPolicy CRD object.
// action must be ActionPost ("Post") or ActionSigkill ("Sigkill").
func Build(input PolicyFormInput, action string) (TracingPolicy, error) {
	kind := "TracingPolicy"
	if input.Namespace != "" {
		kind = "TracingPolicyNamespaced"
	}

	tp := TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       kind,
		Metadata: ObjectMeta{
			Name:      input.Name,
			Namespace: input.Namespace,
		},
	}

	if len(input.PodSelector) > 0 {
		tp.Spec.PodSelector = &LabelSelector{MatchLabels: input.PodSelector}
	}

	// Process rules: ONE sys_execve kprobe with all values combined.
	// matchArgs + Postfix: "/cat" matches /bin/cat, /usr/bin/cat, etc.
	// Multiple kprobes for the same function cause BPF link pin conflicts.
	var allBinaries []string
	for _, r := range input.Process {
		allBinaries = append(allBinaries, r.Binaries...)
	}
	if len(allBinaries) > 0 {
		tp.Spec.KProbes = append(tp.Spec.KProbes, KProbeSpec{
			Call:    "sys_execve",
			Syscall: true,
			Args:    []KProbeArg{{Index: 0, Type: "string"}},
			Selectors: []KProbeSelector{{
				MatchArgs:    []ArgSelector{{Index: 0, Operator: "Postfix", Values: allBinaries}},
				MatchActions: []ActionSelector{{Action: action}},
			}},
		})
	}

	// File rules: ONE security_file_permission kprobe with all paths combined.
	// sys_read/sys_write/sys_openat work on file descriptors and cannot filter
	// by path. security_file_permission receives the file object directly.
	var allPaths []string
	for _, r := range input.File {
		allPaths = append(allPaths, r.Paths...)
	}
	if len(allPaths) > 0 {
		tp.Spec.KProbes = append(tp.Spec.KProbes, KProbeSpec{
			Call:    "security_file_permission",
			Syscall: false,
			Args: []KProbeArg{
				{Index: 0, Type: "file"},
				{Index: 1, Type: "int"},
			},
			Selectors: []KProbeSelector{{
				MatchArgs:    []ArgSelector{{Index: 0, Operator: "Prefix", Values: allPaths}},
				MatchActions: []ActionSelector{{Action: action}},
			}},
		})
	}

	// Network rules: ONE tcp_connect kprobe.
	// NetworkMode "blacklist" → DAddr    (block connections IN list)
	// NetworkMode "whitelist" → NotDAddr (block connections NOT in list) — default
	var netAddresses []string
	for _, r := range input.Network {
		if addr := strings.TrimSpace(r.Address); addr != "" {
			netAddresses = append(netAddresses, addr)
		}
	}
	if len(netAddresses) > 0 {
		netOperator := "NotDAddr"
		if input.NetworkMode == "blacklist" {
			netOperator = "DAddr"
		}
		tp.Spec.KProbes = append(tp.Spec.KProbes, KProbeSpec{
			Call:    "tcp_connect",
			Syscall: false,
			Args:    []KProbeArg{{Index: 0, Type: "sock"}},
			Selectors: []KProbeSelector{{
				MatchArgs:    []ArgSelector{{Index: 0, Operator: netOperator, Values: netAddresses}},
				MatchActions: []ActionSelector{{Action: action}},
			}},
		})
	}

	return tp, nil
}
