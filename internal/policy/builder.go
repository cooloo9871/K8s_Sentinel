package policy

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

	// Process rules: ONE sys_execve kprobe with all binaries combined.
	// Multiple kprobes for the same function name cause BPF link pin conflicts.
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
				MatchBinaries: []BinarySelector{{Operator: "In", Values: allBinaries}},
				MatchActions:  []ActionSelector{{Action: action}},
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

	return tp, nil
}
