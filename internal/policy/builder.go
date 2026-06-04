package policy

import "fmt"

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

	for _, r := range input.Process {
		tp.Spec.KProbes = append(tp.Spec.KProbes, buildProcessKProbe(r, action))
	}
	for _, r := range input.File {
		kp, err := buildFileKProbe(r, action)
		if err != nil {
			return TracingPolicy{}, err
		}
		tp.Spec.KProbes = append(tp.Spec.KProbes, kp)
	}

	return tp, nil
}

func buildProcessKProbe(r ProcessRule, action string) KProbeSpec {
	return KProbeSpec{
		Call:    "sys_execve",
		Syscall: true,
		Args:    []KProbeArg{{Index: 0, Type: "string"}},
		Selectors: []KProbeSelector{{
			MatchBinaries: []BinarySelector{{Operator: "In", Values: r.Binaries}},
			MatchActions:  []ActionSelector{{Action: action}},
		}},
	}
}

func buildFileKProbe(r FileRule, action string) (KProbeSpec, error) {
	call := ""
	switch r.Operation {
	case "read":
		call = "sys_read"
	case "write":
		call = "sys_write"
	case "open":
		call = "sys_openat"
	default:
		return KProbeSpec{}, fmt.Errorf("unknown file operation: %q", r.Operation)
	}
	return KProbeSpec{
		Call:    call,
		Syscall: true,
		Selectors: []KProbeSelector{{
			MatchArgs:    []ArgSelector{{Index: 0, Operator: "Prefix", Values: r.Paths}},
			MatchActions: []ActionSelector{{Action: action}},
		}},
	}, nil
}

