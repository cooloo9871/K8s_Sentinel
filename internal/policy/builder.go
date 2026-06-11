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
	// Whitelist (default): NotPostfix — kill anything whose path does NOT end with a listed suffix.
	// Blacklist: Postfix — kill anything whose path ends with a listed suffix.
	//
	// Strip the leading '/' from each binary value so the suffix matches both
	// absolute paths (/cgichild.sh) and relative-path calls (cgichild.sh).
	// e.g. "/cgichild.sh" → "cgichild.sh" matches both "cgichild.sh" and "/cgichild.sh"
	//      "/usr/bin/cat" → "usr/bin/cat" matches "/usr/bin/cat" only (path-specific)
	var allBinaries []string
	for _, r := range input.Process {
		for _, b := range r.Binaries {
			if len(b) > 0 && b[0] == '/' {
				b = b[1:]
			}
			allBinaries = append(allBinaries, b)
		}
	}
	if len(allBinaries) > 0 {
		processOp := "NotPostfix"
		if input.ProcessMode == "blacklist" {
			processOp = "Postfix"
		}
		tp.Spec.KProbes = append(tp.Spec.KProbes, KProbeSpec{
			Call:    "sys_execve",
			Syscall: true,
			Args:    []KProbeArg{{Index: 0, Type: "string"}},
			Selectors: []KProbeSelector{{
				MatchArgs:    []ArgSelector{{Index: 0, Operator: processOp, Values: allBinaries}},
				MatchActions: []ActionSelector{{Action: action}},
			}},
		})
	}

	// File rules: ONE security_file_permission kprobe with all paths combined.
	var allPaths []string
	for _, r := range input.File {
		allPaths = append(allPaths, r.Paths...)
	}
	if len(allPaths) > 0 {
		tp.Spec.KProbes = append(tp.Spec.KProbes, KProbeSpec{
			Call:    "security_file_permission",
			Syscall: false,
			Args:    []KProbeArg{{Index: 0, Type: "file"}, {Index: 1, Type: "int"}},
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
	var ports []string
	for _, p := range input.NetworkPorts {
		if t := strings.TrimSpace(p); t != "" {
			ports = append(ports, t)
		}
	}

	var netSelectors []KProbeSelector

	// Append selectors using blacklist/whitelist mode.
	// An unrecognised NetworkMode with addresses/ports is treated as whitelist
	// only when NetworkMode is the empty string (unset); any other unexpected
	// value skips the address/port selectors entirely to avoid silently applying
	// wrong semantics.
	if input.NetworkMode != "" && input.NetworkMode != "blacklist" && input.NetworkMode != "whitelist" {
		// Unknown mode — skip address/port selectors, keep binary-specific ones.
		goto buildKProbe
	}
	if input.NetworkMode == "blacklist" {
		var matchArgs []ArgSelector
		if len(netAddresses) > 0 {
			matchArgs = append(matchArgs, ArgSelector{Index: 0, Operator: "DAddr", Values: netAddresses})
		}
		if len(ports) > 0 {
			matchArgs = append(matchArgs, ArgSelector{Index: 0, Operator: "DPort", Values: ports})
		}
		if len(matchArgs) > 0 {
			netSelectors = append(netSelectors, KProbeSelector{
				MatchArgs:    matchArgs,
				MatchActions: []ActionSelector{{Action: action}},
			})
		}
	} else {
		// Whitelist: SEPARATE selectors → NotDAddr OR NotDPort (OR semantics).
		if len(netAddresses) > 0 {
			netSelectors = append(netSelectors, KProbeSelector{
				MatchArgs:    []ArgSelector{{Index: 0, Operator: "NotDAddr", Values: netAddresses}},
				MatchActions: []ActionSelector{{Action: action}},
			})
		}
		if len(ports) > 0 {
			netSelectors = append(netSelectors, KProbeSelector{
				MatchArgs:    []ArgSelector{{Index: 0, Operator: "NotDPort", Values: ports}},
				MatchActions: []ActionSelector{{Action: action}},
			})
		}
	}

buildKProbe:
	if len(netSelectors) > 0 {
		tp.Spec.KProbes = append(tp.Spec.KProbes, KProbeSpec{
			Call:      "tcp_connect",
			Syscall:   false,
			Args:      []KProbeArg{{Index: 0, Type: "sock"}},
			Selectors: netSelectors,
		})
	}

	return tp, nil
}
