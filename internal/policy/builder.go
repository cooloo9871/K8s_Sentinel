package policy

import (
	"fmt"
	"strings"
)

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

	// Process rules: ONE sys_execve kprobe with all values combined, matched
	// exactly against the absolute path.
	//
	// Suffix matching was the previous design, so that a binary invoked by a
	// relative path still matched. It also meant a whitelist could be walked
	// straight past: NotPostfix "usr/sbin/nginx" allows anything ending in that,
	// so a binary at /tmp/usr/sbin/nginx runs. Keeping the leading slash would
	// not have helped — that path ends with "/usr/sbin/nginx" too. The operator
	// was the problem, not the slash.
	//
	// Absolute paths only, therefore, and matched with Equal. A relative name is
	// rejected rather than quietly widened: "nginx" as a whitelist entry means
	// any binary called nginx anywhere, which is not what someone typing a
	// program name is asking for.
	var allBinaries []string
	for _, r := range input.Process {
		for _, b := range r.Binaries {
			b = strings.TrimSpace(b)
			if b == "" { // skip empty strings that would break Tetragon validation
				continue
			}
			if !strings.HasPrefix(b, "/") {
				return TracingPolicy{}, fmt.Errorf(
					"process rule %q must be an absolute path: a bare name would match that "+
						"binary anywhere, including a copy dropped in /tmp", b)
			}
			allBinaries = append(allBinaries, b)
		}
	}
	if len(allBinaries) > 0 {
		processOp := "NotEqual"
		if input.ProcessMode == "blacklist" {
			processOp = "Equal"
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

	// File rules → ONE security_file_permission kprobe.
	var fileSelectors []KProbeSelector
	// permArgs turns a permission into the optional index-1 selector
	// (MAY_READ=4, MAY_WRITE=2); "all" adds nothing.
	permArgs := func(perm string) []ArgSelector {
		switch perm {
		case "read":
			return []ArgSelector{{Index: 1, Operator: "Equal", Values: []string{"4"}}}
		case "write":
			return []ArgSelector{{Index: 1, Operator: "Equal", Values: []string{"2"}}}
		}
		return nil
	}
	if input.FileMode == "whitelist" {
		// Whitelist MUST be a single selector: one NotPrefix over ALL paths and one
		// NotIn over ALL exception binaries. Tetragon OR-s separate selectors, so
		// "NotPrefix[a]" OR "NotPrefix[b]" is true for almost every path and the
		// exclusion silently fails; a single selector gives the intended "not a AND
		// not b". Permission and exceptions therefore apply to the whole exclusion
		// set (the first rule's permission wins).
		var allPaths, allBins []string
		permission := ""
		for _, r := range input.File {
			for _, p := range r.Paths {
				if p != "" {
					allPaths = append(allPaths, p)
				}
			}
			for _, b := range r.ExceptBinaries {
				if b != "" {
					allBins = append(allBins, b)
				}
			}
			if permission == "" {
				permission = r.Permission
			}
		}
		if len(allPaths) > 0 {
			sel := KProbeSelector{
				MatchArgs:    append([]ArgSelector{{Index: 0, Operator: "NotPrefix", Values: allPaths}}, permArgs(permission)...),
				MatchActions: []ActionSelector{{Action: action}},
			}
			if len(allBins) > 0 {
				sel.MatchBinaries = []BinarySelector{{Operator: "NotIn", Values: allBins}}
			}
			fileSelectors = append(fileSelectors, sel)
		}
	} else {
		// Blacklist: each rule gets its own selector (OR = block any listed path),
		// so per-rule permission and exception binaries are preserved.
		for _, r := range input.File {
			paths := make([]string, 0, len(r.Paths))
			for _, p := range r.Paths {
				if p != "" {
					paths = append(paths, p)
				}
			}
			if len(paths) == 0 {
				continue
			}
			sel := KProbeSelector{
				MatchArgs:    append([]ArgSelector{{Index: 0, Operator: "Prefix", Values: paths}}, permArgs(r.Permission)...),
				MatchActions: []ActionSelector{{Action: action}},
			}
			bins := make([]string, 0, len(r.ExceptBinaries))
			for _, b := range r.ExceptBinaries {
				if b != "" {
					bins = append(bins, b)
				}
			}
			if len(bins) > 0 {
				sel.MatchBinaries = []BinarySelector{{Operator: "NotIn", Values: bins}}
			}
			fileSelectors = append(fileSelectors, sel)
		}
	}
	if len(fileSelectors) > 0 {
		tp.Spec.KProbes = append(tp.Spec.KProbes, KProbeSpec{
			Call:      "security_file_permission",
			Syscall:   false,
			Args:      []KProbeArg{{Index: 0, Type: "file"}, {Index: 1, Type: "int"}},
			Selectors: fileSelectors,
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

	// A policy with no rules is not a policy: applied over an existing one it
	// replaces working rules with spec: {} and reports success.
	if len(tp.Spec.KProbes) == 0 {
		return TracingPolicy{}, fmt.Errorf("a policy needs at least one process or file rule")
	}
	return tp, nil
}
