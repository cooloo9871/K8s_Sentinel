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
	//
	// cleanPaths trims and validates one list of file paths or exception
	// binaries. Relative entries are refused, like process binaries are: the
	// operators compare against the absolute path Tetragon resolves, so a
	// relative blacklist entry never matches (a silently dead rule) and a
	// relative whitelist entry makes NotPrefix true for every path — under
	// Sigkill that kills every process touching any file.
	cleanPaths := func(raw []string, what string) ([]string, error) {
		out := make([]string, 0, len(raw))
		for _, p := range raw {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if !strings.HasPrefix(p, "/") {
				return nil, fmt.Errorf("%s %q must be an absolute path", what, p)
			}
			out = append(out, p)
		}
		return out, nil
	}
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
		// set: the first rule carrying a specific (read/write) permission wins —
		// the same rule the form uses to display it, so what is shown is what is
		// generated.
		var allPaths, allBins []string
		permission := ""
		for _, r := range input.File {
			paths, err := cleanPaths(r.Paths, "file rule path")
			if err != nil {
				return TracingPolicy{}, err
			}
			allPaths = append(allPaths, paths...)
			bins, err := cleanPaths(r.ExceptBinaries, "file rule exception")
			if err != nil {
				return TracingPolicy{}, err
			}
			allBins = append(allBins, bins...)
			if permission == "" && r.Permission != "" && r.Permission != "all" {
				permission = r.Permission
			}
		}
		// Exceptions without a single excluded path would be dropped with the
		// whole file section; refuse rather than silently discard them.
		if len(allPaths) == 0 && len(allBins) > 0 {
			return TracingPolicy{}, fmt.Errorf("a file whitelist needs at least one excluded path; exception processes alone have no effect")
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
			paths, err := cleanPaths(r.Paths, "file rule path")
			if err != nil {
				return TracingPolicy{}, err
			}
			if len(paths) == 0 {
				continue
			}
			sel := KProbeSelector{
				MatchArgs:    append([]ArgSelector{{Index: 0, Operator: "Prefix", Values: paths}}, permArgs(r.Permission)...),
				MatchActions: []ActionSelector{{Action: action}},
			}
			bins, err := cleanPaths(r.ExceptBinaries, "file rule exception")
			if err != nil {
				return TracingPolicy{}, err
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

	// Network rules are refused rather than generated. The form dropped them
	// long ago (identity-based network control belongs to CiliumNetworkPolicy:
	// it cannot be bypassed by dialing a pod IP and drops packets instead of
	// killing processes), but the generator lingered here, and its whitelist
	// OR-ed separate NotDAddr/NotDPort selectors — the same broken semantics
	// the file whitelist had. A direct API caller sending network fields would
	// have received a policy that does not do what it says, so refuse instead.
	for _, r := range input.Network {
		if strings.TrimSpace(r.Address) != "" {
			return TracingPolicy{}, fmt.Errorf("network rules are not supported in Tracing Policy; use a Cilium Network Policy instead")
		}
	}
	for _, p := range input.NetworkPorts {
		if strings.TrimSpace(p) != "" {
			return TracingPolicy{}, fmt.Errorf("network rules are not supported in Tracing Policy; use a Cilium Network Policy instead")
		}
	}

	// A policy with no rules is not a policy: applied over an existing one it
	// replaces working rules with spec: {} and reports success.
	if len(tp.Spec.KProbes) == 0 {
		return TracingPolicy{}, fmt.Errorf("a policy needs at least one process or file rule")
	}
	return tp, nil
}
