// Package vulngate keeps images with too many known vulnerabilities from being
// deployed.
//
// A ValidatingAdmissionPolicy cannot ask anyone anything while it decides: it
// sees the object being admitted and a parameter object already in the cluster.
// So Sentinel does the knowing ahead of time. It works out which scanned images
// are over the limit, writes them into a ConfigMap, and the policy refuses a
// workload whose image is listed there.
//
// What Sentinel has not scanned is not listed, and is therefore admitted. The
// gate acts on what is known, as NeuVector's does; it is not a guarantee that
// everything running has been looked at.
package vulngate

import (
	"fmt"
	"sort"
	"strings"
)

// Name is what the ConfigMap, the policy and its binding are all called.
const Name = "sentinel-vulnerability-gate"

// A ConfigMap holds 1 MiB. Staying well under leaves room for the object's own
// metadata and for an update not to be refused at the edge.
const maxListBytes = 900 << 10

// Settings is what the administrator chooses.
type Settings struct {
	Enabled bool `json:"enabled"`
	// "warn" admits the workload and returns a warning; "deny" refuses it.
	Mode string `json:"mode"`
	// An image is over the limit with more criticals than CriticalLimit, or more
	// highs than HighLimit. -1 means that severity is not counted.
	CriticalLimit int `json:"criticalLimit"`
	HighLimit     int `json:"highLimit"`
	// Namespaces the gate leaves alone, on top of kube-system and Sentinel's own.
	ExcludeNamespaces []string `json:"excludeNamespaces"`
}

// DefaultSettings is the gate switched off, set to the strictest useful rule
// for when it is switched on.
func DefaultSettings() Settings {
	return Settings{Mode: "warn", CriticalLimit: 0, HighLimit: -1, ExcludeNamespaces: []string{}}
}

// Validate normalises s and reports what is wrong with it.
func (s *Settings) Validate() error {
	if s.Mode != "warn" && s.Mode != "deny" {
		return fmt.Errorf("mode must be warn or deny")
	}
	if s.CriticalLimit < -1 || s.HighLimit < -1 {
		return fmt.Errorf("a limit is a number from 0 up, or -1 for no limit")
	}
	if s.Enabled && s.CriticalLimit == -1 && s.HighLimit == -1 {
		return fmt.Errorf("set a limit for critical or for high vulnerabilities")
	}
	seen := map[string]bool{}
	out := []string{}
	for _, ns := range s.ExcludeNamespaces {
		ns = strings.TrimSpace(ns)
		if ns == "" || seen[ns] {
			continue
		}
		if len(ns) > 63 || strings.ContainsAny(ns, " /,*") {
			return fmt.Errorf("%q is not a namespace name", ns)
		}
		seen[ns] = true
		out = append(out, ns)
	}
	sort.Strings(out)
	s.ExcludeNamespaces = out
	return nil
}

// over reports whether the counts exceed the limits.
func (s Settings) over(critical, high int) bool {
	return (s.CriticalLimit >= 0 && critical > s.CriticalLimit) ||
		(s.HighLimit >= 0 && high > s.HighLimit)
}

// ScannedImage is one image some scan has a result for.
type ScannedImage struct {
	// As a pod spec or a registry names it: "nginx:1.27", "quay.io/org/app:v2".
	Ref      string `json:"image"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	// Where the result came from, for the page: a workload or a registry.
	Source string `json:"source"`
}

// List is the images over the limit, as the policy will read them.
type List struct {
	// ConfigMap data: an encoded image reference to the reason it is refused.
	Data map[string]string
	// The images behind Data, worst first, one entry per image whatever number
	// of spellings it is listed under.
	Images []ScannedImage
	// Images over the limit that did not fit in the ConfigMap.
	LeftOut int
}

// Build works out the list from every scan result there is.
func Build(scanned []ScannedImage, s Settings) List {
	// The same image may have been scanned as a workload and from a registry.
	// The higher counts win: a result that says it is over the limit is not
	// outvoted by an older one that says it is not.
	worst := map[string]ScannedImage{}
	for _, img := range scanned {
		ref := canonical(img.Ref)
		if ref == "" {
			continue
		}
		if cur, ok := worst[ref]; ok {
			if img.Critical < cur.Critical || (img.Critical == cur.Critical && img.High <= cur.High) {
				continue
			}
		}
		img.Ref = ref
		worst[ref] = img
	}
	var over []ScannedImage
	for _, img := range worst {
		if s.over(img.Critical, img.High) {
			over = append(over, img)
		}
	}
	sort.Slice(over, func(i, j int) bool {
		if over[i].Critical != over[j].Critical {
			return over[i].Critical > over[j].Critical
		}
		if over[i].High != over[j].High {
			return over[i].High > over[j].High
		}
		return over[i].Ref < over[j].Ref
	})

	list := List{Data: map[string]string{}, Images: []ScannedImage{}}
	size := 0
	for _, img := range over {
		reason := fmt.Sprintf("%d critical, %d high", img.Critical, img.High)
		keys := []string{}
		add := 0
		for _, spelling := range spellings(img.Ref) {
			k := Key(spelling)
			// A ConfigMap key is at most 253 characters.
			if len(k) > 253 {
				continue
			}
			if _, dup := list.Data[k]; dup {
				continue
			}
			keys = append(keys, k)
			add += len(k) + len(reason)
		}
		if len(keys) == 0 {
			continue
		}
		if size+add > maxListBytes {
			list.LeftOut++
			continue
		}
		for _, k := range keys {
			list.Data[k] = reason
		}
		size += add
		list.Images = append(list.Images, img)
	}
	return list
}

// Key encodes an image reference as a ConfigMap key, which may hold letters,
// digits, '-', '_' and '.' only. The policy's CEL does the same three
// replacements on the image it is looking at; keyExpr below must stay in step.
func Key(image string) string {
	r := strings.NewReplacer("/", "_.._", ":", "_._", "@", "_..._")
	return r.Replace(image)
}

// keyExpr is Key written in CEL, for an image held in the variable i.
const keyExpr = `i.replace('/', '_.._').replace(':', '_._').replace('@', '_..._')`

var dockerHubHosts = map[string]bool{
	"docker.io": true, "index.docker.io": true, "registry-1.docker.io": true, "registry.hub.docker.com": true,
}

// split takes a reference apart: its registry host ("" when it names none), its
// repository, and its tag or digest with the separator.
func split(ref string) (host, repo, suffix string) {
	ref = strings.TrimSpace(ref)
	if i := strings.Index(ref, "@"); i >= 0 {
		ref, suffix = ref[:i], ref[i:]
	}
	// A colon after the last slash is a tag; before it, a registry port.
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		if suffix == "" {
			suffix = ref[i:]
		}
		ref = ref[:i]
	}
	if first, rest, ok := strings.Cut(ref, "/"); ok &&
		(strings.ContainsAny(first, ".:") || first == "localhost") {
		return first, rest, suffix
	}
	return "", ref, suffix
}

// canonical is the one spelling an image is known by here, so that the same
// image from two scans is counted once: Docker Hub images lose their registry
// host and "library/", and a reference with neither tag nor digest gains
// ":latest", which is what it means.
func canonical(ref string) string {
	host, repo, suffix := split(ref)
	if repo == "" {
		return ""
	}
	if suffix == "" {
		suffix = ":latest"
	}
	if host == "" || dockerHubHosts[host] {
		return strings.TrimPrefix(repo, "library/") + suffix
	}
	return host + "/" + repo + suffix
}

// spellings is every way a pod spec may write a canonical reference. The policy
// compares strings, so each one has to be listed: "nginx", "nginx:latest" and
// "docker.io/library/nginx:latest" are one image to a container runtime and
// three to CEL.
func spellings(ref string) []string {
	host, repo, suffix := split(ref)
	suffixes := []string{suffix}
	if suffix == ":latest" {
		suffixes = append(suffixes, "")
	}
	var names []string
	if host != "" {
		names = []string{host + "/" + repo}
	} else {
		full := repo
		if !strings.Contains(repo, "/") {
			full = "library/" + repo
			names = append(names, repo)
		}
		names = append(names, full, "docker.io/"+full, "index.docker.io/"+full)
		if full != repo {
			names = append(names, "docker.io/"+repo)
		}
	}
	out := make([]string, 0, len(names)*len(suffixes))
	for _, n := range names {
		for _, s := range suffixes {
			out = append(out, n+s)
		}
	}
	return out
}
