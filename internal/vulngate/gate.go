// Package vulngate supplies the admission policies that refuse images with too
// many known vulnerabilities.
//
// A ValidatingAdmissionPolicy cannot ask anyone anything while it decides: it
// sees the object being admitted and a parameter object already in the cluster.
// So Sentinel does the knowing ahead of time. It writes how many critical and
// high vulnerabilities each scanned image has into an object of its own kind, a
// VulnerabilityGate, and a policy made on the Admission Policy page compares
// those counts with the limit it was given.
//
// The policies and their bindings are the administrator's: Sentinel writes the
// counts and nothing else.
//
// The kind is Sentinel's own for a reason. Whoever creates a policy has to be
// allowed to read every object of the kind it takes as its parameter, across
// the cluster. With a ConfigMap as the parameter that would be every ConfigMap
// there is; with this kind it is the one list.
//
// What Sentinel has not scanned is not listed, and is therefore admitted. The
// policies act on what is known, as NeuVector's do; they are not a guarantee
// that everything running has been looked at.
package vulngate

import (
	"sort"
	"strings"
)

// Name is what the list is called. The policies' bindings refer to it.
const Name = "sentinel-vulnerability-gate"

// An object may be about 1.5 MiB in etcd. Staying well under leaves room for
// its own metadata and for an update not to be refused at the edge.
const maxListBytes = 900 << 10

// What one entry costs beyond its key: its four counts and punctuation.
const entryBytes = 90

// ScannedImage is one image some scan has a result for.
type ScannedImage struct {
	// As a pod spec or a registry names it: "nginx:1.27", "quay.io/org/app:v2".
	Ref string
	Counts
	// The vulnerabilities in it that some policy names, by ID.
	CVEs []string
}

// Counts is what the list says about one image.
type Counts struct {
	Critical int
	High     int
	// The ones among them a newer version of the package fixes.
	FixableCritical int
	FixableHigh     int
}

// List is the scanned images as the policies will read them.
type List struct {
	// An image reference, in every spelling a pod spec may use, to its counts.
	Data map[string]Counts
	// The same references to the vulnerabilities some policy names that the
	// image has. Images with none have no entry.
	CVEs map[string][]string
	// Images that did not fit in the list. They are the ones with the fewest
	// vulnerabilities.
	LeftOut int
}

// Build works out the list from every scan result there is. An image with no
// critical and no high vulnerability, and none that a policy names, is one no
// policy can refuse, so it is not listed.
func Build(scanned []ScannedImage) List {
	// The same image may have been scanned as a workload and from a registry.
	// The higher counts win: a result that says it is over a limit is not
	// outvoted by an older one that says it is not.
	worst := map[string]ScannedImage{}
	for _, img := range scanned {
		ref := canonical(img.Ref)
		if ref == "" || (img.Critical <= 0 && img.High <= 0 && len(img.CVEs) == 0) {
			continue
		}
		img.Ref = ref
		if cur, ok := worst[ref]; ok {
			// Either scan finding a named vulnerability is enough to list it.
			named := union(cur.CVEs, img.CVEs)
			if img.Critical < cur.Critical || (img.Critical == cur.Critical && img.High <= cur.High) {
				img = cur
			}
			img.CVEs = named
		}
		worst[ref] = img
	}
	images := make([]ScannedImage, 0, len(worst))
	for _, img := range worst {
		images = append(images, img)
	}
	sort.Slice(images, func(i, j int) bool {
		if images[i].Critical != images[j].Critical {
			return images[i].Critical > images[j].Critical
		}
		if images[i].High != images[j].High {
			return images[i].High > images[j].High
		}
		return images[i].Ref < images[j].Ref
	})

	list := List{Data: map[string]Counts{}, CVEs: map[string][]string{}}
	size := 0
	for _, img := range images {
		keys := []string{}
		add := 0
		for _, k := range spellings(img.Ref) {
			if _, dup := list.Data[k]; dup {
				continue
			}
			keys = append(keys, k)
			add += len(k) + entryBytes
			for _, id := range img.CVEs {
				add += len(id) + 3
			}
		}
		if len(keys) == 0 {
			continue
		}
		if size+add > maxListBytes {
			list.LeftOut++
			continue
		}
		for _, k := range keys {
			list.Data[k] = img.Counts
			if len(img.CVEs) > 0 {
				list.CVEs[k] = img.CVEs
			}
		}
		size += add
	}
	return list
}

// union is both lists as one, sorted, each ID once.
func union(a, b []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, id := range append(append([]string{}, a...), b...) {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

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
