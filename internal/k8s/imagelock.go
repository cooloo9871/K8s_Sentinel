package k8s

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/cooloo9871/K8s_Sentinel/internal/policy"
)

// An image lock is a policy nobody fills in: a workload may run the files its
// images came with, started by its own processes, and nothing else. A tool
// written into the container after it started is not on the list, and a
// command sent in from outside is not started by the container.
//
// Tetragon matches a path and has no notion of "came with the image", so the
// list is read on the node, from a running container of each image, and kept
// up to date as the workload's images change.

const (
	// annotationImageLock marks the policy and names the workload: "Kind/name".
	annotationImageLock = "sentinel.io/image-lock"
	// annotationImageLockBuilt is what the list was read from, to tell when it
	// has to be read again.
	annotationImageLockBuilt = "sentinel.io/image-lock-built-from"

	imageLockPrefix = "image-lock-"
	// An object has to fit in etcd, which takes about 1.5 MB.
	imageLockMaxBytes = 1_000_000
)

var (
	ErrWorkloadNotFound = errors.New("workload not found")
	ErrNoRunningPod     = errors.New("the workload has no running pod to read its image from")
	ErrImageTooLarge    = errors.New("the images have more executable files than one policy can list")
)

// imageFilesScript reads container IDs, one a line, and for each prints the ID
// alone, then the ID and the path of every executable file its image came
// with, tab-separated.
//
// A container's ID is also in the cgroup of what the runtime keeps beside it
// on the node (conmon, under CRI-O), and that process sees the node's files,
// not the image's. Only a process whose root is not the node's is read from.
//
// "Came with the image" is what is on the container's root filesystem and not
// in the layer the container writes to: a file dropped in before the list was
// read must not be on it. On a root that is not an overlay nothing can be told
// apart, and every file is listed. Volumes are other filesystems and are left
// out. A name with a tab or a newline in it is passed over, those being what
// separates the output.
const imageFilesScript = "# " + procNamesMark + `
P=/procRoot; [ -d $P/1 ] || P=/proc
nl='
'
tab=$(printf '\t')
while read -r cid; do
  case $cid in ''|*[!0-9a-f]*) continue ;; esac
  d=
  for c in $(grep -l -- "$cid" $P/[0-9]*/cgroup 2>/dev/null); do
    x=${c%/cgroup}
    [ -d "$x/root/" ] || continue
    if [ "$x/root/" -ef "$P/1/root/" ]; then continue; fi
    d=$x; break
  done
  [ -n "$d" ] || continue
  up=$(sed -n 's/^[0-9]* [0-9]* [^ ]* \/ \/ .* - overlay .*[ ,]upperdir=\([^, ]*\).*/\1/p' $d/mountinfo 2>/dev/null | head -n1)
  [ -n "$up" ] && up=$P/1/root$up
  printf '%s\t\n' "$cid"
  find "$d/root/" -xdev -type f -perm /111 -print0 2>/dev/null | while IFS= read -r -d '' f; do
    p=/${f#"$d/root/"}
    case $p in *"$nl"*|*"$tab"*) continue ;; esac
    if [ -n "$up" ] && [ -e "$up$p" ]; then continue; fi
    printf '%s\t%s\n' "$cid" "$p"
  done
done
exit 0
`

// parseImageFiles reads the script's output: for each container it found, the
// paths it listed.
func parseImageFiles(out []byte) map[string][]string {
	files := make(map[string][]string)
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 2 || f[0] == "" {
			continue
		}
		if f[1] == "" {
			if _, ok := files[f[0]]; !ok {
				files[f[0]] = nil
			}
			continue
		}
		if strings.HasPrefix(f[1], "/") {
			files[f[0]] = append(files[f[0]], f[1])
		}
	}
	return files
}

// Workload names a Deployment, StatefulSet or DaemonSet.
type Workload struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// ListWorkloads returns the workloads of a namespace an image lock can be put
// on: the kinds that keep pods running under one selector.
func (s *Store) ListWorkloads(ctx context.Context, namespace string) ([]Workload, error) {
	out := []Workload{}
	deps, err := s.typed.AppsV1().Deployments(namespace).List(ctx, fromCache)
	if err != nil {
		return nil, err
	}
	for _, d := range deps.Items {
		out = append(out, Workload{"Deployment", d.Name})
	}
	sets, err := s.typed.AppsV1().StatefulSets(namespace).List(ctx, fromCache)
	if err != nil {
		return nil, err
	}
	for _, d := range sets.Items {
		out = append(out, Workload{"StatefulSet", d.Name})
	}
	dss, err := s.typed.AppsV1().DaemonSets(namespace).List(ctx, fromCache)
	if err != nil {
		return nil, err
	}
	for _, d := range dss.Items {
		out = append(out, Workload{"DaemonSet", d.Name})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Kind < out[j].Kind
	})
	return out, nil
}

// workloadSpec returns a workload's selector and pod template.
func (s *Store) workloadSpec(ctx context.Context, namespace, kind, name string) (*metav1.LabelSelector, *corev1.PodSpec, error) {
	var sel *metav1.LabelSelector
	var spec *corev1.PodSpec
	var err error
	switch kind {
	case "Deployment":
		w, e := s.typed.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if err = e; e == nil {
			sel, spec = w.Spec.Selector, &w.Spec.Template.Spec
		}
	case "StatefulSet":
		w, e := s.typed.AppsV1().StatefulSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err = e; e == nil {
			sel, spec = w.Spec.Selector, &w.Spec.Template.Spec
		}
	case "DaemonSet":
		w, e := s.typed.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err = e; e == nil {
			sel, spec = w.Spec.Selector, &w.Spec.Template.Spec
		}
	default:
		return nil, nil, ErrWorkloadNotFound
	}
	if k8serrors.IsNotFound(err) {
		return nil, nil, ErrWorkloadNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	if sel == nil {
		return nil, nil, ErrWorkloadNotFound
	}
	return sel, spec, nil
}

// startedFromOutside reports whether the kubelet itself runs commands in the
// workload's containers, or the containers do not each have a process tree of
// their own. In either case "started by the container's first process" cannot
// be the rule: a probe is started from outside like any kubectl exec, and in a
// shared process namespace the first process is not the container's.
func startedFromOutside(spec *corev1.PodSpec) bool {
	if spec.HostPID || (spec.ShareProcessNamespace != nil && *spec.ShareProcessNamespace) {
		return true
	}
	for _, c := range spec.Containers {
		for _, p := range []*corev1.Probe{c.LivenessProbe, c.ReadinessProbe, c.StartupProbe} {
			if p != nil && p.Exec != nil {
				return true
			}
		}
		if l := c.Lifecycle; l != nil {
			if (l.PostStart != nil && l.PostStart.Exec != nil) || (l.PreStop != nil && l.PreStop.Exec != nil) {
				return true
			}
		}
	}
	return false
}

// lockSource is one running container to read an image's files from.
type lockSource struct {
	node, containerID string
}

// lockTargets looks at the workload's running pods: the containers the policy
// is to cover, one running container of each image among them, and a string
// that changes when either does.
func (s *Store) lockTargets(ctx context.Context, namespace string, selector *metav1.LabelSelector) (containers []string, sources map[string]lockSource, built string, err error) {
	sel, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return nil, nil, "", err
	}
	pods, err := s.typed.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: sel.String()})
	if err != nil {
		return nil, nil, "", err
	}
	names := map[string]bool{}
	sources = map[string]lockSource{}
	for _, p := range pods.Items {
		if p.DeletionTimestamp != nil {
			continue
		}
		for _, cs := range p.Status.ContainerStatuses {
			_, id, ok := strings.Cut(cs.ContainerID, "://")
			if cs.State.Running == nil || !ok || id == "" {
				continue
			}
			image := cs.ImageID
			if image == "" {
				image = cs.Image
			}
			names[cs.Name] = true
			if _, seen := sources[image]; !seen {
				sources[image] = lockSource{node: p.Spec.NodeName, containerID: id}
			}
		}
	}
	if len(sources) == 0 {
		return nil, nil, "", ErrNoRunningPod
	}
	images := make([]string, 0, len(sources))
	for image := range sources {
		images = append(images, image)
	}
	for n := range names {
		containers = append(containers, n)
	}
	sort.Strings(images)
	sort.Strings(containers)
	return containers, sources, strings.Join(containers, ",") + "|" + strings.Join(images, ","), nil
}

// imageFilesOn runs the script on one node. A variable so that a test can
// answer in its place.
var imageFilesOn = func(ctx context.Context, s *Store, node string, containerIDs []string) ([]byte, error) {
	agents, err := s.findAllTetragonPods(ctx)
	if err != nil {
		return nil, err
	}
	for _, a := range agents {
		if a.Node != node {
			continue
		}
		var stdin bytes.Buffer
		for _, id := range containerIDs {
			fmt.Fprintln(&stdin, id)
		}
		return s.execInAgent(ctx, a.Name, imageFilesScript, &stdin)
	}
	return nil, fmt.Errorf("no Tetragon agent on node %s", node)
}

// imageFiles reads the executable files of every image, and returns them as
// one sorted list.
func (s *Store) imageFiles(ctx context.Context, sources map[string]lockSource) ([]string, error) {
	byNode := map[string][]string{}
	for _, src := range sources {
		byNode[src.node] = append(byNode[src.node], src.containerID)
	}
	seen := map[string]bool{}
	size := 0
	for node, ids := range byNode {
		out, err := imageFilesOn(ctx, s, node, ids)
		if err != nil {
			return nil, fmt.Errorf("read image files on node %s: %w", node, err)
		}
		files := parseImageFiles(out)
		for _, id := range ids {
			// A list that came back empty would make a policy that stops
			// everything the workload runs.
			if len(files[id]) == 0 {
				return nil, fmt.Errorf("no executable files were read from container %.12s on node %s", id, node)
			}
			for _, p := range files[id] {
				if !seen[p] {
					seen[p] = true
					size += len(p)
				}
			}
		}
	}
	if size > imageLockMaxBytes {
		return nil, ErrImageTooLarge
	}
	paths := make([]string, 0, len(seen))
	for p := range seen {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths, nil
}

// imageLockObject builds the policy. The hook is the one where the kernel has
// already found the file it is about to run: a shell that tries a command in
// each directory of PATH makes an execve for every one of them, and at the
// system call those attempts are indistinguishable from running something that
// is not on the list.
func imageLockObject(namespace string, w Workload, selector *metav1.LabelSelector, containers, paths []string, built, action string, outside bool) (*unstructured.Unstructured, error) {
	podSelector, err := runtime.DefaultUnstructuredConverter.ToUnstructured(selector)
	if err != nil {
		return nil, err
	}
	act := func() []any { return []any{map[string]any{"action": action}} }
	list := func(in []string) []any {
		out := make([]any, len(in))
		for i, v := range in {
			out[i] = v
		}
		return out
	}
	selectors := []any{}
	if !outside {
		selectors = append(selectors, map[string]any{
			"matchPIDs": []any{map[string]any{
				"operator":       "NotIn",
				"followForks":    true,
				"isNamespacePID": true,
				"values":         []any{int64(1)},
			}},
			"matchActions": act(),
		})
	}
	selectors = append(selectors, map[string]any{
		"matchArgs": []any{map[string]any{
			"index":    int64(0),
			"operator": "NotEqual",
			"values":   list(paths),
		}},
		"matchActions": act(),
	})
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cilium.io/v1alpha1",
		"kind":       "TracingPolicyNamespaced",
		"metadata": map[string]any{
			"name":      imageLockPrefix + strings.ToLower(w.Name),
			"namespace": namespace,
			"annotations": map[string]any{
				annotationImageLock:      w.Kind + "/" + w.Name,
				annotationImageLockBuilt: built,
			},
		},
		"spec": map[string]any{
			"podSelector": podSelector,
			// Not the init containers: they have run and gone, so there is
			// nothing to read their images from.
			"containerSelector": map[string]any{
				"matchExpressions": []any{map[string]any{
					"key":      "name",
					"operator": "In",
					"values":   list(containers),
				}},
			},
			"kprobes": []any{map[string]any{
				"call":    "security_bprm_check",
				"syscall": false,
				"args": []any{map[string]any{
					"index": int64(0),
					"type":  "linux_binprm",
				}},
				"selectors": selectors,
			}},
		},
	}}, nil
}

// ImageLockName is the name the policy for a workload is given.
func ImageLockName(workload string) string { return imageLockPrefix + strings.ToLower(workload) }

// CreateImageLock puts an image lock on a workload. It reports whether
// commands sent in from outside are stopped too, which they are not where the
// kubelet sends its own.
func (s *Store) CreateImageLock(ctx context.Context, namespace string, w Workload, mode, createdBy string) (blocksOutside bool, err error) {
	obj, outside, err := s.buildImageLock(ctx, namespace, w, modeAction(mode))
	if err != nil {
		return false, err
	}
	setCreatedByAnnotation(obj, createdBy)
	if _, err := s.client.Resource(tracingPolicyNamespacedGVR).Namespace(namespace).Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		return false, err
	}
	return !outside, nil
}

func (s *Store) buildImageLock(ctx context.Context, namespace string, w Workload, action string) (*unstructured.Unstructured, bool, error) {
	selector, spec, err := s.workloadSpec(ctx, namespace, w.Kind, w.Name)
	if err != nil {
		return nil, false, err
	}
	containers, sources, built, err := s.lockTargets(ctx, namespace, selector)
	if err != nil {
		return nil, false, err
	}
	paths, err := s.imageFiles(ctx, sources)
	if err != nil {
		return nil, false, err
	}
	outside := startedFromOutside(spec)
	obj, err := imageLockObject(namespace, w, selector, containers, paths, lockBuilt(built, selector, outside), action, outside)
	return obj, outside, err
}

// lockBuilt is everything a policy was made from. Not only the images: a
// probe added to the workload, or the workload made again under another
// selector, changes the policy with the same images running.
func lockBuilt(targets string, selector *metav1.LabelSelector, outside bool) string {
	return fmt.Sprintf("%s|%s|%t", targets, metav1.FormatLabelSelector(selector), outside)
}

// StartImageLockLoop keeps every image lock's list in step with the images its
// workload runs. A rollout brings an image whose files are not on the list
// yet; they can only be read once a container of it is running, so until the
// next pass what is new in that image is treated as not belonging.
func (s *Store) StartImageLockLoop(ctx context.Context) {
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.syncImageLocks(ctx)
			}
		}
	}()
}

func (s *Store) syncImageLocks(ctx context.Context) {
	list, err := s.client.Resource(tracingPolicyNamespacedGVR).Namespace("").List(ctx, fromCache)
	if err != nil {
		return
	}
	for i := range list.Items {
		item := &list.Items[i]
		kind, name, ok := strings.Cut(item.GetAnnotations()[annotationImageLock], "/")
		if !ok {
			continue
		}
		if err := s.syncImageLock(ctx, item, Workload{kind, name}); err != nil {
			log.Printf("image-lock: %s/%s: %v", item.GetNamespace(), item.GetName(), err)
		}
	}
}

func (s *Store) syncImageLock(ctx context.Context, item *unstructured.Unstructured, w Workload) error {
	ns := item.GetNamespace()
	selector, spec, err := s.workloadSpec(ctx, ns, w.Kind, w.Name)
	if errors.Is(err, ErrWorkloadNotFound) {
		return nil // the policy outlives its workload until someone deletes it
	}
	if err != nil {
		return err
	}
	_, _, built, err := s.lockTargets(ctx, ns, selector)
	if errors.Is(err, ErrNoRunningPod) {
		return nil
	}
	if err != nil {
		return err
	}
	if lockBuilt(built, selector, startedFromOutside(spec)) == item.GetAnnotations()[annotationImageLockBuilt] {
		return nil
	}
	action := policy.ActionPost
	if detectMode(item.Object) != "Monitoring" {
		action = policy.ActionSigkill
	}
	obj, _, err := s.buildImageLock(ctx, ns, w, action)
	if err != nil {
		return err
	}
	// The version that was read: a mode switched in the meantime is not
	// written over, and the next pass starts again from what is there.
	obj.SetResourceVersion(item.GetResourceVersion())
	preserveCreatedBy(obj, item)
	_, err = s.client.Resource(tracingPolicyNamespacedGVR).Namespace(ns).Update(ctx, obj, metav1.UpdateOptions{})
	if k8serrors.IsConflict(err) {
		return nil
	}
	return err
}
