package registry

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// On the Job and its pod. Trivy Operator is told to skip resources carrying
	// it, and the Vulnerabilities page leaves the pods out of its workloads.
	ScanLabel = "sentinel.io/registry-scan"

	// Printed last by the scan pod. A log without it is a scan that did not finish.
	completeMarker = "SENTINEL-SCAN-COMPLETE"

	scanTimeout  = 15 * time.Minute
	pollInterval = 3 * time.Second
	maxLogBytes  = 64 << 20
)

// One JSON object per finding, then the marker. Trivy's full JSON report runs
// to megabytes an image, more than is safe to carry through a pod log.
var outputTemplate = `{{ range . }}{{ range .Vulnerabilities }}{{ toJson (dict "id" .VulnerabilityID "severity" .Severity "package" .PkgName "installedVersion" .InstalledVersion "fixedVersion" .FixedVersion "title" .Title "link" .PrimaryURL) }}
{{ end }}{{ end }}` + completeMarker

// JobRunner scans one image by running Trivy in a Job in Sentinel's namespace.
type JobRunner struct {
	Client    kubernetes.Interface
	Namespace string
	// The Trivy image, and where it downloads its databases from when that is
	// not Trivy's default (an air-gapped cluster's mirror).
	TrivyImage       string
	DBRepository     string
	JavaDBRepository string

	poll time.Duration
}

func (r *JobRunner) interval() time.Duration {
	if r.poll > 0 {
		return r.poll
	}
	return pollInterval
}

func randomSuffix() string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// buildJob is the Job that scans one image. secret names the Secret holding the
// registry credentials, or is empty when there are none.
func (r *JobRunner) buildJob(name string, cfg Config, image, secret string) *batchv1.Job {
	env := []corev1.EnvVar{}
	if secret != "" {
		ref := func(key string) *corev1.EnvVarSource {
			return &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: secret}, Key: key,
			}}
		}
		env = append(env,
			corev1.EnvVar{Name: "TRIVY_USERNAME", ValueFrom: ref("username")},
			corev1.EnvVar{Name: "TRIVY_PASSWORD", ValueFrom: ref("password")},
		)
	}
	if cfg.SkipTLSVerify {
		env = append(env, corev1.EnvVar{Name: "TRIVY_INSECURE", Value: "true"})
	}
	if strings.HasPrefix(cfg.URL, "http://") {
		env = append(env, corev1.EnvVar{Name: "TRIVY_NON_SSL", Value: "true"})
	}
	if r.DBRepository != "" {
		env = append(env, corev1.EnvVar{Name: "TRIVY_DB_REPOSITORY", Value: r.DBRepository})
	}
	if r.JavaDBRepository != "" {
		env = append(env, corev1.EnvVar{Name: "TRIVY_JAVA_DB_REPOSITORY", Value: r.JavaDBRepository})
	}

	labels := map[string]string{
		"app.kubernetes.io/managed-by": "sentinel",
		ScanLabel:                      cfg.ID,
	}
	no, yes := false, true
	user := int64(10000)
	var zero int32
	ttl := int32(300)
	deadline := int64(scanTimeout / time.Second)
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: r.Namespace, Labels: labels},
		Spec: batchv1.JobSpec{
			BackoffLimit:            &zero,
			ActiveDeadlineSeconds:   &deadline,
			TTLSecondsAfterFinished: &ttl, // if Sentinel is not there to delete it
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					RestartPolicy:                corev1.RestartPolicyNever,
					AutomountServiceAccountToken: &no,
					// What the namespace's restricted Pod Security level asks for.
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot:   &yes,
						RunAsUser:      &user,
						RunAsGroup:     &user,
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					Containers: []corev1.Container{{
						Name:  "trivy",
						Image: r.TrivyImage,
						Args: []string{
							"image", "--quiet", "--scanners", "vuln",
							"--cache-dir", "/tmp/trivy",
							"--format", "template", "--template", outputTemplate,
							image,
						},
						Env: env,
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: &no,
							ReadOnlyRootFilesystem:   &yes,
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("256Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceMemory: resource.MustParse("1Gi"),
							},
						},
						// The databases and the image's layers are unpacked here.
						VolumeMounts: []corev1.VolumeMount{{Name: "tmp", MountPath: "/tmp"}},
					}},
					Volumes: []corev1.Volume{{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}},
				},
			},
		},
	}
}

// Scan runs one image's scan to the end and returns what it found.
func (r *JobRunner) Scan(ctx context.Context, cfg Config, image string) ([]Finding, error) {
	ctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()
	name := "registry-scan-" + randomSuffix()
	jobs := r.Client.BatchV1().Jobs(r.Namespace)
	secrets := r.Client.CoreV1().Secrets(r.Namespace)
	// Cleaning up must still happen when ctx is what ended the scan.
	cleanup := func(f func(context.Context) error) {
		c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = f(c)
	}

	secret := ""
	if cfg.Username != "" {
		secret = name
		_, err := secrets.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: r.Namespace, Labels: map[string]string{ScanLabel: cfg.ID}},
			StringData: map[string]string{"username": cfg.Username, "password": cfg.Password},
		}, metav1.CreateOptions{})
		if err != nil {
			return nil, fmt.Errorf("creating the credentials Secret: %w", err)
		}
		defer cleanup(func(c context.Context) error { return secrets.Delete(c, name, metav1.DeleteOptions{}) })
	}

	job, err := jobs.Create(ctx, r.buildJob(name, cfg, image, secret), metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("creating the scan Job: %w", err)
	}
	background := metav1.DeletePropagationBackground
	defer cleanup(func(c context.Context) error {
		return jobs.Delete(c, name, metav1.DeleteOptions{PropagationPolicy: &background})
	})
	if secret != "" {
		// So the Secret goes with the Job even if Sentinel stops before the
		// deferred delete runs.
		if s, err := secrets.Get(ctx, name, metav1.GetOptions{}); err == nil {
			s.OwnerReferences = []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID}}
			_, _ = secrets.Update(ctx, s, metav1.UpdateOptions{})
		}
	}

	finished := false
	for !finished {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, fmt.Errorf("the scan did not finish in %s%s", scanTimeout, r.podProblem(name))
			}
			return nil, ctx.Err()
		case <-time.After(r.interval()):
		}
		j, err := jobs.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("reading the scan Job: %w", err)
		}
		finished = j.Status.Succeeded > 0 || j.Status.Failed > 0
	}

	out, err := r.podLog(ctx, name)
	if err != nil {
		return nil, err
	}
	return parseOutput(out)
}

func (r *JobRunner) pod(ctx context.Context, job string) (*corev1.Pod, error) {
	pods, err := r.Client.CoreV1().Pods(r.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "job-name=" + job})
	if err != nil {
		return nil, fmt.Errorf("finding the scan pod: %w", err)
	}
	if len(pods.Items) == 0 {
		return nil, errors.New("the scan Job has no pod")
	}
	return &pods.Items[0], nil
}

// podProblem says why a scan pod is not getting anywhere, when the pod itself
// knows: an image that cannot be pulled, a pod nothing will admit.
func (r *JobRunner) podProblem(job string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pod, err := r.pod(ctx, job)
	if err != nil {
		return ""
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if w := cs.State.Waiting; w != nil && w.Reason != "" {
			return fmt.Sprintf(": the scan pod is waiting, %s %s", w.Reason, w.Message)
		}
	}
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionFalse {
			return ": the scan pod could not be scheduled, " + c.Message
		}
	}
	return ""
}

func (r *JobRunner) podLog(ctx context.Context, job string) (string, error) {
	pod, err := r.pod(ctx, job)
	if err != nil {
		return "", err
	}
	stream, err := r.Client.CoreV1().Pods(r.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{}).Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("reading the scan pod's output: %w", err)
	}
	defer stream.Close()
	data, err := io.ReadAll(io.LimitReader(stream, maxLogBytes))
	if err != nil {
		return "", fmt.Errorf("reading the scan pod's output: %w", err)
	}
	return string(data), nil
}

var logPrefix = regexp.MustCompile(`^\S+Z\s+(FATAL|ERROR)\s+(Fatal error\s+)?`)

// parseOutput reads a scan pod's log. Trivy's own messages share the stream
// with the findings, so a line is a finding only if it is a JSON object; and
// without the closing marker the scan failed, with Trivy's last message as the
// reason.
func parseOutput(out string) ([]Finding, error) {
	findings := []Finding{}
	complete := false
	lastMessage := ""
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "":
		case line == completeMarker:
			complete = true
		case strings.HasPrefix(line, "{"):
			var f Finding
			if json.Unmarshal([]byte(line), &f) == nil && f.ID != "" {
				findings = append(findings, f)
			} else {
				lastMessage = line
			}
		default:
			lastMessage = line
		}
	}
	if !complete {
		if lastMessage == "" {
			return nil, errors.New("the scan ended without output")
		}
		// Trivy prefixes its messages with a timestamp and level; the reason
		// is what follows.
		lastMessage = logPrefix.ReplaceAllString(lastMessage, "")
		if len(lastMessage) > 600 {
			lastMessage = lastMessage[:600] + "…"
		}
		return nil, errors.New(lastMessage)
	}
	return findings, nil
}

// CleanupStale removes scan Jobs left by a previous Sentinel process. Their
// results were never read, and the runs they belonged to start again.
func (r *JobRunner) CleanupStale(ctx context.Context) {
	jobs := r.Client.BatchV1().Jobs(r.Namespace)
	list, err := jobs.List(ctx, metav1.ListOptions{LabelSelector: ScanLabel})
	if err != nil {
		return
	}
	background := metav1.DeletePropagationBackground
	for _, j := range list.Items {
		_ = jobs.Delete(ctx, j.Name, metav1.DeleteOptions{PropagationPolicy: &background})
	}
}
