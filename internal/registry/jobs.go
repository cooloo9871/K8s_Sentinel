package registry

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
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

	// Printed last by the scan pod, followed by how many findings it printed. A
	// log without it is a scan that did not finish; one with fewer findings
	// than it states has lost its beginning to log rotation.
	completeMarker = "SENTINEL-SCAN-COMPLETE"

	// How long a scan pod may sit unable to start before the scan gives up on
	// it, rather than waiting out the whole timeout.
	startGrace = 2 * time.Minute

	scanTimeout = 15 * time.Minute
	// Trivy gives up on its own after 5 minutes unless told otherwise, which a
	// large image on a slow link does not fit in: the database download and
	// every layer count against it. It is given most of the scan's time, with
	// the rest left for the pod to start.
	trivyTimeout = "13m"
	pollInterval = 3 * time.Second
	maxLogBytes  = 64 << 20
)

// One JSON object per finding, then the marker. Trivy's full JSON report runs
// to megabytes an image, more than is safe to carry through a pod log.
var outputTemplate = `{{ $n := 0 }}{{ range . }}{{ range .Vulnerabilities }}{{ $n = add $n 1 }}{{ toJson (dict "id" .VulnerabilityID "severity" .Severity "package" .PkgName "installedVersion" .InstalledVersion "fixedVersion" .FixedVersion "title" .Title "link" .PrimaryURL) }}
{{ end }}{{ end }}` + completeMarker + ` {{ $n }}`

// InfraError is a scan that failed because its pod could not run at all, which
// will be just as true of the next image.
type InfraError struct{ msg string }

func (e *InfraError) Error() string { return e.msg }

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

func (r *JobRunner) grace() time.Duration {
	if r.poll > 0 {
		return 20 * r.poll // tests
	}
	return startGrace
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

const (
	secretKeyDocker = "config.json"
	secretKeyCA     = "ca.crt"
)

// needsSecret reports whether a scan of this registry has anything to mount.
func needsSecret(cfg Config) bool {
	return cfg.Username != "" || (cfg.CACert != "" && !cfg.SkipTLSVerify)
}

// secretData is what a scan pod is given: the registry login and the CA to
// trust, whichever apply.
func secretData(cfg Config) map[string][]byte {
	data := map[string][]byte{}
	if cfg.Username != "" {
		data[secretKeyDocker] = dockerConfig(cfg)
	}
	if cfg.CACert != "" && !cfg.SkipTLSVerify {
		data[secretKeyCA] = []byte(cfg.CACert)
	}
	return data
}

// buildJob is the Job that scans one image. secret names the Secret holding the
// registry credentials, or is empty when there are none.
func (r *JobRunner) buildJob(name string, cfg Config, image, secret string) *batchv1.Job {
	env := []corev1.EnvVar{}
	volumes := []corev1.Volume{{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
	// The databases and the image's layers are unpacked in /tmp.
	mounts := []corev1.VolumeMount{{Name: "tmp", MountPath: "/tmp"}}
	// One Secret, mounted as a directory per use so neither sees the other's file.
	fromSecret := func(volume, key, path string) {
		volumes = append(volumes, corev1.Volume{Name: volume, VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{SecretName: secret, Items: []corev1.KeyToPath{{Key: key, Path: key}}},
		}})
		mounts = append(mounts, corev1.VolumeMount{Name: volume, MountPath: path, ReadOnly: true})
	}
	if cfg.Username != "" {
		// A Docker config file names the host the credentials are for.
		// TRIVY_USERNAME and TRIVY_PASSWORD name none, and Trivy offers them to
		// every registry it talks to, the one serving its database included.
		env = append(env, corev1.EnvVar{Name: "DOCKER_CONFIG", Value: "/docker"})
		fromSecret("docker", secretKeyDocker, "/docker")
	}
	switch {
	case cfg.SkipTLSVerify:
		env = append(env, corev1.EnvVar{Name: "TRIVY_INSECURE", Value: "true"})
	case cfg.CACert != "":
		// Trivy has no option for a CA, but it is a Go program, and Go reads
		// every certificate in SSL_CERT_DIR on top of the system's bundle file.
		// SSL_CERT_FILE would replace that bundle, and with it the roots Trivy
		// needs to download its database.
		env = append(env, corev1.EnvVar{Name: "SSL_CERT_DIR", Value: "/registry-ca"})
		fromSecret("registry-ca", secretKeyCA, "/registry-ca")
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
							"--timeout", trivyTimeout,
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
						VolumeMounts: mounts,
					}},
					Volumes: volumes,
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
	if needsSecret(cfg) {
		secret = name
	}
	job, err := jobs.Create(ctx, r.buildJob(name, cfg, image, secret), metav1.CreateOptions{})
	if err != nil {
		return nil, &InfraError{fmt.Sprintf("creating the scan Job: %v", err)}
	}
	background := metav1.DeletePropagationBackground
	defer cleanup(func(c context.Context) error {
		return jobs.Delete(c, name, metav1.DeleteOptions{PropagationPolicy: &background})
	})
	if secret != "" {
		// After the Job, so the Secret can be owned by it from the start and
		// goes with it even if Sentinel stops before the delete below. The pod
		// waits for the Secret to appear.
		_, err := secrets.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: r.Namespace, Labels: map[string]string{ScanLabel: cfg.ID},
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID}},
			},
			Data: secretData(cfg),
		}, metav1.CreateOptions{})
		if err != nil {
			return nil, &InfraError{fmt.Sprintf("creating the credentials Secret: %v", err)}
		}
		defer cleanup(func(c context.Context) error { return secrets.Delete(c, name, metav1.DeleteOptions{}) })
	}

	started := time.Now()
	finished := false
	for !finished {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, fmt.Errorf("the scan did not finish in %s", scanTimeout)
			}
			return nil, ctx.Err()
		case <-time.After(r.interval()):
		}
		j, err := jobs.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("reading the scan Job: %w", err)
		}
		finished = j.Status.Succeeded > 0 || j.Status.Failed > 0
		if !finished && time.Since(started) > r.grace() {
			if problem := r.podProblem(ctx, name); problem != "" {
				return nil, &InfraError{problem}
			}
		}
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

// podProblem says why a scan pod is not getting anywhere, when it has not
// started: an image that cannot be pulled, a pod nothing will admit or
// schedule. Empty once the container has run.
func (r *JobRunner) podProblem(ctx context.Context, job string) string {
	pod, err := r.pod(ctx, job)
	if err != nil {
		// No pod this long after the Job: its creation is being refused.
		return "the scan Job has no pod; see the Job's events in namespace " + r.Namespace
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Running != nil || cs.State.Terminated != nil {
			return ""
		}
		if w := cs.State.Waiting; w != nil && w.Reason != "" && w.Reason != "ContainerCreating" && w.Reason != "PodInitializing" {
			return fmt.Sprintf("the scan pod cannot start: %s %s", w.Reason, w.Message)
		}
	}
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionFalse {
			return "the scan pod could not be scheduled: " + c.Message
		}
	}
	return ""
}

// dockerConfig is a Docker client config file holding one registry's login.
func dockerConfig(cfg Config) []byte {
	auth := base64.StdEncoding.EncodeToString([]byte(cfg.Username + ":" + cfg.Password))
	b, _ := json.Marshal(map[string]any{"auths": map[string]any{cfg.Host(): map[string]string{"auth": auth}}})
	return b
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
	stated := -1
	lastMessage := ""
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "":
		case strings.HasPrefix(line, completeMarker+" "):
			if n, err := strconv.Atoi(strings.TrimPrefix(line, completeMarker+" ")); err == nil {
				stated = n
			}
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
	if stated < 0 {
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
	if stated != len(findings) {
		return nil, fmt.Errorf("the scan reported %d findings but only %d could be read back from the pod's log", stated, len(findings))
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
