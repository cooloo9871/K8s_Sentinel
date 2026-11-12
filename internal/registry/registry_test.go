package registry

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"library/nginx", "library/nginx", true},
		{"library/nginx", "library/nginx2", false},
		{"library/*", "library/nginx", true},
		{"library/*", "library/team/app", true},
		{"library/*", "other/nginx", false},
		{"*", "anything/at/all", true},
		{"v1.*", "v1.2.3", true},
		{"v1.*", "v10", false},
		{"*-alpine", "1.27-alpine", true},
		{"a.b", "axb", false}, // a dot is a dot, not "any character"
	}
	for _, c := range cases {
		if got := matchGlob(c.pattern, c.s); got != c.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}

func TestParseFilter(t *testing.T) {
	f, err := parseFilter("library/*")
	if err != nil || f.repo != "library/*" || f.tag != "*" {
		t.Errorf("library/* = %+v, %v", f, err)
	}
	f, err = parseFilter("team/app:v1.*")
	if err != nil || f.repo != "team/app" || f.tag != "v1.*" {
		t.Errorf("team/app:v1.* = %+v, %v", f, err)
	}
	for _, bad := range []string{"", ":tag", "repo:", "a b", "repo@sha256:abc"} {
		if _, err := parseFilter(bad); err == nil {
			t.Errorf("parseFilter(%q) accepted", bad)
		}
	}
}

func validConfig() Config {
	return Config{ID: "r1", Name: "internal", Type: TypeDocker, URL: "https://registry.internal", Filters: []string{"library/*"}, IntervalDays: 7}
}

func TestValidate(t *testing.T) {
	c := validConfig()
	c.URL = " https://registry.internal/ "
	c.Filters = []string{" library/* ", ""}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if c.URL != "https://registry.internal" || !reflect.DeepEqual(c.Filters, []string{"library/*"}) {
		t.Errorf("not normalised: %q %q", c.URL, c.Filters)
	}

	bad := map[string]func(*Config){
		"no name":            func(c *Config) { c.Name = " " },
		"unknown type":       func(c *Config) { c.Type = "ecr" },
		"url with a path":    func(c *Config) { c.URL = "https://registry.internal/v2" },
		"url without scheme": func(c *Config) { c.URL = "registry.internal" },
		"no filters":         func(c *Config) { c.Filters = []string{" "} },
		"interval too short": func(c *Config) { c.IntervalDays = 0 },
		"interval too long":  func(c *Config) { c.IntervalDays = 31 },
		"harbor, no project": func(c *Config) { c.Type = TypeHarbor; c.Filters = []string{"*"} },
		"quay, wild org":     func(c *Config) { c.Type = TypeQuay; c.Filters = []string{"prom*/node"} },
	}
	for name, mutate := range bad {
		c := validConfig()
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// A wildcard after a literal project is what Harbor and quay can list.
	c = validConfig()
	c.Type = TypeHarbor
	if err := c.Validate(); err != nil {
		t.Errorf("harbor library/* rejected: %v", err)
	}
}

// The password is never sent back, and an edit that leaves it blank keeps it.
func TestStoreKeepsThePasswordOutOfReach(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registries.json")
	s := NewStore(path)
	c := validConfig()
	c.Username, c.Password = "robot", "s3cret"
	s.Create(c)

	pub := c.Public()
	if pub.Password != "" || !pub.HasPassword {
		t.Errorf("public = %+v, want no password and hasPassword", pub)
	}
	if b, _ := json.Marshal(pub); strings.Contains(string(b), "s3cret") {
		t.Errorf("the password is in the API response: %s", b)
	}

	edit := c
	edit.Password = ""
	edit.IntervalDays = 3
	s.Update(edit)
	if got, _ := s.Get("r1"); got.Password != "s3cret" || got.IntervalDays != 3 {
		t.Errorf("after an edit with a blank password: %+v", got)
	}
	if got, _ := NewStore(path).Get("r1"); got.Password != "s3cret" {
		t.Errorf("not persisted: %+v", got)
	}

	// Removing the username removes the password with it.
	edit.Username = ""
	_ = edit.Validate()
	s.Update(edit)
	if got, _ := s.Get("r1"); got.Password != "" {
		t.Errorf("password kept after the username was removed")
	}
}

// fakeRegistry serves the Registry v2 listing API, two names to a page, behind
// a bearer-token challenge when token is set.
type fakeRegistry struct {
	repos map[string][]string // repository → tags
	token string
	user  string
	pass  string
	srv   *httptest.Server
}

func (f *fakeRegistry) page(w http.ResponseWriter, r *http.Request, field string, all []string) {
	start := 0
	if last := r.URL.Query().Get("last"); last != "" {
		for i, v := range all {
			if v == last {
				start = i + 1
			}
		}
	}
	end := min(start+2, len(all))
	if end < len(all) {
		w.Header().Set("Link", fmt.Sprintf(`<%s?last=%s&n=2>; rel="next"`, r.URL.Path, all[end-1]))
	}
	_ = json.NewEncoder(w).Encode(map[string]any{field: all[start:end]})
}

func (f *fakeRegistry) start(t *testing.T) string {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		if u != f.user || p != f.pass {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": f.token})
	})
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		if f.token != "" && r.Header.Get("Authorization") != "Bearer "+f.token {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="reg",scope="registry:catalog:*"`, f.srv.URL))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/v2/_catalog" {
			var names []string
			for name := range f.repos {
				names = append(names, name)
			}
			sortStrings(names)
			f.page(w, r, "repositories", names)
			return
		}
		repo := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v2/"), "/tags/list")
		tags, ok := f.repos[repo]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		f.page(w, r, "tags", tags)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f.srv.URL
}

func sortStrings(s []string) {
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

func hostOf(url string) string { return strings.TrimPrefix(url, "http://") }

func TestResolveListsACatalogAcrossPages(t *testing.T) {
	reg := &fakeRegistry{repos: map[string][]string{
		"library/nginx": {"1.25", "1.26", "1.27", "latest"},
		"library/redis": {"7", "7-alpine"},
		"library/zebra": {"1"},
		"team/app":      {"v1.0", "v1.1", "v2.0"},
		"team/other":    {"v1.0"},
	}}
	url := reg.start(t)
	cfg := Config{Type: TypeDocker, URL: url, Filters: []string{"library/*:1.*", "team/app:v1.*", "team/other:pinned", "team/*:v2.0"}}

	images, matched, err := Resolve(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := hostOf(url)
	want := []string{
		h + "/library/nginx:1.25", h + "/library/nginx:1.26", h + "/library/nginx:1.27",
		// team/*:v2.0 names v2.0 only where it exists: not team/other.
		h + "/team/app:v1.0", h + "/team/app:v1.1", h + "/team/app:v2.0",
		// A tag named outright is taken as given, without asking the registry.
		h + "/team/other:pinned",
	}
	if !reflect.DeepEqual(images, want) || matched != len(want) {
		t.Errorf("images = %v (matched %d)\n  want %v", images, matched, want)
	}
}

func TestResolveAnswersABearerChallenge(t *testing.T) {
	reg := &fakeRegistry{repos: map[string][]string{"a/b": {"1"}}, token: "tok", user: "robot", pass: "pw"}
	url := reg.start(t)
	cfg := Config{Type: TypeDocker, URL: url, Filters: []string{"a/*"}, Username: "robot", Password: "pw"}

	images, _, err := Resolve(context.Background(), cfg)
	if err != nil || len(images) != 1 {
		t.Fatalf("images = %v, err = %v", images, err)
	}

	cfg.Password = "wrong"
	if _, _, err := Resolve(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "refused the credentials") {
		t.Errorf("err = %v, want the token service's refusal", err)
	}
}

// A listing that half worked must not be returned as the whole registry.
func TestResolveFailsAsAWhole(t *testing.T) {
	reg := &fakeRegistry{repos: map[string][]string{"a/b": {"1"}}}
	url := reg.start(t)
	cfg := Config{Type: TypeDocker, URL: url, Filters: []string{"a/b", "missing/repo:*"}}

	images, _, err := Resolve(context.Background(), cfg)
	if err == nil || images != nil {
		t.Fatalf("images = %v, err = %v; want an error and nothing", images, err)
	}
	if !strings.Contains(err.Error(), `"missing/repo:*"`) {
		t.Errorf("err = %v, want it to name the filter", err)
	}
}

func TestResolveStopsAtTheCapAndSaysHowManyMatched(t *testing.T) {
	tags := make([]string, 0, maxImages+40)
	for i := range maxImages + 40 {
		tags = append(tags, fmt.Sprintf("t%04d", i))
	}
	// One page, so the test is not three hundred requests.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"tags": tags})
	}))
	defer srv.Close()

	images, matched, err := Resolve(context.Background(), Config{Type: TypeDocker, URL: srv.URL, Filters: []string{"big/repo:*"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(images) != maxImages || matched != maxImages+40 {
		t.Errorf("images = %d, matched = %d; want %d and %d", len(images), matched, maxImages, maxImages+40)
	}
}

func TestResolveListsAHarborProject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v2.0/projects/library/repositories":
			if u, p, _ := r.BasicAuth(); u != "admin" || p != "pw" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.URL.Query().Get("page") == "1" {
				_, _ = w.Write([]byte(`[{"name":"library/nginx"},{"name":"library/team/app"}]`))
				return
			}
			_, _ = w.Write([]byte(`[]`))
		case strings.HasSuffix(r.URL.Path, "/tags/list"):
			_, _ = w.Write([]byte(`{"tags":["1"]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	cfg := Config{Type: TypeHarbor, URL: srv.URL, Filters: []string{"library/*"}, Username: "admin", Password: "pw"}

	images, _, err := Resolve(context.Background(), cfg)
	h := hostOf(srv.URL)
	if err != nil || !reflect.DeepEqual(images, []string{h + "/library/nginx:1", h + "/library/team/app:1"}) {
		t.Errorf("images = %v, err = %v", images, err)
	}

	cfg.Password = "wrong"
	if _, _, err := Resolve(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "refused access") {
		t.Errorf("err = %v, want a refusal", err)
	}
}

func TestResolveListsAQuayOrganisation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/repository":
			if r.URL.Query().Get("namespace") != "prometheus" || r.URL.Query().Get("public") != "true" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if r.URL.Query().Get("next_page") == "" {
				_, _ = w.Write([]byte(`{"repositories":[{"namespace":"prometheus","name":"node-exporter"}],"next_page":"p2"}`))
				return
			}
			_, _ = w.Write([]byte(`{"repositories":[{"namespace":"prometheus","name":"alertmanager"}]}`))
		case strings.HasSuffix(r.URL.Path, "/tags/list"):
			_, _ = w.Write([]byte(`{"tags":["v1"]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	images, _, err := Resolve(context.Background(), Config{Type: TypeQuay, URL: srv.URL, Filters: []string{"prometheus/*"}})
	h := hostOf(srv.URL)
	if err != nil || !reflect.DeepEqual(images, []string{h + "/prometheus/alertmanager:v1", h + "/prometheus/node-exporter:v1"}) {
		t.Errorf("images = %v, err = %v", images, err)
	}
}

func TestParseOutput(t *testing.T) {
	out := `2026-11-12T02:00:00Z	WARN	something Trivy wanted to say
{"fixedVersion":"2.6.2","id":"CVE-2026-1","installedVersion":"2.6.1","link":"https://x/1","package":"apt","severity":"HIGH","title":"t"}
{"fixedVersion":"","id":"CVE-2026-2","installedVersion":"1","link":"","package":"zlib","severity":"CRITICAL","title":"t"}
` + completeMarker + " 2\n"
	findings, err := parseOutput(out)
	if err != nil || len(findings) != 2 {
		t.Fatalf("findings = %+v, err = %v", findings, err)
	}
	if findings[0].ID != "CVE-2026-1" || findings[0].FixedVersion != "2.6.2" || findings[1].Severity != "CRITICAL" {
		t.Errorf("findings = %+v", findings)
	}
	c, fixable := summarize(findings)
	if c.Critical != 1 || c.High != 1 || fixable != 1 {
		t.Errorf("counts = %+v, fixable = %d", c, fixable)
	}

	// An image with nothing found still finishes, and is told apart from...
	if findings, err := parseOutput(completeMarker + " 0"); err != nil || len(findings) != 0 {
		t.Errorf("clean image: %v, %v", findings, err)
	}
	// ...a scan that died, which gives Trivy's reason and no findings.
	_, err = parseOutput("2026-11-12T02:00:00Z\tFATAL\tFatal error\tunable to find the specified image\n")
	if err == nil || err.Error() != "unable to find the specified image" {
		t.Errorf("err = %v, want Trivy's message", err)
	}
	// Findings printed before the failure are not a result either.
	_, err = parseOutput(`{"id":"CVE-2026-1","severity":"HIGH"}` + "\nFATAL out of memory\n")
	if err == nil {
		t.Errorf("a scan cut short was accepted")
	}
	if _, err := parseOutput(""); err == nil {
		t.Errorf("an empty log was accepted")
	}
	// The kubelet rotates a long log, and only its tail is read back. The
	// marker survives that; the findings before it do not.
	_, err = parseOutput(`{"id":"CVE-2026-9","severity":"LOW"}` + "\n" + completeMarker + " 30000\n")
	if err == nil || !strings.Contains(err.Error(), "30000 findings but only 1") {
		t.Errorf("err = %v, want a truncated log refused", err)
	}
}

// The scan pod has to be admitted by a namespace enforcing the restricted Pod
// Security level, and the password must not be readable off the Job.
func TestBuildJobIsRestrictedAndCarriesNoPassword(t *testing.T) {
	r := &JobRunner{Namespace: "sentinel-system", TrivyImage: "trivy:x", DBRepository: "mirror.internal/trivy-db"}
	cfg := validConfig()
	cfg.URL = "http://registry.internal:5000"
	cfg.Username, cfg.Password, cfg.SkipTLSVerify = "robot", "s3cret", true

	job := r.buildJob("registry-scan-abc", cfg, "registry.internal:5000/a/b:1", "registry-scan-abc")

	if b, _ := json.Marshal(job); strings.Contains(string(b), "s3cret") {
		t.Fatalf("the password is in the Job spec")
	}
	pod := job.Spec.Template.Spec
	psc, c := pod.SecurityContext, pod.Containers[0]
	if psc.RunAsNonRoot == nil || !*psc.RunAsNonRoot || psc.SeccompProfile == nil || psc.SeccompProfile.Type != "RuntimeDefault" {
		t.Errorf("pod security context = %+v", psc)
	}
	csc := c.SecurityContext
	if *csc.AllowPrivilegeEscalation || !*csc.ReadOnlyRootFilesystem || len(csc.Capabilities.Drop) != 1 || csc.Capabilities.Drop[0] != "ALL" {
		t.Errorf("container security context = %+v", csc)
	}
	if *pod.AutomountServiceAccountToken {
		t.Errorf("the scan pod mounts a service account token it has no use for")
	}
	if !strings.Contains(strings.Join(c.Args, " "), "--timeout 13m") {
		t.Errorf("Trivy is left on its own 5 minute timeout: %v", c.Args)
	}
	if c.Args[len(c.Args)-1] != "registry.internal:5000/a/b:1" {
		t.Errorf("args = %v", c.Args)
	}
	env := map[string]string{}
	for _, e := range c.Env {
		env[e.Name] = e.Value
	}
	want := map[string]string{
		"DOCKER_CONFIG":       "/docker",
		"TRIVY_INSECURE":      "true",
		"TRIVY_NON_SSL":       "true",
		"TRIVY_DB_REPOSITORY": "mirror.internal/trivy-db",
	}
	if !reflect.DeepEqual(env, want) {
		t.Errorf("env = %v\n want %v", env, want)
	}
	// The login reaches the pod as a file naming its registry, never as
	// TRIVY_USERNAME/TRIVY_PASSWORD, which Trivy would also offer to the
	// registry its database comes from.
	var mounted bool
	for _, v := range pod.Volumes {
		mounted = mounted || (v.Secret != nil && v.Secret.SecretName == "registry-scan-abc")
	}
	if !mounted {
		t.Errorf("the credentials Secret is not mounted")
	}
	var dc struct {
		Auths map[string]struct{ Auth string }
	}
	_ = json.Unmarshal(dockerConfig(cfg), &dc)
	if got, _ := base64.StdEncoding.DecodeString(dc.Auths["registry.internal:5000"].Auth); string(got) != "robot:s3cret" || len(dc.Auths) != 1 {
		t.Errorf("docker config = %+v", dc)
	}
	if job.Labels[ScanLabel] != "r1" || job.Spec.Template.Labels[ScanLabel] != "r1" {
		t.Errorf("the scan label is missing")
	}

	// No credentials, https: none of that.
	plain := r.buildJob("j", validConfig(), "x/y:1", "")
	if n := len(plain.Spec.Template.Spec.Containers[0].Env); n != 1 {
		t.Errorf("env has %d entries for an anonymous https registry, want only the DB repository", n)
	}
	if n := len(plain.Spec.Template.Spec.Volumes); n != 1 {
		t.Errorf("an anonymous scan mounts %d volumes, want only /tmp", n)
	}
}

// What the fake API server can show: the Secret is created owned by the Job,
// the pod's output decides the result, and both are removed afterwards.
func TestScanCreatesAndRemovesItsJobAndSecret(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	client.PrependReactor("get", "jobs", func(a k8stesting.Action) (bool, runtime.Object, error) {
		j, err := client.Tracker().Get(batchv1.SchemeGroupVersion.WithResource("jobs"), "ns", a.(k8stesting.GetAction).GetName())
		if err != nil {
			return true, nil, err
		}
		done := j.(*batchv1.Job).DeepCopy()
		done.Status.Failed = 1
		return true, done, nil
	})
	r := &JobRunner{Client: client, Namespace: "ns", TrivyImage: "trivy:x", poll: time.Millisecond}
	cfg := validConfig()
	cfg.Username, cfg.Password = "robot", "pw"

	_, err := r.Scan(context.Background(), cfg, "x/y:1")

	// The fake has no pod for the Job, which is itself a failure to report.
	if err == nil || !strings.Contains(err.Error(), "no pod") {
		t.Errorf("err = %v, want the missing pod reported", err)
	}
	owned, order := false, []string{}
	for _, a := range client.Actions() {
		if c, ok := a.(k8stesting.CreateAction); ok {
			order = append(order, a.GetResource().Resource)
			if a.GetResource().Resource == "secrets" {
				refs := c.GetObject().(metav1.Object).GetOwnerReferences()
				owned = len(refs) == 1 && refs[0].Kind == "Job"
			}
		}
		// The Role grants create and delete on Secrets and nothing else.
		if a.GetResource().Resource == "secrets" && a.GetVerb() != "create" && a.GetVerb() != "delete" {
			t.Errorf("Secret %s is not in the Role", a.GetVerb())
		}
	}
	if !owned || !reflect.DeepEqual(order, []string{"jobs", "secrets"}) {
		t.Errorf("created %v, Secret owned by the Job: %v", order, owned)
	}
	if jobs, _ := client.BatchV1().Jobs("ns").List(context.Background(), metav1.ListOptions{}); len(jobs.Items) != 0 {
		t.Errorf("%d Jobs left behind", len(jobs.Items))
	}
	if secrets, _ := client.CoreV1().Secrets("ns").List(context.Background(), metav1.ListOptions{}); len(secrets.Items) != 0 {
		t.Errorf("%d Secrets left behind", len(secrets.Items))
	}
}

// A scan pod that cannot pull its image is given up on early, as a failure of
// the scanning itself rather than of the image.
func TestScanGivesUpOnAPodThatCannotStart(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	client.PrependReactor("create", "jobs", func(a k8stesting.Action) (bool, runtime.Object, error) {
		job := a.(k8stesting.CreateAction).GetObject().(*batchv1.Job)
		_ = client.Tracker().Add(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: job.Name + "-x", Labels: map[string]string{"job-name": job.Name}},
			Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
				State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff", Message: "pull access denied"}},
			}}},
		})
		return false, nil, nil
	})
	r := &JobRunner{Client: client, Namespace: "ns", TrivyImage: "nope:x", poll: time.Millisecond}

	_, err := r.Scan(context.Background(), validConfig(), "x/y:1")

	var ie *InfraError
	if !errors.As(err, &ie) || !strings.Contains(err.Error(), "ImagePullBackOff") {
		t.Errorf("err = %v, want an InfraError naming ImagePullBackOff", err)
	}
}

// ── Scanner ────────────────────────────────────────────────────────────────

type fakeScans struct {
	mu      sync.Mutex
	images  []string
	matched int
	listErr error
	// image → findings, or an error for the ones in fail
	found map[string][]Finding
	fail  map[string]error
	block chan struct{} // when set, scans wait on it
	calls []string
}

func (f *fakeScans) resolve(context.Context, Config) ([]string, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.matched
	if m == 0 {
		m = len(f.images)
	}
	return f.images, m, f.listErr
}

func (f *fakeScans) scan(ctx context.Context, _ Config, image string) ([]Finding, error) {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, image)
	if err := f.fail[image]; err != nil {
		return nil, err
	}
	return f.found[image], nil
}

func newTestScanner(t *testing.T, f *fakeScans) (*Scanner, *Store, string) {
	t.Helper()
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "registries.json"))
	store.Create(validConfig())
	s := NewScanner(store, filepath.Join(dir, "registry-scans"), f.scan)
	s.resolve = f.resolve
	return s, store, dir
}

func waitDone(t *testing.T, s *Scanner, id string) Report {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if r := s.Report(id); !r.Run.Running {
			// The run lets go of its slot just after it stops reporting as running.
			s.stop(id)
			return r
		}
		if time.Now().After(deadline) {
			t.Fatalf("the run never finished: %+v", s.Report(id).Run)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRunRecordsEveryImageAndNeverCallsAFailureClean(t *testing.T) {
	f := &fakeScans{
		images: []string{"h/a:1", "h/b:1", "h/c:1"},
		found: map[string][]Finding{
			"h/a:1": {{ID: "CVE-2", Severity: "LOW"}, {ID: "CVE-1", Severity: "CRITICAL", FixedVersion: "2"}},
			"h/b:1": {},
		},
		fail: map[string]error{"h/c:1": errors.New("unable to find the specified image")},
	}
	s, _, _ := newTestScanner(t, f)

	if err := s.Start("r1"); err != nil {
		t.Fatal(err)
	}
	r := waitDone(t, s, "r1")

	if r.Run.Total != 3 || r.Run.Done != 3 || r.Run.FinishedAt == "" || r.Run.Error != "" {
		t.Errorf("run = %+v", r.Run)
	}
	byImage := map[string]ImageResult{}
	for _, img := range r.Images {
		byImage[img.Image] = img
	}
	if a := byImage["h/a:1"]; !a.Scanned || a.Counts.Critical != 1 || a.Counts.Low != 1 || a.Fixable != 1 {
		t.Errorf("a = %+v", a)
	}
	if b := byImage["h/b:1"]; !b.Scanned || b.Error != "" {
		t.Errorf("b = %+v, want scanned and clean", b)
	}
	if c := byImage["h/c:1"]; c.Scanned || !strings.Contains(c.Error, "unable to find") {
		t.Errorf("c = %+v, want not scanned, with the reason", c)
	}
	// Worst first, then the unknown one ahead of the clean one.
	if got := []string{r.Images[0].Image, r.Images[1].Image, r.Images[2].Image}; !reflect.DeepEqual(got, []string{"h/a:1", "h/c:1", "h/b:1"}) {
		t.Errorf("order = %v", got)
	}

	// Kept worst first, whatever order the scanner printed them in.
	if findings, ok := s.Findings("r1", "h/a:1"); !ok || len(findings) != 2 || findings[0].ID != "CVE-1" {
		t.Errorf("findings of a = %v, %v", findings, ok)
	}
	if _, ok := s.Findings("r1", "h/c:1"); ok {
		t.Errorf("a failed scan has findings on file")
	}
}

func TestRunThatCannotListTheRegistrySaysSo(t *testing.T) {
	f := &fakeScans{listErr: errors.New(`filter "a/*": the registry refused access (HTTP 401)`)}
	s, _, _ := newTestScanner(t, f)

	_ = s.Start("r1")
	r := waitDone(t, s, "r1")

	if !strings.Contains(r.Run.Error, "refused access") || r.Run.FinishedAt == "" {
		t.Errorf("run = %+v", r.Run)
	}
}

func TestRunReportsWhenTheCapLeftImagesOut(t *testing.T) {
	f := &fakeScans{images: []string{"h/a:1"}, matched: 740}
	s, _, _ := newTestScanner(t, f)

	_ = s.Start("r1")
	r := waitDone(t, s, "r1")

	if r.Run.Total != 1 || r.Run.Matched != 740 {
		t.Errorf("run = %+v, want total 1 of 740 matched", r.Run)
	}
}

// An image the filters no longer cover leaves the list; one still covered
// stays visible while the next run is in progress.
func TestRescanDropsImagesNoLongerCovered(t *testing.T) {
	f := &fakeScans{images: []string{"h/a:1", "h/b:1"}, found: map[string][]Finding{"h/b:1": {{ID: "CVE-1", Severity: "HIGH"}}}}
	s, _, _ := newTestScanner(t, f)
	_ = s.Start("r1")
	waitDone(t, s, "r1")

	f.mu.Lock()
	f.images = []string{"h/a:1"}
	f.block = make(chan struct{})
	f.mu.Unlock()
	_ = s.Start("r1")
	if mid := s.Report("r1"); len(mid.Images) != 2 || !mid.Run.Running {
		t.Errorf("mid-run: %d images, running %v; want the last results still listed", len(mid.Images), mid.Run.Running)
	}
	if err := s.Start("r1"); !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("second start = %v, want ErrAlreadyRunning", err)
	}
	close(f.block)
	r := waitDone(t, s, "r1")

	if len(r.Images) != 1 || r.Images[0].Image != "h/a:1" {
		t.Errorf("images = %+v, want only a", r.Images)
	}
	if _, ok := s.Findings("r1", "h/b:1"); ok {
		t.Errorf("findings of a dropped image are still on file")
	}
}

func TestDue(t *testing.T) {
	f := &fakeScans{images: []string{"h/a:1"}}
	s, store, _ := newTestScanner(t, f)
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	cfg, _ := store.Get("r1") // every 7 days

	if !s.due(cfg) {
		t.Errorf("a registry never scanned is not due")
	}
	_ = s.Start("r1")
	waitDone(t, s, "r1")
	if s.due(cfg) {
		t.Errorf("due again right after a run")
	}
	now = now.Add(7*24*time.Hour - time.Minute)
	if s.due(cfg) {
		t.Errorf("due a minute early")
	}
	now = now.Add(time.Minute)
	if !s.due(cfg) {
		t.Errorf("not due after the interval")
	}
}

// Results survive a restart, and a run the restart cut short is due at once
// rather than a whole interval later.
func TestResultsSurviveARestart(t *testing.T) {
	f := &fakeScans{images: []string{"h/a:1", "h/b:1"}, found: map[string][]Finding{"h/a:1": {{ID: "CVE-1", Severity: "HIGH"}}}}
	s, store, dir := newTestScanner(t, f)
	_ = s.Start("r1")
	waitDone(t, s, "r1")

	again := NewScanner(store, filepath.Join(dir, "registry-scans"), f.scan)
	r := again.Report("r1")
	if len(r.Images) != 2 || r.Run.FinishedAt == "" {
		t.Fatalf("after a restart: %+v", r)
	}
	if findings, ok := again.Findings("r1", "h/a:1"); !ok || len(findings) != 1 {
		t.Errorf("findings after a restart = %v, %v", findings, ok)
	}
	cfg, _ := store.Get("r1")
	if again.due(cfg) {
		t.Errorf("a finished run is due again after a restart")
	}

	// Now one that was in progress when the process stopped.
	f.block = make(chan struct{})
	_ = s.Start("r1")
	interrupted := NewScanner(store, filepath.Join(dir, "registry-scans"), f.scan)
	close(f.block)
	if rr := interrupted.Report("r1"); rr.Run.Running {
		t.Errorf("a run from before the restart still shows as running")
	}
	if !interrupted.due(cfg) {
		t.Errorf("an interrupted run is not due")
	}
	waitDone(t, s, "r1")
}

func TestForgetCancelsAndRemovesEverything(t *testing.T) {
	f := &fakeScans{images: []string{"h/a:1"}, block: make(chan struct{})}
	s, _, dir := newTestScanner(t, f)
	_ = s.Start("r1")

	s.Forget("r1")

	if r := s.Report("r1"); len(r.Images) != 0 || r.Run.Running {
		t.Errorf("report after forget = %+v", r)
	}
	if _, err := os.Stat(filepath.Join(dir, "registry-scans", "r1")); !os.IsNotExist(err) {
		t.Errorf("results directory still exists: %v", err)
	}
	if err := s.Start("missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("start of an unknown registry = %v", err)
	}
}

// Three at a time, however many registries are running.
func TestScansAreLimited(t *testing.T) {
	var mu sync.Mutex
	running, peak := 0, 0
	images := make([]string, 12)
	for i := range images {
		images[i] = fmt.Sprintf("h/a:%d", i)
	}
	f := &fakeScans{images: images}
	s, _, _ := newTestScanner(t, f)
	s.scan = func(context.Context, Config, string) ([]Finding, error) {
		mu.Lock()
		running++
		peak = max(peak, running)
		mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		mu.Lock()
		running--
		mu.Unlock()
		return nil, nil
	}

	_ = s.Start("r1")
	waitDone(t, s, "r1")

	if peak > maxConcurrentScans || peak == 0 {
		t.Errorf("peak = %d, want at most %d", peak, maxConcurrentScans)
	}
}

// A run that scanned nothing is tried again within the hour, not after the
// registry's whole interval.
func TestAFailedRunIsRetriedSoon(t *testing.T) {
	f := &fakeScans{listErr: errors.New("the registry refused access")}
	s, store, _ := newTestScanner(t, f)
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	cfg, _ := store.Get("r1")
	_ = s.Start("r1")
	waitDone(t, s, "r1")

	now = now.Add(59 * time.Minute)
	if s.due(cfg) {
		t.Errorf("due before the retry delay")
	}
	now = now.Add(2 * time.Minute)
	if !s.due(cfg) {
		t.Errorf("a failed run is not due an hour later")
	}
}

// When the scan pods cannot run, every image would fail the same way. The run
// stops, says why, and does not write the images off as failed scans.
func TestRunStopsWhenScanPodsCannotRun(t *testing.T) {
	images := make([]string, 40)
	for i := range images {
		images[i] = fmt.Sprintf("h/a:%d", i)
	}
	f := &fakeScans{images: images}
	s, _, _ := newTestScanner(t, f)
	var mu sync.Mutex
	calls := 0
	s.scan = func(context.Context, Config, string) ([]Finding, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return nil, &InfraError{"the scan pod cannot start: ImagePullBackOff"}
	}

	_ = s.Start("r1")
	r := waitDone(t, s, "r1")

	if !strings.Contains(r.Run.Error, "ImagePullBackOff") || r.Run.FinishedAt == "" {
		t.Errorf("run = %+v", r.Run)
	}
	if len(r.Images) != 0 {
		t.Errorf("%d images recorded as failed scans, want none", len(r.Images))
	}
	if calls > 2*maxConcurrentScans {
		t.Errorf("%d scans were started after the first could not run", calls)
	}
}

// Found in review: a run that had just stopped reporting "running" still held
// its place, and gave it up a moment later, taking away the place of a run
// started in between. That run could then be neither stopped nor restarted.
func TestARunStartedAsAnotherEndsKeepsItsPlace(t *testing.T) {
	f := &fakeScans{images: []string{"h/a:1"}}
	s, _, _ := newTestScanner(t, f)
	for range 300 {
		_ = s.Start("r1")
		for s.Report("r1").Run.Running {
		}
		// The instant the first run reads as finished, start another and block it.
		gate := make(chan struct{})
		f.mu.Lock()
		f.block = gate
		f.mu.Unlock()
		if err := s.Start("r1"); err != nil {
			t.Fatalf("start after a finished run: %v", err)
		}
		s.mu.Lock()
		_, held := s.cancels["r1"]
		s.mu.Unlock()
		if !held {
			t.Fatalf("the running scan lost its place and can no longer be stopped")
		}
		f.mu.Lock()
		f.block = nil
		f.mu.Unlock()
		close(gate)
		waitDone(t, s, "r1")
	}
}

// quay.io answers an anonymous _catalog with 200 and nothing in it, so the
// login has to be offered rather than waited for.
func TestResolveListsPrivateQuayRepositoriesWhenLoggedIn(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authed := r.Header.Get("Authorization") == "Bearer tok"
		switch {
		case r.URL.Path == "/api/v1/repository":
			_, _ = w.Write([]byte(`{"repositories":[]}`))
		case r.URL.Path == "/token":
			// quay.io: "Unable to decode repository and actions: registry:catalog:*"
			if r.URL.Query().Has("scope") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if u, p, _ := r.BasicAuth(); u != "org+robot" || p != "pw" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"token":"tok"}`))
		case r.URL.Path == "/v2/":
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="quay"`, srv.URL))
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/v2/_catalog" && authed:
			_, _ = w.Write([]byte(`{"repositories":["org/private","other/x"]}`))
		case r.URL.Path == "/v2/_catalog":
			_, _ = w.Write([]byte(`{"repositories":[]}`))
		case strings.HasSuffix(r.URL.Path, "/tags/list"):
			_, _ = w.Write([]byte(`{"tags":["1"]}`))
		}
	}))
	defer srv.Close()
	cfg := Config{Type: TypeQuay, URL: srv.URL, Filters: []string{"org/*"}, Username: "org+robot", Password: "pw"}

	images, _, err := Resolve(context.Background(), cfg)
	if err != nil || !reflect.DeepEqual(images, []string{hostOf(srv.URL) + "/org/private:1"}) {
		t.Errorf("images = %v, err = %v", images, err)
	}

	// With the wrong password the private repositories cannot be listed, and
	// saying "no images" would hide that.
	cfg.Password = "wrong"
	if _, _, err := Resolve(context.Background(), cfg); err == nil {
		t.Errorf("a refused login was reported as an empty organisation")
	}
}

// A repository the catalog lists but that has no tags to give is skipped; the
// rest of the registry is still scanned.
func TestResolveSkipsARepositoryThatVanished(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/_catalog":
			_, _ = w.Write([]byte(`{"repositories":["a/gone","a/here"]}`))
		case "/v2/a/here/tags/list":
			_, _ = w.Write([]byte(`{"tags":["1"]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	images, _, err := Resolve(context.Background(), Config{Type: TypeDocker, URL: srv.URL, Filters: []string{"a/*"}})
	if err != nil || !reflect.DeepEqual(images, []string{hostOf(srv.URL) + "/a/here:1"}) {
		t.Errorf("images = %v, err = %v", images, err)
	}
}

func pemOf(srv *httptest.Server) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
}

// A registry signed by a private CA is verified against the CA that was pasted
// in, and is still refused without it.
func TestResolveTrustsThePastedCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tags":["1"]}`))
	}))
	defer srv.Close()
	cfg := Config{Type: TypeDocker, URL: srv.URL, Filters: []string{"a/b:*"}}

	if _, _, err := Resolve(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("err = %v, want the unknown certificate refused", err)
	}
	cfg.CACert = pemOf(srv)
	images, _, err := Resolve(context.Background(), cfg)
	if err != nil || len(images) != 1 {
		t.Errorf("with the CA: images = %v, err = %v", images, err)
	}

	// Another CA does not make this registry trusted.
	other := httptest.NewTLSServer(nil)
	other.Close()
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "another CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &otherKey.PublicKey, otherKey)
	cfg.CACert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if _, _, err := Resolve(context.Background(), cfg); err == nil {
		t.Errorf("a registry was trusted on the strength of an unrelated CA")
	}
}

func TestValidateCACert(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	c := validConfig()
	c.CACert = "\n  " + pemOf(srv) + "\n\n"
	if err := c.Validate(); err != nil {
		t.Fatalf("a PEM certificate was rejected: %v", err)
	}
	if !strings.HasPrefix(c.CACert, "-----BEGIN CERTIFICATE-----") || !strings.HasSuffix(c.CACert, "-----END CERTIFICATE-----\n") {
		t.Errorf("not trimmed: %q", c.CACert)
	}
	// It is shown again when the registry is edited: a CA is public.
	if c.Public().CACert == "" {
		t.Errorf("the CA is withheld from the edit form")
	}

	for name, bad := range map[string]string{
		"not PEM":       "MIIBhTCCASugAwIBAgIQ",
		"a private key": "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----",
		"a path":        "/etc/ssl/ca.pem",
	} {
		c := validConfig()
		c.CACert = bad
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "CA certificate") {
			t.Errorf("%s: err = %v, want it refused", name, err)
		}
	}
}

// The scan pod gets the CA as an addition to its trusted roots, and nothing it
// has no use for.
func TestBuildJobMountsTheCA(t *testing.T) {
	r := &JobRunner{Namespace: "ns", TrivyImage: "trivy:x"}
	cfg := validConfig()
	cfg.CACert = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	if !needsSecret(cfg) {
		t.Fatalf("a registry with only a CA gets no Secret to carry it")
	}

	pod := r.buildJob("j", cfg, "h/a:1", "j").Spec.Template.Spec
	env := map[string]string{}
	for _, e := range pod.Containers[0].Env {
		env[e.Name] = e.Value
	}
	// SSL_CERT_DIR adds to the system bundle. SSL_CERT_FILE would replace it,
	// and Trivy could no longer download its database.
	if !reflect.DeepEqual(env, map[string]string{"SSL_CERT_DIR": "/registry-ca"}) {
		t.Errorf("env = %v", env)
	}
	var keys []string
	for _, v := range pod.Volumes {
		if v.Secret != nil {
			keys = append(keys, v.Secret.Items[0].Key)
		}
	}
	if !reflect.DeepEqual(keys, []string{"ca.crt"}) {
		t.Errorf("mounted Secret keys = %v, want only the CA", keys)
	}
	if data := secretData(cfg); len(data) != 1 || string(data["ca.crt"]) != cfg.CACert {
		t.Errorf("secret data = %v", data)
	}

	// With a login as well, both are mounted, each in its own directory.
	cfg.Username, cfg.Password = "robot", "pw"
	if data := secretData(cfg); len(data) != 2 {
		t.Errorf("secret keys with a login and a CA = %d, want 2", len(data))
	}
	if n := len(r.buildJob("j", cfg, "h/a:1", "j").Spec.Template.Spec.Containers[0].VolumeMounts); n != 3 {
		t.Errorf("mounts = %d, want /tmp, /docker and /registry-ca", n)
	}

	// Skipping verification makes a CA pointless; it is not mounted.
	cfg.Username, cfg.SkipTLSVerify = "", true
	if needsSecret(cfg) {
		t.Errorf("a CA is carried to a scan that does not verify certificates")
	}
	for _, e := range r.buildJob("j", cfg, "h/a:1", "").Spec.Template.Spec.Containers[0].Env {
		if e.Name == "SSL_CERT_DIR" {
			t.Errorf("SSL_CERT_DIR set although verification is skipped")
		}
	}
}
