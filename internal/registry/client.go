package registry

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// A run stops here. Each image is a Job that downloads the vulnerability
// database, so an accidental "*" on a large registry must not become thousands.
const maxImages = 500

// MaxImages is the cap, for the API to state alongside a count that exceeds it.
const MaxImages = maxImages

const pageSize = 100

// client lists what a registry holds. It speaks the Registry v2 API, which
// Harbor, Docker Registry and quay.io all serve for tags, and each one's own
// API for listing repositories where v2 has no usable answer.
type client struct {
	cfg  Config
	http *http.Client
	// Bearer tokens by scope, so each page of a listing does not fetch its own.
	tokens map[string]string
}

func newClient(cfg Config) *client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.SkipTLSVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &client{cfg: cfg, http: &http.Client{Timeout: 30 * time.Second, Transport: tr}, tokens: map[string]string{}}
}

func (c *client) do(ctx context.Context, rawURL, authorization string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	return c.http.Do(req)
}

var challengeParam = regexp.MustCompile(`(\w+)="([^"]*)"`)

// getV2 fetches a Registry v2 URL, answering the 401 challenge the way a
// container runtime does: basic credentials, or a bearer token fetched from the
// realm the registry names.
func (c *client) getV2(ctx context.Context, rawURL string) (*http.Response, error) {
	resp, err := c.do(ctx, rawURL, "")
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	resp.Body.Close()

	scheme, rest, _ := strings.Cut(challenge, " ")
	switch strings.ToLower(scheme) {
	case "basic":
		if c.cfg.Username == "" {
			return nil, fmt.Errorf("the registry requires a username and password")
		}
		return c.doBasic(ctx, rawURL)
	case "bearer":
		params := map[string]string{}
		for _, m := range challengeParam.FindAllStringSubmatch(rest, -1) {
			params[m[1]] = m[2]
		}
		token, err := c.token(ctx, params["realm"], params["service"], params["scope"])
		if err != nil {
			return nil, err
		}
		return c.do(ctx, rawURL, "Bearer "+token)
	}
	return nil, fmt.Errorf("the registry answered 401 with an unsupported challenge %q", challenge)
}

func (c *client) doBasic(ctx context.Context, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.cfg.Username != "" {
		req.SetBasicAuth(c.cfg.Username, c.cfg.Password)
	}
	return c.http.Do(req)
}

func (c *client) token(ctx context.Context, realm, service, scope string) (string, error) {
	if t, ok := c.tokens[scope]; ok {
		return t, nil
	}
	u, err := url.Parse(realm)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("the registry named an unusable token service %q", realm)
	}
	q := u.Query()
	if service != "" {
		q.Set("service", service)
	}
	if scope != "" {
		q.Set("scope", scope)
	}
	u.RawQuery = q.Encode()
	resp, err := c.doBasic(ctx, u.String())
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the registry's token service refused the credentials (HTTP %d)", resp.StatusCode)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", fmt.Errorf("the registry's token service gave an unreadable answer: %w", err)
	}
	t := body.Token
	if t == "" {
		t = body.AccessToken
	}
	if t == "" {
		return "", fmt.Errorf("the registry's token service returned no token")
	}
	c.tokens[scope] = t
	return t, nil
}

func decode(resp *http.Response, what string, v any) error {
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%s: the registry refused access (HTTP %d); check the credentials and what they may read", what, resp.StatusCode)
	case http.StatusNotFound:
		return fmt.Errorf("%s: not found on the registry", what)
	default:
		return fmt.Errorf("%s: the registry answered HTTP %d", what, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(v); err != nil {
		return fmt.Errorf("%s: unreadable answer: %w", what, err)
	}
	return nil
}

var linkNext = regexp.MustCompile(`<([^>]+)>\s*;\s*rel="?next"?`)

// v2List reads every page of a Registry v2 listing. field is the JSON key that
// holds the names: "repositories" or "tags".
func (c *client) v2List(ctx context.Context, path, field, what string) ([]string, error) {
	var out []string
	next := c.cfg.URL + path + "?n=" + fmt.Sprint(pageSize)
	for next != "" {
		resp, err := c.getV2(ctx, next)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", what, err)
		}
		link := resp.Header.Get("Link")
		var page map[string]json.RawMessage
		if err := decode(resp, what, &page); err != nil {
			return nil, err
		}
		var names []string
		if raw, ok := page[field]; ok {
			_ = json.Unmarshal(raw, &names) // null when a repository has no tags
		}
		out = append(out, names...)

		next = ""
		if m := linkNext.FindStringSubmatch(link); m != nil {
			base, _ := url.Parse(c.cfg.URL)
			if ref, err := url.Parse(m[1]); err == nil {
				next = base.ResolveReference(ref).String()
			}
		}
	}
	return out, nil
}

func (c *client) tags(ctx context.Context, repo string) ([]string, error) {
	return c.v2List(ctx, "/v2/"+repo+"/tags/list", "tags", "tags of "+repo)
}

// harborRepositories lists a project through Harbor's own API. /v2/_catalog on
// Harbor answers only to a system administrator.
func (c *client) harborRepositories(ctx context.Context, project string) ([]string, error) {
	what := "repositories of project " + project
	var out []string
	for page := 1; ; page++ {
		u := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories?page=%d&page_size=%d", c.cfg.URL, url.PathEscape(project), page, pageSize)
		resp, err := c.doBasic(ctx, u)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", what, err)
		}
		var items []struct {
			Name string `json:"name"`
		}
		if err := decode(resp, what, &items); err != nil {
			return nil, err
		}
		for _, it := range items {
			out = append(out, it.Name)
		}
		if len(items) < pageSize {
			return out, nil
		}
	}
}

// quayRepositories lists an organisation's public repositories through quay's
// API, which needs no login. Private ones are added from /v2/_catalog when
// credentials are set; a robot account can use that but not the API.
func (c *client) quayRepositories(ctx context.Context, org string) ([]string, error) {
	what := "repositories of " + org
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	for token := ""; ; {
		q := url.Values{"namespace": {org}, "public": {"true"}}
		if token != "" {
			q.Set("next_page", token)
		}
		resp, err := c.do(ctx, c.cfg.URL+"/api/v1/repository?"+q.Encode(), "")
		if err != nil {
			return nil, fmt.Errorf("%s: %w", what, err)
		}
		var page struct {
			Repositories []struct {
				Namespace string `json:"namespace"`
				Name      string `json:"name"`
			} `json:"repositories"`
			NextPage string `json:"next_page"`
		}
		if err := decode(resp, what, &page); err != nil {
			return nil, err
		}
		for _, r := range page.Repositories {
			add(r.Namespace + "/" + r.Name)
		}
		if token = page.NextPage; token == "" {
			break
		}
	}
	if c.cfg.Username != "" {
		// Best-effort: the public listing above already answered.
		if private, err := c.v2List(ctx, "/v2/_catalog", "repositories", what); err == nil {
			for _, name := range private {
				if strings.HasPrefix(name, org+"/") {
					add(name)
				}
			}
		}
	}
	return out, nil
}

// repositories returns the repositories a pattern covers.
func (c *client) repositories(ctx context.Context, pattern string) ([]string, error) {
	if !strings.Contains(pattern, "*") {
		return []string{pattern}, nil
	}
	var all []string
	var err error
	project, _, _ := strings.Cut(pattern, "/")
	switch c.cfg.Type {
	case TypeHarbor:
		all, err = c.harborRepositories(ctx, project)
	case TypeQuay:
		all, err = c.quayRepositories(ctx, project)
	default:
		all, err = c.v2List(ctx, "/v2/_catalog", "repositories", "repository list")
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range all {
		if matchGlob(pattern, r) {
			out = append(out, r)
		}
	}
	return out, nil
}

// Resolve turns a registry's filters into image references, sorted. matched is
// how many the filters cover; the list stops at maxImages. Any failure fails
// the whole thing: a partial list would read as "that is all there is".
func Resolve(ctx context.Context, cfg Config) (images []string, matched int, err error) {
	c := newClient(cfg)
	seen := map[string]bool{}
	for _, raw := range cfg.Filters {
		f, err := parseFilter(raw)
		if err != nil {
			return nil, 0, err
		}
		repos, err := c.repositories(ctx, f.repo)
		if err != nil {
			return nil, 0, fmt.Errorf("filter %q: %w", raw, err)
		}
		for _, repo := range repos {
			// Only a repository and tag both named outright are taken as given.
			// With a wildcard on either side the tag is checked against what
			// the repository holds, or library/*:v2 would name v2 of every
			// repository whether it exists or not.
			tags := []string{f.tag}
			if strings.Contains(f.tag, "*") || strings.Contains(f.repo, "*") {
				if tags, err = c.tags(ctx, repo); err != nil {
					return nil, 0, fmt.Errorf("filter %q: %w", raw, err)
				}
			}
			for _, tag := range tags {
				if matchGlob(f.tag, tag) {
					seen[cfg.Host()+"/"+repo+":"+tag] = true
				}
			}
		}
	}
	for ref := range seen {
		images = append(images, ref)
	}
	sort.Strings(images)
	matched = len(images)
	if len(images) > maxImages {
		images = images[:maxImages]
	}
	return images, matched, nil
}
