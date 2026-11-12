package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cooloo9871/K8s_Sentinel/internal/registry"
)

// registryFixture is a registry store and scanner over a fake registry that
// lists one repository, with scans that find one HIGH in everything.
func registryFixture(t *testing.T) (*registry.Store, *registry.Scanner, string) {
	t.Helper()
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); r.URL.Path == "/v2/private/app/tags/list" && (!ok || u != "robot" || p != "pw") {
			w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"tags":["1","2"]}`))
	}))
	t.Cleanup(fake.Close)
	dir := t.TempDir()
	store := registry.NewStore(filepath.Join(dir, "registries.json"))
	scans := registry.NewScanner(store, filepath.Join(dir, "scans"), func(context.Context, registry.Config, string) ([]registry.Finding, error) {
		return []registry.Finding{{ID: "CVE-1", Severity: "HIGH"}}, nil
	})
	return store, scans, fake.URL
}

func call(h http.HandlerFunc, method, path string, body any, params map[string]string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	rc := chi.NewRouteContext()
	for k, v := range params {
		rc.URLParams.Add(k, v)
	}
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rc))
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

func TestRegistryLifecycle(t *testing.T) {
	store, scans, url := registryFixture(t)
	body := map[string]any{
		"name": "internal", "type": "docker", "url": url, "filters": []string{"private/app:*"},
		"intervalDays": 7, "username": "robot", "password": "pw",
	}

	w := call(createRegistry(store, scans), http.MethodPost, "/api/registries", body, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), `"pw"`) || !strings.Contains(w.Body.String(), `"hasPassword":true`) {
		t.Errorf("create response leaks or loses the password: %s", w.Body)
	}
	var created struct{ ID string }
	_ = json.Unmarshal(w.Body.Bytes(), &created)

	// Creating a registry starts its first scan.
	var images struct {
		Registry struct {
			Run    registry.Run
			Images int
			Counts registry.Counts
		}
		Images []registry.ImageResult
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		w = call(registryImages(store, scans), http.MethodGet, "/", nil, map[string]string{"id": created.ID})
		_ = json.Unmarshal(w.Body.Bytes(), &images)
		if images.Registry.Run.FinishedAt != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the first scan never finished: %s", w.Body)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(images.Images) != 2 || images.Registry.Counts.High != 2 || images.Registry.Run.Error != "" {
		t.Errorf("images = %s", w.Body)
	}

	w = call(listRegistries(store, scans), http.MethodGet, "/api/registries", nil, nil)
	if strings.Contains(w.Body.String(), `"pw"`) {
		t.Errorf("list leaks the password: %s", w.Body)
	}

	req := httptest.NewRequest(http.MethodGet, "/x?image="+images.Images[0].Image, nil)
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", created.ID)
	rec := httptest.NewRecorder()
	registryFindings(scans)(rec, req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rc)))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "CVE-1") {
		t.Errorf("findings = %d %s", rec.Code, rec.Body)
	}

	// The edit form does not hold the password; testing and saving both work
	// without it being typed again.
	body["password"] = ""
	body["id"] = created.ID
	if w = call(testRegistry(store), http.MethodPost, "/", body, nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"matched":2`) {
		t.Errorf("test with the saved password = %d %s", w.Code, w.Body)
	}
	if w = call(updateRegistry(store, scans), http.MethodPut, "/", body, map[string]string{"id": created.ID}); w.Code != http.StatusOK {
		t.Errorf("update = %d %s", w.Code, w.Body)
	}
	if c, _ := store.Get(created.ID); c.Password != "pw" {
		t.Errorf("the saved password was lost by an edit")
	}

	// Pointing the registry somewhere else must not carry the saved password
	// there: neither a test nor a save may send it to the new host.
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the new host was contacted: %s (authorization %q)", r.URL.Path, r.Header.Get("Authorization"))
	}))
	defer elsewhere.Close()
	body["url"] = elsewhere.URL
	if w = call(testRegistry(store), http.MethodPost, "/", body, nil); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "enter the password again") {
		t.Errorf("test against a new URL with the saved password = %d %s", w.Code, w.Body)
	}
	if w = call(updateRegistry(store, scans), http.MethodPut, "/", body, map[string]string{"id": created.ID}); w.Code != http.StatusBadRequest {
		t.Errorf("update to a new URL with the saved password = %d %s", w.Code, w.Body)
	}
	if c, _ := store.Get(created.ID); c.URL != url {
		t.Errorf("the refused update was saved")
	}

	if w = call(deleteRegistry(store, scans), http.MethodDelete, "/", nil, map[string]string{"id": created.ID}); w.Code != http.StatusNoContent {
		t.Errorf("delete = %d", w.Code)
	}
	if w = call(registryImages(store, scans), http.MethodGet, "/", nil, map[string]string{"id": created.ID}); w.Code != http.StatusNotFound {
		t.Errorf("images of a deleted registry = %d", w.Code)
	}
}

func TestRegistryRejectsWhatItCannotUse(t *testing.T) {
	store, scans, url := registryFixture(t)

	w := call(createRegistry(store, scans), http.MethodPost, "/", map[string]any{
		"name": "x", "type": "docker", "url": url, "filters": []string{"a/*"}, "intervalDays": 45,
	}, nil)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "1 to 30 days") {
		t.Errorf("interval of 45 days = %d %s", w.Code, w.Body)
	}
	if len(store.List()) != 0 {
		t.Errorf("an invalid registry was saved")
	}

	// Wrong credentials are the registry's answer, passed on, not a 500.
	w = call(testRegistry(store), http.MethodPost, "/", map[string]any{
		"type": "docker", "url": url, "filters": []string{"private/app:*"}, "username": "robot", "password": "wrong",
	}, nil)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "refused access") {
		t.Errorf("test with bad credentials = %d %s", w.Code, w.Body)
	}

	if w = call(scanRegistry(scans), http.MethodPost, "/", nil, map[string]string{"id": "nope"}); w.Code != http.StatusNotFound {
		t.Errorf("scan of an unknown registry = %d", w.Code)
	}
}
