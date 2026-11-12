package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cooloo9871/K8s_Sentinel/internal/registry"
)

// registryView is a registry with the state of its scans, for the list.
type registryView struct {
	registry.PublicConfig
	Run registry.Run `json:"run"`
	// Totals over the images scanned so far.
	Images   int             `json:"images"`
	Failed   int             `json:"failed"`
	Counts   registry.Counts `json:"counts"`
	MaxScans int             `json:"maxImages"`
}

func viewRegistry(c registry.Config, scans *registry.Scanner) registryView {
	rep := scans.Report(c.ID)
	v := registryView{PublicConfig: c.Public(), Run: rep.Run, Images: len(rep.Images), MaxScans: registry.MaxImages}
	for _, img := range rep.Images {
		if !img.Scanned {
			v.Failed++
			continue
		}
		v.Counts.Critical += img.Counts.Critical
		v.Counts.High += img.Counts.High
		v.Counts.Medium += img.Counts.Medium
		v.Counts.Low += img.Counts.Low
		v.Counts.Unknown += img.Counts.Unknown
	}
	return v
}

func listRegistries(store *registry.Store, scans *registry.Scanner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := []registryView{}
		for _, c := range store.List() {
			out = append(out, viewRegistry(c, scans))
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func decodeRegistry(w http.ResponseWriter, r *http.Request) (registry.Config, bool) {
	var c registry.Config
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return c, false
	}
	return c, true
}

func createRegistry(store *registry.Store, scans *registry.Scanner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := decodeRegistry(w, r)
		if !ok {
			return
		}
		c.ID = fmt.Sprintf("registry-%d", time.Now().UnixMilli())
		if err := c.Validate(); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		store.Create(c)
		_ = scans.Start(c.ID)
		writeJSON(w, http.StatusCreated, viewRegistry(c, scans))
	}
}

func updateRegistry(store *registry.Store, scans *registry.Scanner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := decodeRegistry(w, r)
		if !ok {
			return
		}
		c.ID = chi.URLParam(r, "id")
		if err := c.Validate(); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !keepPassword(store, &c, w) {
			return
		}
		if !store.Update(c) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		// What is being scanned, or how, may have changed: start over.
		scans.Restart(c.ID)
		saved, _ := store.Get(c.ID)
		writeJSON(w, http.StatusOK, viewRegistry(saved, scans))
	}
}

// keepPassword fills in the saved password for an edit that left the field
// empty, as the form does when the password is not being changed. Only for the
// registry it was saved for: with a different URL the saved password would be
// sent to a host its owner never gave it to, so it has to be typed again.
// Called after Validate, which normalises the URL.
func keepPassword(store *registry.Store, c *registry.Config, w http.ResponseWriter) bool {
	saved, found := store.Get(c.ID)
	if !found || c.Password != "" || c.Username == "" || saved.Password == "" {
		return true
	}
	if saved.URL != c.URL {
		writeError(w, http.StatusBadRequest, "the URL has changed, so enter the password again")
		return false
	}
	c.Password = saved.Password
	return true
}

func deleteRegistry(store *registry.Store, scans *registry.Scanner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		if !store.Delete(id) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		scans.Forget(id)
		w.WriteHeader(http.StatusNoContent)
	}
}

func scanRegistry(scans *registry.Scanner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch err := scans.Start(chi.URLParam(r, "id")); {
		case errors.Is(err, registry.ErrNotFound):
			writeError(w, http.StatusNotFound, "not found")
		case errors.Is(err, registry.ErrAlreadyRunning):
			writeError(w, http.StatusConflict, err.Error())
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}
}

// testRegistry resolves a registry's filters without scanning anything, so the
// form can say how many images a set of filters covers before it is saved.
func testRegistry(store *registry.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := decodeRegistry(w, r)
		if !ok {
			return
		}
		if c.Name == "" {
			c.Name = "test"
		}
		if c.IntervalDays == 0 {
			c.IntervalDays = 1
		}
		if err := c.Validate(); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !keepPassword(store, &c, w) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		images, matched, err := registry.Resolve(ctx, c)
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		sample := images
		if len(sample) > 10 {
			sample = sample[:10]
		}
		if sample == nil {
			sample = []string{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"matched": matched, "maxImages": registry.MaxImages, "sample": sample})
	}
}

func registryImages(store *registry.Store, scans *registry.Scanner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := store.Get(chi.URLParam(r, "id"))
		if !ok {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		rep := scans.Report(c.ID)
		writeJSON(w, http.StatusOK, map[string]any{
			"registry": viewRegistry(c, scans),
			"images":   rep.Images,
		})
	}
}

func registryFindings(scans *registry.Scanner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		findings, ok := scans.Findings(chi.URLParam(r, "id"), r.URL.Query().Get("image"))
		if !ok {
			writeError(w, http.StatusNotFound, "no findings on file for this image")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"findings": findings})
	}
}
