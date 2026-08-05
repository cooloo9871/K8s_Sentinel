package handler

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"sigs.k8s.io/yaml"
)

// checkManifestName rejects a PUT whose manifest names a different object than
// the URL does.
//
// Both apply handlers took the name from the manifest alone, so renaming a policy
// in the editor created a second one and left the original untouched — while the
// UI reported that the edit had been saved. Returns false when it has already
// written the response.
func checkManifestName(w http.ResponseWriter, r *http.Request, rawYAML string) bool {
	want := chi.URLParam(r, "name")
	if want == "" {
		return true // a create, which has no name to agree with
	}
	var manifest struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}
	if err := yaml.Unmarshal([]byte(rawYAML), &manifest); err != nil {
		return true // let the store report why the YAML is unusable
	}
	if got := manifest.Metadata.Name; got != "" && got != want {
		writeError(w, http.StatusBadRequest, fmt.Sprintf(
			"manifest is named %q but this edits %q — renaming would leave the original in place; create a new policy instead", got, want))
		return false
	}
	return true
}
