package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/cooloo9871/K8s_Sentinel/internal/auth"
)

type roleResp struct {
	Name        auth.Role        `json:"name"`
	Permissions auth.Permissions `json:"permissions"`
	BuiltIn     bool             `json:"builtIn"`
	// How many accounts have the role. One that has any cannot be deleted.
	Users int `json:"users"`
}

func listRolesHandler(roles *auth.RoleStore, users *auth.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		count := map[auth.Role]int{}
		for _, u := range users.List() {
			count[u.Role]++
		}
		all := roles.List()
		resp := make([]roleResp, 0, len(all))
		for _, d := range all {
			resp = append(resp, roleResp{Name: d.Name, Permissions: d.Permissions, BuiltIn: d.BuiltIn, Users: count[d.Name]})
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// roleError answers a role store's refusal with the status it deserves.
func roleError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, auth.ErrRoleName), errors.Is(err, auth.ErrRolePermissions):
		status = http.StatusBadRequest
	case errors.Is(err, auth.ErrRoleExists), errors.Is(err, auth.ErrRoleBuiltIn):
		status = http.StatusConflict
	case errors.Is(err, auth.ErrRoleNotFound):
		status = http.StatusNotFound
	}
	msg := err.Error()
	writeError(w, status, string(msg[0]-32)+msg[1:]+".")
}

func createRoleHandler(roles *auth.RoleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name        auth.Role        `json:"name"`
			Permissions auth.Permissions `json:"permissions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "bad request")
			return
		}
		if err := roles.Create(auth.RoleDef{Name: body.Name, Permissions: body.Permissions}); err != nil {
			roleError(w, err)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}
}

// updateRoleHandler changes what a role grants. Every account that has it gets
// the new levels on its next request; nobody is signed out.
func updateRoleHandler(roles *auth.RoleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Permissions auth.Permissions `json:"permissions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "bad request")
			return
		}
		if err := roles.Update(auth.Role(chi.URLParam(r, "name")), body.Permissions); err != nil {
			roleError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func deleteRoleHandler(roles *auth.RoleStore, users *auth.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := auth.Role(chi.URLParam(r, "name"))
		// An account left on a role that is gone could do nothing at all.
		n := 0
		for _, u := range users.List() {
			if u.Role == name {
				n++
			}
		}
		if n > 0 {
			noun := "accounts have"
			if n == 1 {
				noun = "account has"
			}
			writeError(w, http.StatusConflict, fmt.Sprintf("%d %s this role. Give them another role first.", n, noun))
			return
		}
		if err := roles.Delete(name); err != nil {
			roleError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
