package handler

import (
	"net/http"

	"github.com/cooloo9871/K8s_Sentinel/internal/auth"
)

// perm is one thing a route can ask of the account's role.
type perm struct {
	area  auth.Area
	level auth.Level
}

// can reports whether the signed-in account's role reaches the level on the
// area. Where the account may do it (its namespaces) is scope's to say.
func can(r *http.Request, area auth.Area, level auth.Level) bool {
	c := claimsFromCtx(r)
	return c != nil && c.Perms.Can(area, level)
}

// need lets a request through when the account's role reaches the level on the
// area. Every route behind the session declares one, for reads as for writes:
// a page hidden in the interface is not what keeps its data from an account.
func need(area auth.Area, level auth.Level) func(http.Handler) http.Handler {
	return needAny(perm{area, level})
}

// needAny lets a request through on any one of the permissions.
func needAny(perms ...perm) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, p := range perms {
				if can(r, p.area, p.level) {
					next.ServeHTTP(w, r)
					return
				}
			}
			writeError(w, http.StatusForbidden, "this account's role does not allow this")
		})
	}
}
