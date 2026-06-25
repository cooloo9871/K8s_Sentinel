package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cooloo9871/sentinel/internal/auth"
)

type contextKey string

const claimsKey contextKey = "claims"

func claimsFromCtx(r *http.Request) *auth.Claims {
	c, _ := r.Context().Value(claimsKey).(*auth.Claims)
	return c
}

func authMiddleware(secret []byte, users *auth.UserStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("sentinel_token")
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			claims, err := auth.ParseToken(secret, cookie.Value)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if users.IsTokenRevoked(claims.ID) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if claimsFromCtx(r).Role != auth.RoleAdmin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func loginHandler(users *auth.UserStore, secret []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		u, ok := users.Authenticate(body.Username, body.Password)
		if !ok {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		ttl := time.Duration(users.GetSessionTTL()) * time.Second
		token, err := auth.SignToken(secret, u, ttl)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "sentinel_token",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   isSecureRequest(r),
			SameSite: http.SameSiteStrictMode,
			MaxAge:   users.GetSessionTTL(),
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"username": u.Username,
			"role":     u.Role,
		})
	}
}

func getSessionTTLHandler(users *auth.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"sessionTTL": users.GetSessionTTL()})
	}
}

func setSessionTTLHandler(users *auth.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			SessionTTL int `json:"sessionTTL"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.SessionTTL <= 0 {
			http.Error(w, "sessionTTL must be a positive integer (seconds)", http.StatusBadRequest)
			return
		}
		users.SetSessionTTL(body.SessionTTL)
		w.WriteHeader(http.StatusNoContent)
	}
}

func logoutHandler(users *auth.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Revoke the current token so it cannot be reused after logout
		if claims := claimsFromCtx(r); claims != nil && claims.ID != "" && claims.ExpiresAt != nil {
			users.RevokeToken(claims.ID, claims.ExpiresAt.Time)
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "sentinel_token",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   isSecureRequest(r),
			SameSite: http.SameSiteStrictMode,
			MaxAge:   -1,
		})
		w.WriteHeader(http.StatusNoContent)
	}
}

func meHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := claimsFromCtx(r)
		writeJSON(w, http.StatusOK, map[string]any{
			"username": claims.Username,
			"role":     claims.Role,
		})
	}
}

func listUsersHandler(users *auth.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		all := users.List()
		type userResp struct {
			Username  string    `json:"username"`
			Role      auth.Role `json:"role"`
			CreatedAt string    `json:"createdAt"`
		}
		resp := make([]userResp, 0, len(all))
		for _, u := range all {
			resp = append(resp, userResp{Username: u.Username, Role: u.Role, CreatedAt: u.CreatedAt})
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func createUserHandler(users *auth.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Username string    `json:"username"`
			Password string    `json:"password"`
			Role     auth.Role `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if body.Username == "" || body.Password == "" {
			http.Error(w, "username and password required", http.StatusBadRequest)
			return
		}
		if body.Role != auth.RoleAdmin && body.Role != auth.RoleViewer {
			body.Role = auth.RoleViewer
		}
		if err := users.Create(body.Username, body.Password, body.Role); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}
}

func deleteUserHandler(users *auth.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := chi.URLParam(r, "username")
		if claimsFromCtx(r).Username == username {
			http.Error(w, "cannot delete yourself", http.StatusBadRequest)
			return
		}
		if !users.Delete(username) {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func changePasswordHandler(users *auth.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := claimsFromCtx(r)
		username := chi.URLParam(r, "username")
		if claims.Role != auth.RoleAdmin && claims.Username != username {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var body struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Password == "" {
			http.Error(w, "password required", http.StatusBadRequest)
			return
		}
		if err := users.ChangePassword(username, body.Password); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// isSecureRequest returns true when the request arrived over HTTPS —
// either directly (r.TLS != nil) or via a TLS-terminating proxy
// (X-Forwarded-Proto: https). Cookie Secure flag is only set for HTTPS
// so that HTTP access (e.g. kubectl port-forward) continues to work.
func isSecureRequest(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}
