package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cooloo9871/K8s_Sentinel/internal/audit"
	"github.com/cooloo9871/K8s_Sentinel/internal/auth"
)

type contextKey string

const claimsKey contextKey = "claims"

func claimsFromCtx(r *http.Request) *auth.Claims {
	c, _ := r.Context().Value(claimsKey).(*auth.Claims)
	return c
}

// usernameFromCtx is claimsFromCtx for callers that may run without the auth
// middleware — a handler unit test, or any future public route. Empty means
// nobody is recorded, which every store treats as "leave authorship alone".
func usernameFromCtx(r *http.Request) string {
	if c := claimsFromCtx(r); c != nil {
		return c.Username
	}
	return ""
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

func loginHandler(users *auth.UserStore, secret []byte, limiter *auth.LoginLimiter, auditStore *audit.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		// The rate-limit check comes first, and a blocked attempt is NOT audited:
		// the earlier failures from this IP already recorded the attack, so writing
		// an audit entry per blocked request would only let an attacker flood the
		// (shared, capped) audit log and evict real admin-action evidence.
		if limiter.Blocked(ip) {
			http.Error(w, "too many attempts, try again shortly", http.StatusTooManyRequests)
			return
		}
		// A login body is tiny; cap it so a blocked-or-not client cannot make us
		// read a huge payload into memory.
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
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
			limiter.Fail(ip)
			recordLogin(auditStore, body.Username, ip, http.StatusUnauthorized)
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		limiter.Reset(ip)
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
		recordLogin(auditStore, u.Username, ip, http.StatusOK)
		writeJSON(w, http.StatusOK, map[string]any{
			"username":           u.Username,
			"role":               u.Role,
			"mustChangePassword": u.MustChangePassword,
		})
	}
}

// recordLogin logs a sign-in attempt: the account it was for, the source IP as
// the target, and the outcome as the status (200 ok, 401 wrong credentials, 429
// rate-limited). Failed attempts are the point — the log answers "who tried to
// sign in as whom, from where". The password is never recorded.
func recordLogin(store *audit.Store, username, ip string, status int) {
	if store == nil {
		return
	}
	store.Record(audit.Entry{
		User:   username,
		Action: "Sign in",
		Target: ip,
		Method: http.MethodPost,
		Path:   "/api/auth/login",
		Status: status,
	})
}

// clientIP is the source the login limiter keys on. By default it is the
// connection's remote address, which a client cannot forge. X-Forwarded-For is
// honoured only when TRUST_PROXY_HEADERS is set, because a client talking
// directly to Sentinel controls that header completely — trusting it
// unconditionally would let an attacker send a fresh fake IP per request and
// never hit the rate limit at all. Enable it only behind a proxy that
// overwrites the header.
func clientIP(r *http.Request) string {
	if trustProxyHeaders() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i >= 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
	}
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return host
}

func trustProxyHeaders() bool {
	return os.Getenv("TRUST_PROXY_HEADERS") == "true"
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

func logoutHandler(users *auth.UserStore, secret []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The cookie is parsed here rather than read from the request context,
		// because this route is deliberately public — so that logging out works
		// with an expired token — which means the auth middleware never ran and
		// there are no claims to read. Taking them from the context silently found
		// nothing every time, so nothing was ever revoked and a token kept working
		// for the rest of its TTL after its owner logged out.
		if c, err := r.Cookie("sentinel_token"); err == nil {
			if claims, err := auth.ParseToken(secret, c.Value); err == nil &&
				claims.ID != "" && claims.ExpiresAt != nil {
				users.RevokeToken(claims.ID, claims.ExpiresAt.Time)
			}
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

func meHandler(users *auth.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := claimsFromCtx(r)
		writeJSON(w, http.StatusOK, map[string]any{
			"username":           claims.Username,
			"role":               claims.Role,
			"mustChangePassword": users.RequiresPasswordChange(claims.Username),
		})
	}
}

// mustChangeGate blocks a user who must change their password from doing
// anything but reading /me and changing their own password. It closes the
// window in which admin/admin could be used for real work before it is changed.
func mustChangeGate(users *auth.UserStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := claimsFromCtx(r)
			if claims == nil || !users.RequiresPasswordChange(claims.Username) {
				next.ServeHTTP(w, r)
				return
			}
			// Allowed while the change is pending: read who you are, and change
			// your own password. Path-matched rather than route-pattern-matched
			// so it does not depend on middleware ordering.
			if r.Method == http.MethodGet && r.URL.Path == "/api/auth/me" {
				next.ServeHTTP(w, r)
				return
			}
			if r.Method == http.MethodPut &&
				r.URL.Path == "/api/users/"+claims.Username+"/password" {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, "password change required before continuing", http.StatusForbidden)
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
			CurrentPassword string `json:"currentPassword"`
			Password        string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Password == "" {
			http.Error(w, "password required", http.StatusBadRequest)
			return
		}
		// Changing your own password requires proving you know the current one,
		// so a hijacked session cannot silently lock the owner out. An admin
		// resetting someone else's password is a separate, audit-logged action
		// that does not need the old one.
		if claims.Username == username {
			if _, ok := users.Authenticate(username, body.CurrentPassword); !ok {
				http.Error(w, "current password is incorrect", http.StatusForbidden)
				return
			}
		}
		if err := users.ChangePassword(username, body.Password); err != nil {
			status := http.StatusBadRequest
			if err.Error() == "user not found" {
				status = http.StatusNotFound
			}
			http.Error(w, err.Error(), status)
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
