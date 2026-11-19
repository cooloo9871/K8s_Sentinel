# Custom roles implementation plan

**Goal:** Roles that grant each area of the product at `none`, `view` or `manage`, enforced on the server for reads and writes.

**Architecture:** `internal/auth` gains the permission model and a `RoleStore` beside `UserStore`. The auth middleware resolves the account's role to permissions on every request; each route group in `internal/handler/handler.go` declares the area and level it needs. The frontend reads the resolved permissions from `/api/auth/me` and asks `can(area, level)` in place of `isAdmin`.

**Tech stack:** Go 1.26 (chi), React + TypeScript (vitest).

**Spec:** `docs/superpowers/specs/2026-11-19-custom-roles-design.md`

## Global constraints

- Role names `admin` and `viewer` keep their stored spelling; no data migration.
- Every route that is `clusterWide` today stays so.
- UI copy: no em dash, edit pages titled `Edit <name>`, no example placeholders, no secondary text the layout already says.
- Go tooling runs in the `golang:1.26-alpine` container; frontend checks are `npx tsc --noEmit` and `npx vitest run`.

## Review focus

- A route added later with no permission declared: the route table test must fail.
- A stored account whose role name no longer exists: no permissions, can still sign in and change its password.
- The last unlimited `admin` account being deleted, re-roled or limited by an account holding a custom `system: manage` role.
- An account without `events: view` must not open event streams (no 403 loop in the browser).
- A role edited while accounts are signed in: the next request uses the new levels.

---

### Task 1: Permission model and role store

**Files:** create `internal/auth/roles.go`, `internal/auth/roles_test.go`; modify `internal/auth/store.go` (add `SetRole`), `internal/auth/jwt.go` (`Claims.Perms`).

**Produces:**

- `type Area string`, `type Level string`; `Areas []Area` in display order; levels `LevelNone`, `LevelView`, `LevelManage`.
- `type Permissions map[Area]Level`; `func (p Permissions) Can(a Area, l Level) bool` (a missing area is `none`).
- `type RoleDef struct { Name Role; Permissions Permissions; BuiltIn bool }`.
- `func NewRoleStore(path string) *RoleStore` (empty path keeps roles in memory only).
- `Get(name Role) (RoleDef, bool)`, `List() []RoleDef` (built-ins first, then by name), `Create(RoleDef) error`, `Update(name Role, p Permissions) error`, `Delete(name Role) error`.
- Errors: `ErrRoleExists`, `ErrRoleNotFound`, `ErrRoleBuiltIn`, `ErrRoleName`, `ErrRolePermissions`.
- `func (s *UserStore) SetRole(username string, role Role) bool`.

**Tests:** built-ins resolve as the spec's table; name rules (length, characters, case-insensitive uniqueness, built-in names taken); unknown area or level refused; a role survives a reload from disk; a missing area reads as `none`.

### Task 2: Enforcement on every route

**Files:** modify `internal/handler/handler.go`, `internal/handler/auth.go`, `internal/handler/alerts.go`, `cmd/server/main.go`; create `internal/handler/permissions.go`, `internal/handler/permissions_test.go`.

**Consumes:** Task 1. **Produces:** `Config.Roles *auth.RoleStore` (nil means built-ins only); `need(area, level)` and `needAny(...)` middleware; `can(r, area, level) bool`; `/api/auth/me` returns `permissions`.

**Tests:** walk the router; every route under the signed-in group is either in the open list or in the expected table, and for a role with `none` / `view` / `manage` on its area (and `manage` elsewhere) answers 403 or not as the table says. Retention reads open with either `events: view` or `system: view`. The existing scope tests pass unchanged.

### Task 3: Roles API and account role changes

**Files:** create `internal/handler/roles.go`, `internal/handler/roles_test.go`; modify `internal/handler/auth.go`, `internal/handler/audit.go`, `internal/handler/handler.go`.

**Produces:** `GET /api/roles` (each role with its account count), `POST /api/roles`, `PUT /api/roles/{name}`, `DELETE /api/roles/{name}`, `PUT /api/users/{username}/role`.

**Tests:** a role in use is not deleted and the refusal gives the count; built-ins refuse edit and delete; an account cannot change its own role; the last unlimited `admin` cannot be deleted, re-roled or limited; an edited role applies on the account's next request; creating an account with an unknown role is refused.

### Task 4: Frontend permissions

**Files:** modify `web/src/api/client.ts`, `web/src/api/types.ts`, `web/src/layout/AuthContext.tsx`, `AppSidebar.tsx`, `AppHeader.tsx`, the three event providers, `web/src/App.tsx`, and every page that reads `isAdmin` or `role === 'admin'`.

**Produces:** `useAuth().can(area, level)`; sidebar items and routes carry their area; event providers do nothing without `events: view`.

### Task 5: Roles page and Users page

**Files:** create `web/src/pages/RolesPage.tsx`; modify `web/src/pages/UsersPage.tsx`, `AppSidebar.tsx`, `App.tsx`, `AppHeader.tsx` (breadcrumb labels).

### Task 6: Documentation

**Files:** `docs/features.md`, `docs/architecture.md`, `README.md`.

### Task 7: Verification in the lab

Through the UI, after a release: a role with only `events: view`; a role with `network: manage` and `events: view`; a limited account with a custom role; the two built-in roles unchanged.
