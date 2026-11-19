# Custom roles — design

Date: 2026-11-19

## Intent

An account is either `admin` or `viewer` today, optionally limited to some
namespaces. "May write" is one switch for the whole product, so there is no way
to make an account that only watches events, or one that only manages Network
Policy. Enterprises ask for exactly that. This adds roles that grant each part
of the product separately.

## Decisions (made by the owner)

1. **A permission is an area and a level.** Each area is `none`, `view` or
   `manage`. `manage` includes `view`.
2. **A role is a named set of those**, and roles can be created, edited and
   deleted. An account has exactly one role.
3. **The namespace limit stays on the account**, not on the role, so one role
   serves several teams. Both are checked: the role says what kind of thing,
   the namespaces say where.
4. **Templates and Behavior Discovery belong to the Tracing Policy area.**
5. **Quarantine is its own area.**
6. **Only an account with `system: manage` that is not limited to namespaces
   manages roles and accounts.**
7. **No per-button permissions** (create but not delete, and so on).

## Areas

| Key | Pages | Notes |
|---|---|---|
| `tracing` | Tracing Policy, Templates, Behavior Discovery | includes each policy's mode and "Set all to Monitoring" |
| `network` | Network Policy, Network Topology | |
| `admission` | Admission Policy, Bindings | |
| `quarantine` | Quarantine | `manage` quarantines and releases |
| `events` | Security Events, Admission Events, Event Sources | |
| `vulnerabilities` | Vulnerabilities (Workloads), Registries | |
| `notifications` | Alerts, Syslog | |
| `system` | Users, Roles, Audit Log, Event Retention, Session Timeout | |

The Dashboard is open to every signed-in account; each card is shown only with
`view` on its area.

## Built-in roles

Two roles always exist, cannot be edited or deleted, and keep the names stored
on every existing account, so **an upgrade needs no data change**:

| Role | Permissions |
|---|---|
| `admin` | `manage` on every area |
| `viewer` | `view` on `tracing`, `network`, `admission`, `quarantine`, `events`, `vulnerabilities`; `none` on `notifications` and `system` |

`viewer` is drawn to match what a viewer is shown today: the Settings group
(Users, Alerts, Syslog, Event Retention) and the Audit Log are already hidden
from it. (My call: `notifications` is `none`, not `view`, because an alert
rule's webhook URL is a credential.) Three API reads tighten for a viewer,
none of which any page shows it: `GET /api/alerts` and `GET /api/rsyslog`
(answered with the URL redacted before) and `GET /api/settings/session-ttl`
now answer 403.

## Behaviour

**Enforcement is on the server, for reads as well as writes.** An account
without `events: view` is refused the events API and its streams; hiding a page
is not the control.

**Route to area.** Every route under the signed-in group declares the area and
level it needs. Reads need `view`, writes need `manage`, with these specifics:

- Open to any signed-in account: `/api/auth/me`, changing one's own password,
  `/api/namespaces`, `/api/pods/{ns}/{pod}/labels`, `/api/selector-preview`,
  `/api/cluster/cidr`. They are helpers for forms and carry nothing an area
  protects beyond what the namespace limit already filters.
- `tracing`: policies, policy preview, policy mode, `/api/mode`, templates,
  discovery profiles (clearing them is `manage`).
- `network`: `/api/cnp*`, `/api/network-topology`, `/api/cilium/*`.
- `admission`: `/api/vap*`, `/api/vap-bindings*`.
- `quarantine`: `/api/quarantine*`.
- `events`: security and admission events and their streams, the raw Tetragon
  stream `/api/events/stream` (my call: it is events, and the frontend does not
  use it), `/api/tetragon/agents`, `/api/ingestion/health`.
- Reading either retention setting is the one route two areas open: `events:
  view` (the event pages show it) or `system: view` (the Event Retention page
  edits it). My call. The Event Retention page needs `system: view`; anything
  on it that comes from the event data is shown only with `events: view`, and
  the page works without it.
- `vulnerabilities`: `/api/vulnerabilities*`, `/api/registries*`.
- `notifications`: `/api/alerts*`, `/api/rsyslog*`. The webhook URL is shown
  unredacted only with `manage`.
- `system`: `/api/users*`, `/api/roles*`, `/api/audit`, writing either
  retention setting, the session timeout (read and write).

**The namespace limit is unchanged and still applies on top.** Every route that
refuses a limited account today (`clusterWide`) still does, whatever its role:
templates, registries, alerts, syslog, users, roles, audit, settings, event
sources, "Set all to Monitoring". A limited account's `system` and
`notifications` permissions therefore have no effect; the role editor does not
need to prevent the combination.

**Pages that cross areas.**

- "Quarantine this pod" on a security event needs `quarantine: manage`; the
  button is absent otherwise. The Topology marks quarantined pods only for an
  account with `quarantine: view`.
- An account without `events: view` gets no event streams, no unread counters
  and no event pages.
- A page the account has no `view` on is absent from the sidebar, and its URL
  lands on the Dashboard, as cluster pages do for a limited account now.

**Roles.**

- Stored in the data directory beside the other settings (`roles.json`), each
  with a name and its area levels. An area missing from a stored role is `none`,
  so a later release can add an area without touching stored roles.
- A role's name is fixed once it is created (my call): accounts refer to a
  role by name, and a rename would have to rewrite two files together. Editing
  a role changes its levels only.
- Name: 1 to 40 characters, letters, digits, space, `-` and `_`; unique without
  regard to case; `admin` and `viewer` are taken.
- A role some account still has cannot be deleted; the refusal names how many
  accounts have it.
- Editing a role takes effect on the next request of every account that has
  it. No one is signed out.
- An account whose role no longer exists (a hand-edited file) has no
  permissions and can only sign in, see the Dashboard and change its password.

**Accounts.**

- New User offers every role instead of the two fixed buttons.
- An account's role can be changed afterwards (new: `PUT
  /api/users/{username}/role`), from the same dialog that sets its namespaces.
- An account cannot change its own role, as it already cannot limit or delete
  itself.
- There is always at least one account with the `admin` role and no namespace
  limit: deleting it, changing its role or limiting it is refused when it is the
  last.

`system: manage` is the power to grant anything, to oneself included by way of
another account. That is stated in the role editor; it is not something to
engineer around.

**Audit.** Creating, editing and deleting a role and changing an account's role
are recorded like every other write. Writes by any role are recorded, not only
by `admin`.

## Interface

- **Settings → Roles** (new, needs `system: view`): a list of roles with the
  number of accounts on each. Editing a role is one table, a row per area and
  the three levels as a choice in each row. Built-in roles open read-only.
- **Users**: the role column shows the role name; the role is chosen from a
  list.
- `/api/auth/me` returns the account's resolved permissions, and the frontend
  asks one question everywhere, `can(area, level)`, in place of `isAdmin`.
- UI copy follows the existing rules: no em dash, edit pages titled `Edit
  <name>`, no example placeholders, no secondary text the layout already says.

## Non-goals

- Per-action permissions inside an area.
- More than one role per account, or a namespace limit on a role.
- Mapping roles from an external directory (OIDC, LDAP groups). The role model
  here is what such a mapping would target later.
- Per-cluster roles.

## Anti-goals

- A page hidden in the UI whose API still answers.
- An upgrade that changes what any existing account can do, other than the
  three viewer reads noted above.
- A state with no account able to manage accounts.

## Left to the builder

- How a route declares its permission (middleware per route, wrapper, table),
  as long as a test fails when a route under the signed-in group declares none.
- File layout and naming in `internal/auth` and `internal/handler`.
- The exact look of the role editor within the existing component set.

## Verification

- A table test over every route: for a role with `none`, `view` and `manage` on
  the route's area and `manage` on every other, the route answers 403, or is
  let through, as the tables above say.
- The existing namespace-limit tests pass unchanged.
- Stored accounts with `admin` and `viewer` behave as before the change.
- In the lab, through the UI: a role with only `events: view`, and a role with
  `network: manage` plus `events: view`, each see and can do exactly that.
