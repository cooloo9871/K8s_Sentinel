# K8s Sentinel — Architecture

**Status:** reflects the current code (updated alongside it)

[install.md](install.md) covers **how to install and configure**. This document covers
**why it is shaped this way**, and which invariants must not be broken.

---

## 1. The whole picture

One Pod, two things: a Go backend, and a React SPA compiled into the same binary.

```
                    ┌──────────────────────────────────────┐
   Browser ────────▶ │  sentinel (single Pod, replicas: 1)  │
                    │                                      │
                    │   chi router  ──▶  embed FS (SPA)    │
                    │       │                              │
                    │       ├── /api/*  handlers           │
                    │       │                              │
                    │   ┌───▼──────────────────────────┐   │
                    │   │ internal/k8s.Store           │   │
                    │   │  · Tetragon event broadcast  │   │
                    │   │  · Hubble flow broadcast     │   │
                    │   │    + topology buffer         │   │
                    │   │  · assorted TTL caches       │   │
                    │   └───┬──────────────────────────┘   │
                    └───────┼──────────────────────────────┘
                            │ gRPC / API
              ┌─────────────┴─────────────┐
              ▼                           ▼
      tetragon DaemonSet          cilium-agent DaemonSet
      (GetEvents gRPC)             (Relay GetFlows gRPC)
```

**There is no database.** All state is either in memory or in JSON files under `DATA_DIR`.

---

## 2. Backend packages

| Package | Responsibility |
|---|---|
| `cmd/server` | Assembly: build clients, start background goroutines, mount the router, graceful shutdown |
| `internal/k8s` | Everything that talks to the cluster. The Store is the single entry point |
| `internal/handler` | HTTP routes, auth middleware, topology graph assembly |
| `internal/security` | Security Events: persistence, deduplication, retention, SSE |
| `internal/admission` | Admission Events: K8s Event watch + audit webhook |
| `internal/policy` | TracingPolicy form model and YAML generation |
| `internal/auth` | Users, bcrypt, JWT issuance and revocation |
| `internal/alert` | Webhook notifications |
| `internal/rsyslog` | Syslog forwarding |
| `internal/registry` | Registry scanning: listing registries, a Trivy Job per image, results and schedule |

`internal/k8s.Store` is deliberately large: every read and write against the cluster
goes through it, caching and broadcasting live inside it, and handlers only turn
results into JSON.

---

## 3. The two event-ingestion pipelines

### 3.1 Tetragon — runtime events

`StartTetragonBroadcast` opens the Tetragon `GetEvents` gRPC stream against **every**
Tetragon Pod (dialing each pod IP on port 54321), bridges each protobuf message back
to `TetragonEvent`, and fans out to all subscribers.

Why one stream per Pod: **each agent only sees its own node's events** — one missing
connection means every event from that node silently disappears. Tetragon has no
relay, so the per-pod model is unavoidable here.

**The bridge**: rather than parse protobuf directly, each message is marshaled with
the proto field names — exactly what `tetra getevents -o json` emits — and fed to the
same `parseTetragonLog` the CLI output used. The careful parsing, dedup and
attribution logic is reused unchanged; a bridge test pins that the protobuf still
reproduces the CLI shape.

The only subscriber is `security.Store`.

**Alerts and rsyslog do not subscribe to this raw stream.** They subscribe to
`security.Store.SubscribeFirstSightings()` — notified only when an event **opens a new
row**. All three used to read the raw stream and each decide for itself what counted
as distinct, so one retry loop was one row on screen and hundreds of webhooks. There
is now a single arbiter of "what counts as one event": `security.Fingerprint`.

The alert cooldown is not replaced by this — the dedup window is only 30 seconds, so
repeats spaced further apart still open new rows, and that is exactly the stretch the
cooldown covers. Both now key on the **same identity**, so the cooldown only
suppresses repeats of the same thing and can no longer swallow *different* events
from one pod.

> **Known duplication**: `StartDiscoveryLoop` does not subscribe to this broadcast; it
> opens its own `StreamTetragonEvents`. So every node actually carries **two**
> `GetEvents` streams. Switching Discovery to the broadcast would make it drop
> events when the buffer fills (the broadcast is a non-blocking fan-out), while its
> own stream has backpressure — that trade-off has not been decided.

### 3.2 Hubble — network flows

`StartCiliumBroadcast` first runs `DetectCilium`, then opens the `GetFlows` gRPC
stream against **Hubble Relay** — one aggregated endpoint for the whole cluster,
unlike the per-pod Tetragon streams, because Relay already collects from every node.
Each `GetFlowsResponse` is bridged the same way (proto-names marshal → the existing
`parseCiliumFlow` that `hubble observe -o json` was written against).

**Cilium's namespace must be detected to address Relay.** Detection probes
`kube-system`, `cilium` and `cilium-system`; the relay endpoint defaults to
`hubble-relay.<ns>.svc.cluster.local:80` in whichever it finds, overridable with
`HUBBLE_RELAY_ADDRESS`.

Every flow goes three ways:
1. Merged into the topology buffer
2. Broadcast to SSE subscribers (allowed/dropped only)
3. If it is an attributable policy denial → synthesized into a `TetragonEvent` and fed
   into the security event stream

### 3.3 Ingestion health — knowing when we are blind

The worst failure mode for a security console is looking like it is monitoring
while it is blind. A Tetragon Pod's readiness probe reports whether the agent
itself is up, **not** whether Sentinel's gRPC stream to it is connected — so a
blocked NetworkPolicy, a wrong `TETRAGON_GRPC`, a TLS mismatch or a stream that
drops on connect would leave the agent showing "Ready" while not a single event
arrives.

`IngestionHealth` (`internal/k8s/ingestion_health.go`) records, per source, the
truth the readiness probe cannot: whether the stream is **connected**, the
**consecutive-failure** count, the **last error**, and the **last time an event
actually arrived**. The stream paths mark it directly — `streamFromPod` on
connect / receive / error (keyed by node, since Tetragon is per-node),
`StreamCiliumFlows` likewise for Hubble, and the `DetectCilium` miss records
"Cilium not detected" rather than returning silently.

Health is **connection liveness**, not event volume: a stream that is connected
but quiet is healthy (a calm cluster is not a broken one), so the last-event
time is shown as information, never used on its own to declare a source dead.
`GET /api/ingestion/health` returns every source's status; `GetTetragonAgents`
folds each node's ingestion state into its row so the agent view shows
**Stream Down** when a Ready pod is not actually being ingested, and the
dashboard raises a banner the moment any stream has failed.

---

## 4. The topology graph

### 4.1 The buffer

`ciliumTopo` is a map keyed by `srcID|dstID|port|verdict`, each entry accumulating a
count and a lastSeen. The window is **15 minutes**.

**The verdict is part of the key**, and that matters: remove it and a later allowed
flow overwrites a denial in place — the red edge turns green while the policy is
still dropping traffic.

### 4.2 Which flows never enter the buffer

| Excluded | Why |
|---|---|
| Verdicts other than allowed/dropped | TRACED / TRANSLATED are intermediate observation points, not outcomes |
| `is_reply = true` | An edge's direction is the **connection-initiation direction**. Reply-direction flows make a pod's outbound curl look like inbound external traffic |
| ICMP error messages | Those are the network reporting "the packet you just sent failed", and the source field names the **reporter**. Drawing one states the causality backwards |

ICMP **echo** is kept — a ping is real traffic, and a ping sweep is exactly what a
security tool should show.

### 4.3 How addresses resolve to nodes (`resolveID`)

The order is significant:

1. **Has a pod name** → pod
2. **Link-local** (`169.254.0.0/16`, `fe80::/10`) → its own kind. RFC 3927 addresses
   are not routable beyond the local link, so one can never be a client from outside
   the cluster. `169.254.169.254` is named cloud metadata
3. **`reserved:world` identity** → external. **Identity outranks address**: NodePort
   traffic forwarded across nodes is SNATed to the ingress node's `cilium_host`, so
   the address looks in-cluster while the identity is still world
4. **A node address** (physical IP or `cilium_host`) → node
5. **Inside the pod CIDR but not a known pod** → skipped
6. Everything else → external

Classifying link-local as external is not just a wrong label: the UI flags pods that
receive external traffic with no exposure path in red, so a sidecar's own plumbing
was being reported as an intrusion (fixed in v0.21.1).

### 4.4 One verdict per pair

On an L7 denial, L3/L4 is allowed while L7 is dropped — **both exist at once and both
are current**. Picking the newer one flips between them and mostly shows the allow,
hiding the denial entirely.

The rule: **a denial that is still arriving wins outright** (`denialStillLive = 2
minutes`); only a denial that has stopped gives way to the traffic that replaced it.
A tie counts as denied.

### 4.5 Recognising kubelet probes

`IsHealthProbe` requires **both conditions at once**: the source node equals the pod's
node, and the destination port is one the pod declares for probing. Neither alone is
enough — the same port reached from anywhere else is ordinary traffic, and the same
node reaching a different port is not a probe.

The declared probe ports cover:

- `livenessProbe` / `readinessProbe` / `startupProbe`
- `httpGet` / `tcpSocket` / `grpc`
- Named ports (resolved against **that container's own** `ports`, the same way the
  kubelet does)
- `postStart` / `preStop` `httpGet` lifecycle hooks — also requests the kubelet sends
- **Regular containers and native sidecars** (initContainers with
  `restartPolicy: Always`)

The last item is how Istio injects its proxy on Kubernetes 1.29+. Reading only
`spec.containers` misses the sidecar's readiness probe on 15021, which shows up as a
node connection that can be neither explained nor hidden (fixed in v0.21.3).

**Deliberately not hidden**: `kubectl port-forward` also arrives from the node, but
that is a person reaching into a pod — a security console should show it.

### 4.6 What cannot be told apart

When the probe port and the service port are the same (say the app and the probe both
on 8080), a connection from that node to that port cannot be attributed to the
kubelet or to a person. The kubelet and a shell on the node live in the same host
network namespace; Hubble sees identical identity, address and port range, and a flow
carries no process information.

There are only two ways out: untick `Hide health probes` while testing, or give the
probe a dedicated port.

---

## 5. Policy attribution

Hubble only names the policy when an **explicit `ingressDeny` / `egressDeny` rule**
fires. An allowlist policy denies through default-deny — the **absence of an allow
rule** — so there is no rule to report.

`AttributePolicyDenial` fills that gap: it finds the policies that govern the pod in
that direction.

Three invariants:

- **Never invent a policy name.** If nothing matches, no event is produced. The
  Policy column only ever shows policies that actually exist in the cluster
- **If several match, list them all.** A default-deny drop cannot be pinned on one of
  them; picking one sends the operator to the wrong rule
- **`matchExpressions` are not evaluated.** Claiming a hit on a partial match would
  name the wrong policy

The same cache also supplies container names (flows do not carry that field) and
probe ports, on a 30-second TTL.

---

## 6. Exposure detection

**This is static analysis of configuration, not observed traffic.** It answers "where
would someone outside have to aim to reach this pod".

| Type | Source |
|---|---|
| nodeport / loadbalancer / externalip | Service |
| ingress | Ingress, with the TLS block deciding the scheme |
| gateway | Gateway API `Gateway` + `HTTPRoute` / `GRPCRoute` |
| istio | Istio `Gateway` + `VirtualService` |
| hostnetwork / hostport | Pod spec |

Service → Pod resolves through **EndpointSlice**, not the deprecated Endpoints API —
the latter truncates at 1000 addresses, quietly dropping pods of a large Service out
of exposure detection.

**Istio requires reading the Gateway; the VirtualService alone is not enough.** A
VS's `hosts: ["*"]` means "every host this Gateway serves" — a wildcard relative to
the Gateway — and the hostname and port only exist on the Gateway. The two are met
and **the more specific one wins**, which is Istio's own resolution rule. A VS naming
a host its Gateway does not serve is ignored by Istio — so it is not an external path
(v0.22.0).

When the Gateway cannot be read (absent, or missing RBAC), the fallback is to **show
the VS's own hosts** rather than dropping the path. On a screen that inventories
attack surface, being imprecise beats saying nothing.

ClusterIP is **not** exposure, deliberately.

---

## 6.5 Quarantine

Cut a suspect pod off from the network **without killing it** — the process, its
memory and its open files all stay available for examination. Killing the process is
what Tetragon's Sigkill already does; deleting the pod is worse, because the
Deployment rebuilds it.

The mechanism is **one label plus one standing policy**, not a policy per pod:

```
pod labelled  sentinel.io/quarantine=true
        +
CCNP sentinel-quarantine  selects that label
```

A CNP selects endpoints by label anyway, so "one policy per pod" would first need a
unique label per pod — at which point one policy is simpler. This way **the cluster
is the source of truth**: a Sentinel restart cannot forget who is contained, and
`kubectl label pod … sentinel.io/quarantine-` releases a pod without the UI.

The policy's shape carries one key decision:

```yaml
ingress:
  - fromEntities:       # the kubelet's probes still get through
      - host
      - health
egressDeny:
  - toEntities:         # a deny beats any allow
      - all
```

**Ingress from the node must stay open.** Block it and the kubelet's probes fail →
readiness fails → liveness fails → the container restarts → the Deployment hands back
a **fresh, uncontained pod**, and the containment goes with the evidence.

Triggering is **manual only** (the button on Security Events). Automation is
deliberately not built: the policy builder defaults to whitelist mode — everything
*outside* the list fires — so one mis-scoped policy could quarantine an entire
Deployment in seconds.

---

## 6.6 Vulnerabilities

Sentinel does not scan images. Trivy Operator does, and writes one
`VulnerabilityReport` per container of each workload; `internal/k8s/vulnerability.go`
reads them. This is the same division as Tetragon and Hubble: a dedicated engine
does the work, Sentinel correlates and presents.

**The list is built from running pods, not from reports.** Listing reports would
be simpler and would be wrong in both directions:

- A workload nothing has scanned would be absent, which reads as "nothing to
  worry about". Starting from pods, it is present and marked not scanned.
- A report outlives its workload until the operator garbage-collects it. Starting
  from pods, a report nobody runs any more is never shown.

Reports are matched by Trivy Operator's owner labels
(`trivy-operator.resource.kind` / `.name`, plus `trivy-operator.container.name`).
An owner name longer than a label value may be (63 characters) is carried in an
annotation of the same key, which is checked when the label is absent.

**Where the operator files a report is not always where the pod's owner is**, so
each pod has two answers: the workload it is listed under, and the owner its
report is looked up under. These were checked against the operator's source
(`pkg/operator/workload/helper.go`, `pkg/kube/object.go`), not observed on a
cluster:

| Pod's controller | Listed as | Report looked up under |
|---|---|---|
| ReplicaSet owned by a Deployment | Deployment | the **ReplicaSet** |
| StatefulSet, DaemonSet, bare ReplicaSet, ReplicationController | itself | itself |
| Job owned by a CronJob | CronJob | the **CronJob** |
| Job | Job | Job |
| Anything else (a custom resource such as a database operator's `Cluster`) | that owner | the **Pod** |
| None, or a Node (static pod) | Pod | Pod |

Pods carrying `app.kubernetes.io/managed-by=trivy-operator` are the operator's
own scan jobs, which it does not scan, and are left out.

**The image is matched as well as the container.** The operator scans the
controller's pod *template*, not each pod. A StatefulSet or DaemonSet whose
template has moved on while old pods keep running (`OnDelete`, a partition, a
stuck rollout) has a report for the new image only. Matching on the container
name alone would show the old image with the new image's findings, or as clean.
`scannedImage` compares the report's `artifact.repository` and tag or digest with
the image the pod runs, and an image that does not match is not scanned. The
registry is not compared: the two sides write it differently (`docker.io`
against `index.docker.io`). Mid-rollout a Deployment runs two ReplicaSets; by
default the operator keeps the report of the current one only, so the outgoing
image shows as not scanned until its pods are gone.

**A container with no report of its own borrows one of the same image**
(`reportForImage`). Two things leave such containers behind. The operator scans
all of a workload's containers side by side in one pod; they share a scan cache,
and with several the losers of the lock fail and are not retried until the
report TTL brings the next rescan (seen on a cluster: Cilium's agent pod, seven
containers on one image, one report). And a sidecar injected at admission is not
in the pod template at all. Findings are a property of the image, so a report of
the same repository and tag or digest answers for it. A report of the same
workload is preferred; one from another workload must also match the registry,
since a name and tag on two registries are not promised to be one image. The
borrowed report may be in another namespace, so each image carries the namespace
its findings are read from.

**Exposure is joined in, not recomputed.** The `exposed` flag comes from
`CachedPodExposures` (§6), so this page and the topology cannot disagree about
what is reachable from outside.

**Reports are large.** Each carries every finding inline and can run to
megabytes, so the list is read in pages of 20 and only the summary of each
report is kept: counts, the number of fixable findings, the scan time, the image
and the report's name. The findings themselves are fetched by that name when a
row is expanded. One refresh runs at a time, and the two halves are cached
separately: the aggregate, rebuilt from the pod informer, for 60 seconds, and
the report summaries for five minutes, since reports change only when a workload
does or on the daily rescan. The Refresh button bypasses both. Failures are not
cached, so installing the operator or fixing the ClusterRole shows on the next
load.

**The topology does not wait for a scan.** It polls every few seconds and marks
pods from `PodVulnCounts`, which returns the last per-pod counts at once and,
when they have expired, starts one refresh in the background. The counts are
per pod, summed over that pod's own matched reports, so the image-matching rule
above holds for the mark too. A failed read clears them: a mark Sentinel can no
longer vouch for is removed rather than left standing.

**The scanner's health is read off the reports.** Trivy Operator is not a stream
with a connection to watch. `reports` and `lastScanAt` in the overview cover
every report in the cluster, including those of workloads no longer running, so
Event Sources can tell "installed and writing" from "installed and silent".

**A report can vanish between the list and the read.** The operator deletes and
rewrites each report when it rescans (every 24 hours by default). A read that
fails is returned as `unavailable` for that container and the page says so; it
is never folded into "no findings".

**An empty page always says why.** A missing CRD (`not-installed`), a ClusterRole
without the rule (`forbidden`) and any other failure (`error`) are distinct
states, because the operator does something different about each. The
`forbidden` case is the one an upgrade produces: a new image against the old
ClusterRole.

Known gap: a container added at admission (a service mesh sidecar, a secrets
agent) is not in the pod template, so the operator never scans it. Its workload
shows as **partial** permanently. That is accurate, since the sidecar is running
and unscanned, but in a meshed cluster it makes "partial" the norm. Ephemeral
containers are not listed.

---

## 6.7 Registry scanning

The one place Sentinel starts work rather than reading someone else's.
Trivy Operator scans what runs in the cluster and has no notion of a registry,
so `internal/registry` lists a registry, starts a Trivy Job per image, and
keeps the results. Trivy is still the scanner.

**Listing.** A filter is `repository[:tag]` with `*` matching any run of
characters, slashes included. Tags come from `GET /v2/{repo}/tags/list`, which
Harbor, Docker Registry and quay.io all serve, with the bearer-token challenge
answered the way a container runtime does. Listing *repositories* is where they
differ: `/v2/_catalog` on a Docker Registry; Harbor's
`/api/v2.0/projects/{project}/repositories`, because its `_catalog` answers only
to a system administrator; quay's `/api/v1/repository?namespace=`, plus
`_catalog` when credentials are set, since a robot account can use that and not
the API. A tag is checked against the registry whenever either side of the
filter has a wildcard, or `library/*:v2` would name `v2` of every repository
whether it exists or not. Any listing failure fails the whole resolution: a
partial list would read as "that is all there is".

**One Job per image, three at a time.** The pod runs as a non-root user on a
read-only root filesystem with an `emptyDir` at `/tmp`, which is what the
namespace's restricted Pod Security level admits. A run stops at 500 images and
reports how many the filters matched, so the cap is never silent.

**Results come back through the pod log.** Trivy's JSON report runs to megabytes
an image, more than is safe to carry through a log the kubelet rotates, so the
Job uses an output template: one JSON object per finding with seven fields, then
a completion marker carrying the number of findings printed. `parseOutput`
treats a log without the marker as a failed scan and Trivy's last message as the
reason, and a log with fewer findings than the marker states as one whose
beginning the kubelet rotated away. Findings printed before a failure
are discarded: a scan cut short is not a result.

**Credentials.** The password lives in `registries.json` and is stripped from
every API response. For a scan it goes into a Secret created after the Job and
owned by it from the start, as a Docker `config.json` keyed by the registry
host, mounted and pointed to with `DOCKER_CONFIG`. `TRIVY_USERNAME` and
`TRIVY_PASSWORD` are not used: they name no host, and Trivy offers them to every
registry it contacts, the one serving its database included (confirmed against
Trivy 0.76.1 with a listening socket). An edit that changes the URL without
giving the password is refused, so a saved password cannot be pointed at
another host. Sentinel's Role can create and delete Secrets, not read them.

**A private CA.** A registry's `caCert` is added to the system roots for
Sentinel's own listing requests. The scan pod is harder: Trivy has no option for
a CA. It is a Go program, though, and Go loads every certificate in
`SSL_CERT_DIR` on top of the system bundle file, so the CA travels in the Job's
Secret and is mounted where that variable points. `SSL_CERT_FILE` is avoided
because it replaces the bundle, and with it the roots Trivy needs to fetch its
database (both behaviours confirmed against Trivy 0.76.1 and a registry signed
by a throwaway CA).

**Storage.** `registry-scans/{id}/index.json` holds the run and one summary per
image and is all that is kept in memory; each image's findings are in a file of
their own beside it, read when a row is expanded.

**A pod that cannot run stops the run.** A scan pod still unable to start after
two minutes (image pull failure, unschedulable, refused by admission) ends its
scan with an `InfraError`, and the run stops there with that as its error rather
than spending a timeout on each remaining image. Such a run, like one that could
not list the registry, is retried after an hour.

**Scheduling.** A loop checks once a minute and starts a registry whose last run
began more than its interval ago. A run interrupted by a restart has no finish
time, which makes it due at once; its orphaned Jobs are deleted at startup. An
edit cancels the running scan and starts another, since what is being scanned
may have changed.

**Keeping the two scanners apart.** The Jobs and their pods carry
`sentinel.io/registry-scan`. The Workloads list skips pods with it, and
`deploy/trivy-operator-values.yaml` sets `skipResourceByLabels` so the operator
does not scan Trivy scanning.

**What has and has not run for real.** The listing code ran against quay.io,
Docker Hub and a public Harbor. The Trivy command line, its output template and
the `DOCKER_CONFIG` login ran in a local container under the same user and
filesystem restrictions. Trivy Operator's own scan pods have been seen running
as non-root in a namespace enforcing the restricted level. Sentinel's own Job,
its Role, and reading the log back have only been tested against a fake API
server.

## 7. Storage

| Data | Where |
|---|---|
| Users, JWT secret, security events, admission events, alert rules, rsyslog configs, templates | JSON under `DATA_DIR` |
| Topology buffer, SSE subscriptions, token revocation list, assorted caches | Memory |

File writes are **asynchronous**: snapshot plus generation number, a stale goroutine
abandons its write, and the rename happens inside the mutex to eliminate the TOCTOU.

> **Persistence.** `deploy/sentinel.yaml` mounts `/data/sentinel` as an `emptyDir`
> by default: a zero-dependency install that needs no StorageClass, which keeps
> evaluation frictionless. On an `emptyDir` a Pod restart clears everything above
> (accounts return to admin/admin, the JWT secret regenerates and invalidates every
> session — unless `JWT_SECRET` is injected from a Kubernetes Secret, which keeps
> sessions valid across restarts with no volume at all — and event history
> resets), so to keep data across restarts mount a
> PersistentVolume as described in [install.md](install.md#persistent-storage),
> together with `strategy: Recreate` (a single replica on an RWO volume would
> otherwise deadlock a rolling update, so this path needs a default StorageClass).
> The writability check in `main.go` does not flag this: the directory is writable,
> it simply does not survive a restart.

Retention caps are per severity (default 500 warnings / 300 criticals / 7 days), with
the oldest evicted first.

---

## 8. Authentication

A JWT in a cookie (HS256), `HttpOnly` + `SameSite=Strict`, plus `Secure` on HTTPS.
The signing method is verified, blocking alg-confusion.

The secret is 32 random bytes stored in `DATA_DIR/.jwt-secret`. **When the length
matches it is used as-is**, without trimming first — the last byte of a random value
is whitespace with probability 4/256, and trimming first misjudges the length,
regenerates the secret, and logs everyone out (fixed in v0.21.0).

Logout puts the JTI on a revocation list. That route is **deliberately public** (an
expired token must still be able to log out), so the handler parses the cookie
itself instead of reading claims from the context — read from the context, the
middleware never ran, the claims are always nil, and revocation silently does nothing
(fixed in v0.21.0).

There are two roles: `admin` writes, `viewer` reads.

Login hardening (v0.47.0): the default `admin` account must change its password
on first login before the rest of the console is reachable — enforced on the
server by a gate that, while the flag is set, allows only `GET /api/auth/me` and
the account's own password change. Passwords are at least 8 characters. Failed
logins are rate limited per source IP (5 per minute, then a brief block), keyed
on the source rather than the username so an attacker cannot lock a real user
out. Changing your own password requires the current one; an admin resetting
another account's does not. Every sign-in attempt is written to the audit log —
success, wrong credentials, and rate-limited alike — recording the account it
targeted, the source IP, and the outcome (the password is never recorded).
Password changes are audited too, on their own route since they sit outside the
admin group (fixed in v0.47.1).

> **Known weaknesses**: the login rate-limit state is memory-only, so it resets
> on restart (acceptable — bcrypt already makes each attempt cost ~50-100ms, and
> an attacker cannot force restarts); the revocation list is likewise memory-only
> (see the previous section).

Every response carries security headers (v0.53.0): `nosniff`, `X-Frame-Options:
DENY`, `Referrer-Policy: no-referrer`, and a Content-Security-Policy locked to
same-origin — the SPA loads nothing external, so only React's inline style
attributes need an allowance (`style-src 'unsafe-inline'`).

---

## 9. Frontend

React 19 + TypeScript + Vite, **shadcn/ui + Tailwind v4**. Compiled into the Go
binary (`web/dist` via `//go:embed`), so there is exactly one artifact.

```
web/src/
  api/          fetch wrappers
  layout/       AppLayout, Sidebar, SSE provider (one connection per event kind,
                shared app-wide)
  pages/        one file per page
  components/   shared across pages: ScopeFilter, FilterPopover, NamespaceSelect,
                PolicyForm; ui/ holds the raw shadcn-generated components
  hooks/        custom hooks
  lib/          cn() (clsx + tailwind-merge)
  data/         static data (policy templates and the like)
  utils/        cnpForm (CNP form ↔ YAML), time, exportEvents
```

**The shared components are deliberate**: the namespace filter and the filter panel
were once written per page, and each copy drifted. Tracing Policy / Network Policy /
Network Topology / Security Events / Admission Events now use the same `ScopeFilter`.

One rule runs through every filter: **nothing ticked = no filter**, never "match the
empty value".

The version number flows in at build time via the `VERSION` build arg →
`VITE_APP_VERSION` into the bundle, shown at the bottom of the sidebar. A build
without the arg shows `dev`.

---

## 10. Open architectural problems

Ordered by severity.

1. **No informers** — every cache does its own periodic full LIST of all pods
   (attribution 30s, ClusterIPs 30s, exposures 30s, workloads 60s, runc resolution
   30s). Five paths, no sharing. v0.34.0 moved these LISTs onto the apiserver's watch
   cache (`ResourceVersion: "0"`) instead of etcd quorum reads and put a cache in
   front of `ListNodeIPMap` — but **the same pod list is still fetched five times**;
   the real fix is one shared informer
2. **Two Tetragon event streams** (see §3.1)
3. **Authentication weaknesses** (see §8)

Persistence with `emptyDir` is a deliberate default, not a problem — mount a
PersistentVolume (see §7 and [install.md](install.md#persistent-storage)) to keep
data across restarts.

**Resolved since first draft:** the audit webhook can now require a bearer token
(v0.39.1), and `pods/exec` is gone — events are collected over the Tetragon and
Hubble gRPC APIs (v0.43.0), so the ClusterRole no longer grants the exec that was
equivalent to cluster-admin.
