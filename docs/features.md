# Features

Everything the UI does, and the reasoning behind the sharp edges. For how the
pieces fit together internally, see [architecture.md](architecture.md); for
getting it running, see [install.md](install.md).

## Policies

### Tracing Policy

- Create, edit and delete **TracingPolicy** resources, cluster-wide or namespace-scoped
- Filter the list by namespace and scope
- **Process Rules** — control which binaries may execute (whitelist / blacklist). **Absolute paths, matched exactly.** A bare program name is refused: it would have to be matched as a suffix, and a whitelist of suffixes is walked straight past by a binary at a path ending in an allowed one — `/tmp/usr/sbin/nginx` satisfies a rule meant for `/usr/sbin/nginx`. Behavior Discovery lists the paths each workload actually runs, so the exact value does not have to be guessed
- **File Rules** — control which paths may be accessed, optionally restricted to reads or writes, with per-rule process exceptions
- Switch each policy between **Monitoring** (observe) and **Protect** (block) mode, or flip every policy at once with **Global Protect Mode**
- **Created By** records who created each policy; resources applied with `kubectl` show as `k8s-apply`
- **+ New Policy** opens the form builder; **+ New YAML** starts from a manifest. Editing reopens the form when the policy can be represented in it, and the YAML editor otherwise — a policy carrying network kprobes opens as YAML so a save cannot drop those rules
- **Policy Templates** — built-in and custom, searchable and filterable by scope:
  - **Monitor All Process Executions** — observe process execution across every pod
  - **Monitor All File Access** — observe reads and writes on sensitive paths

> Network rules are not part of the Tracing Policy templates or form — network access control belongs to [Network Policy](#network-policy-cilium). A `tcp_connect` kprobe bound to process context (for example, killing any binary other than an allow-listed one that opens an outbound connection) is still expressible in the YAML editor; it is the one network control CNP cannot represent, because CNP judges by workload identity and cannot distinguish processes inside a pod.

### Network Policy (Cilium)

- Manage **CiliumNetworkPolicy** and **CiliumClusterwideNetworkPolicy** through a form builder, with a raw YAML editor for anything the form cannot express
- A policy is anchored on **one** `endpointSelector`, which is what the form shows: **Applies to** belongs to the policy, while each rule contributes a peer with its own ports and HTTP rules
- **Ingress and egress are separate sections of the same policy**, and either may be left empty. "This pod reaches the database and nothing else reaches it" is one intent, so it is one policy — a section with no rules is left out of the manifest entirely, rather than written as an empty `ingress: []` that would switch the endpoint to default-deny for a direction nobody filled in
- **Mode** is per direction, and it is named for what it does rather than as Allow/Deny. It has to be per direction because it decides whether that direction goes default-deny, and `enableDefaultDeny` is itself keyed by direction:
  - **Blacklist** — blocks only what the rules name; everything else is untouched. Writes `ingressDeny`/`egressDeny` with `enableDefaultDeny: false` for that direction, so one deny rule does not lock the whole direction down
  - **Whitelist** — permits only what the rules name and **drops everything else** reaching the endpoint, because in Cilium an allow section switches the endpoint to default-deny for that direction
- **Scope** — namespaced, or cluster-wide. A namespaced policy's `endpointSelector` only ever matches its own namespace, so governing pods elsewhere requires `CiliumClusterwideNetworkPolicy`
- Labels are **Key / Value** fields, not free text: a mistyped `app=web` does not fail, it selects nothing
- **Live selector preview**: while editing, the form shows which pods the selector matches right now (`Selects 3 pods in demo: ...`), turns red when it selects nothing, and warns when an empty selector is about to govern every pod. The Tracing Policy form has the same preview on its Pod Selector
- A peer is **Labels**, an **Entity** (`world`, `cluster`, `host` and the rest, for peers that have no labels to select), an **IP / CIDR** (a bare IP means that one host), or an **FQDN** (`github.com`, `*.github.com`). FQDN rules exist on the egress allow side only: Cilium learns a name's addresses from the DNS answers the pod receives, so there is nothing to match on ingress or in a deny rule. A DNS visibility rule to kube-dns rides along automatically, because a whitelist egress section would otherwise block DNS itself and the names would never resolve
- **A peer in another namespace has to name it.** A namespaced policy's `toEndpoints`/`fromEndpoints` match only its own namespace, so allowing egress to CoreDNS in `kube-system` needs the namespace alongside the selector — without it the rule selects nothing and the traffic is dropped by the default deny the allow section created. Each rule has its own **Peer namespace** field for this, which writes `io.kubernetes.pod.namespace` — the label nobody types from memory. A namespace on its own is a complete selector: it names everything in that namespace. A cluster-wide policy gets the same field for its subject, since it has no Namespace of its own; a namespaced one does not, because its selector is confined to its Namespace already
- Ports are rows with a protocol each; **L7 HTTP rules** are a list of alternatives (method and path), and are disabled under Blacklist because Cilium deny rules match on L3/L4 only
- Policies built here carry `sentinel.io/builder: "true"`, so **Edit** reopens the form; anything else opens as YAML, since a hand-written policy can hold rules the form cannot show
- The list shows what is easy to miss in raw YAML: whether a policy carries **L7** rules, and which direction it puts into **default deny**
- Policy denials become Security Events, fire webhook alerts, reach syslog and show as red edges in Network Topology

### Quarantine

Cut a suspect pod off from the network **without killing it**, so the process, its
memory and its open files are still there to examine. Killing the process is what
Tetragon's `Sigkill` already does; deleting the pod is worse, because the
Deployment hands back a replacement and the evidence goes with it.

- **Quarantine** from a Security Event, in the expanded detail — it contains the one pod that event names
- **Policies → Quarantine** lists what is contained, with who asked and when, and releases it
- On **Network Topology** a contained pod carries a red border and a lock

One label and one standing policy, not a policy per pod:

```
pod labelled  sentinel.io/quarantine=true
      +
CCNP sentinel-quarantine  selects that label
```

A CiliumNetworkPolicy selects endpoints by label anyway, so a per-pod policy would
need a unique label as well. This way there is one object to read, one to undo, and
**the cluster holds the state** — a Sentinel restart cannot lose track of who is
contained, and `kubectl label pod … sentinel.io/quarantine-` releases a pod without
the UI. The standing policy is created the first time it is needed and left in
place afterwards; with nothing labelled it selects no endpoints and has no effect.

The policy's shape carries one decision worth knowing about:

```yaml
ingress:
  - fromEntities:       # the kubelet's probes still get through
      - host
      - health
egressDeny:
  - toEntities:         # a deny beats any allow
      - all
```

**Ingress from the node stays open on purpose.** Block it and the kubelet's probes
fail, then readiness, then liveness — the container is restarted and the Deployment
hands back a fresh, uncontained pod. The containment and the evidence would go in
one move.

A pod that is deleted and recreated comes back without the label, and so without
the quarantine: the new pod is not the one that was contained.

> **Manual only.** Automatic quarantine on a policy violation is deliberately not
> here. The Tracing Policy form defaults to whitelist mode, where anything *not*
> listed fires, so one mis-scoped policy could contain an entire Deployment in
> seconds.

### Admission Policy (ValidatingAdmissionPolicy)

- Manage native Kubernetes VAP resources and bindings, via YAML editor or a UI builder that generates CEL
- The builder covers seven rule types and reverse-parses existing policies so they can be reopened in the form:

  | Rule Type | Description |
  |---|---|
  | **Label Check** | Require or forbid specific label key=value pairs; multiple rules; scoped to chosen resources |
  | **Annotation Check** | Require or forbid specific annotation key=value pairs; scoped to chosen resources |
  | **Image Policy** | Forbid the `:latest` tag; require images from named registries; covers every workload type and initContainers |
  | **Replica Limit** | Cap replicas on Deployments and StatefulSets |
  | **Resource Limits** | Require CPU and memory limits; covers every workload type and initContainers |
  | **Security Context** | Forbid privileged containers; require runAsNonRoot, honouring pod and container level inheritance |
  | **Host Access** | Forbid hostNetwork, hostPID and hostIPC across Pods and template-based workloads |

- **Binding Builder** — pick the policy, namespaces and validation actions (Deny / Audit / Warn)
- Resources created through the UI are tagged `sentinel.io/builder: "true"` so Edit reopens the builder

## Behavior Discovery

- Learns the processes each pod actually executes from the Tetragon base sensor — **no TracingPolicy required**
- Grouped by Deployment, DaemonSet and StatefulSet
- **Create Policy** prefills a policy form with the observed pod selector and binaries

## Network Topology

Graphs live pod network connections from Cilium Hubble flows.

- **A 15-minute window.** The graph shows what is happening now: a connection that stops falls off, and one that resumes reappears. Fifteen rather than five so a workload that only talks every few minutes does not make its edge flicker
- **Node kinds** — Pod (neutral), Node (blue), Link-local (slate), External IP (amber). Distinct hues so a glance separates workloads from infrastructure from what is outside the cluster. The legend lists only the kinds actually on the canvas. Service ClusterIPs are not drawn: a VIP is an intermediate routing concept, not an endpoint, and under Cilium the destination is already rewritten to the backend pod before the flow is observed
- **Link-local** (`169.254.0.0/16`, `fe80::/10`) is its own kind rather than external. Those addresses are not routable beyond the local link, so one can never be a client from outside — calling them external also made the pod light up as receiving unexplained external traffic, which is a pod's own sidecar plumbing reported as an intrusion. `169.254.169.254` is named **cloud metadata**: reaching it is a known credential-theft path, and an Istio sidecar probes it at startup to detect the platform
- A **quarantined** pod carries a red border and a lock, with the reason in the detail panel
- **Edges** take the colour of what they point at: indigo inside the cluster (pod or node — the node cards already say which), slate to link-local, amber to outside, red dashed for policy-denied. A denial that is still arriving wins over the allowed traffic it rides on, which is what an **L7 denial** always looks like: the connection is permitted and only the request is refused, so Hubble reports both verdicts at once
- Click a red edge for the policy that denied it. Where no policy can be named, it says so rather than inventing one — a default-deny drop has no rule to attribute, and the policy may also have been deleted
- **Aggregated per source/destination pair** with a per-port breakdown in the detail panel, so ephemeral client ports do not fan out into parallel lines
- **Hover focus** — labels appear only on the hovered node's edges and unrelated traffic dims out; hovering an edge makes it glow, and clicking the canvas clears the selection
- **View** gathers the toggles into one panel, with a dot on the trigger when any of them is hiding something: **Hide kube-system** (on), **Hide health probes** (on), **Exposed only**, **Auto refresh**
- **Exposure badges** — pods reachable from outside are marked, with each path listed. Every entry point is followed to the pods behind it, not just recorded:

  | Type | Resolved from |
  |---|---|
  | `nodeport` / `loadbalancer` | Service type |
  | `externalip` | `spec.externalIPs`, which is reachable whatever the type says and can sit alongside the others |
  | `ingress` | Ingress rules and default backend, any controller |
  | `gateway` | Gateway API `HTTPRoute` / `GRPCRoute` / `TCPRoute` / `TLSRoute` / `UDPRoute` `backendRefs`, including cross-namespace ones |
| `traefik` | Traefik `IngressRoute` / `IngressRouteTCP` / `IngressRouteUDP` (both API groups), hosts read from the rule matches |
| `contour` | Contour `HTTPProxy`: the virtualhost FQDN, route services and tcpproxy services; delegated child proxies show as `*` |
  | `istio` | `VirtualService` destinations, met with the hosts and ports its **Gateway** publishes — only where a real Gateway is attached, since `mesh` alone is sidecar traffic and exposes nothing |
  | `hostnetwork` / `hostport` | pod and container spec |

  Each one is shown as the chain of objects between the outside and the pod, rather than a joined-up sentence — the hops name what you would edit to close the path:

  ```
  GATEWAY
  www.test.com
  HTTPS · 443
  ↓
  Gateway
  envoy-gateway-system/eg
  ↓
  HTTPRoute
  default/backend2-route
  ↓
  Backend
  default/svc-backend2:8080
  ```

  Every entry point resolves through **Service → EndpointSlice → Pod**. EndpointSlice rather than the deprecated Endpoints API, which truncates at 1000 addresses per object — enough to drop pods out of a large Service, in the one place a missing pod reads as "not reachable".

  For Istio, reading the `VirtualService` alone is not enough. Its `hosts: ["*"]` means *every host the attached Gateway serves* — a wildcard relative to the Gateway, not an address — and the hostname and port exist only on the Gateway. The two are met and **the more specific wins**, which is what Istio itself resolves to; a `VirtualService` naming a host its Gateway does not serve is inert in Istio and is not reported as a path at all. A Gateway that cannot be read falls back to the `VirtualService`'s own hosts rather than dropping the row.

  Gateway API and Istio are optional: without the CRDs the lookup is skipped rather than failing.

  Known gaps: controller-specific CRDs beyond Traefik and Contour, such as Emissary `Mapping`, Gloo `VirtualService` and `CiliumEnvoyConfig`. A workload exposed only through one of those carries no badge. A pod receiving external traffic with **no declared exposure path** is flagged red, which catches config drift, a hostPort bypass or an active probe
- **L7 detail** — HTTP method, path and status code on edges where Cilium's proxy is in the path
- Traffic arriving from outside is identified by Cilium's `reserved:world` identity rather than by its address, so a connection SNATed to a node's `cilium_host` still reads as external — labelled **world via `<node>`**, with the detail panel explaining that the address is the node's and how to keep the client's
- **Traffic between two node addresses is never drawn.** It is Cilium's own plumbing — inter-node health probing and tunnel chatter — and never a workload's traffic. Node-to-pod is always shown, because that is how the outside reaches a workload
- **ICMP error messages do not become edges.** An unreachable or time-exceeded report names the *reporter* as the source, so drawing one states the opposite of what happened: a pod whose metadata lookup went nowhere appeared to be receiving traffic from an unknown address. Echo request and reply are kept — a ping is real traffic, and a ping sweep is worth seeing
- **Kubelet probes** are recognised and hidden by default. Detection needs both the source node *and* a port the pod declares, so the same port reached from anywhere else is ordinary traffic. It covers `httpGet` / `tcpSocket` / `grpc` probes, named ports resolved against the container's own declarations, `postStart` and `preStop` httpGet lifecycle hooks, and **native sidecars** — restartable init containers, which is how Istio injects its proxy on Kubernetes 1.29+, and where its readiness probe on 15021 lives. `kubectl port-forward` arrives from the node too and is deliberately **not** hidden: that is a person reaching into a pod

- A **hostNetwork** pod never appears as its own node. It shares the node's IP with the kubelet, the API server and every other hostNetwork pod there, and a flow carries only that address — so attributing one to a particular pod would be a guess. Its traffic shows as the node's
- Dagre auto-layout, pod search, and a namespace filter that takes several at once. Auto refresh every 60 seconds, and it can be turned off. The poll is silent — it does not replace the graph with a loading state, and only redraws when it brings something new, so a count ticking up neither blanks the view nor moves the camera

## Notifications

### Security Events

- Live stream of Tetragon events and Cilium policy denials; persisted across restarts
- **Every hook kind a TracingPolicy can attach to lands here** — kprobes, tracepoints, uprobes and LSM hooks. The trigger point shows in one Function field whichever kind it is (`tcp_connect`, `raw_syscalls/sys_enter`, `/usr/lib/libssl.so:SSL_write`, `file_open`), and the expanded detail names the hook kind. An LSM or kprobe **Override** action — the call forced to return an error — reads as Critical, the same as a Sigkill: both prevented something
- Warning / Critical severity, with content-based deduplication over 30 seconds. The client-side port is collapsed for that comparison, so a pod retrying a denied destination accumulates a count rather than filling the list
- A network denial names the workload that **attempted** the connection, the same way a process or file event names the pod that acted, and carries its containers. All of them are listed when a pod has several: they share one network namespace, so the flow cannot say which opened the connection
- **Only policies that exist are ever named.** A drop Hubble cannot correlate is attributed by asking which of your policies govern that pod in that direction; if none match, no event is recorded rather than one naming nothing
- Expand a row for the triggering file path, connection endpoints, process UID, policy name, drop reason and more
- **Filters** — search by pod, several namespaces at once, and one panel for **Severity** (Warning, Critical) and **Rule** (Process, File, Network, Kernel — the last for kernel functions outside the other three). Every group is multi-select, and nothing ticked in a group means no filter for that group
- **Quarantine this pod** on an expanded row — see [Quarantine](#quarantine). Every event from a contained pod shows a lock and offers no second button
- **Pause / Resume** freezes the view while buffering new events with an unread count
- **Export CSV**
- Default retention: 500 warnings, 300 criticals, 7-day TTL (adjustable in Settings)

> **Alerts and syslog fire once per event, matching this list.** All three used to
> read the raw event stream and each decide for itself what counted as distinct, so
> a pod retrying a denied connection was one row here, a webhook every cooldown
> period, and a syslog line per attempt. This store is the only arbiter now: it
> publishes an event the first time it records one, and a repeat folded into an
> existing row notifies nobody. The alert cooldown still applies on top, keyed on
> the same identity — it catches repeats spaced further apart than the 30-second
> folding window, and can no longer swallow *different* events from one pod.

### Admission Events

- ValidatingAdmissionPolicy violations, with several namespaces selectable at once and one panel for **Severity** and **Source**. The audit log alone is the default view
- **Critical** for `Deny` (request blocked) and **Warning** for `Audit` (request allowed but recorded)
- Sourced from Kubernetes Warning Events (no setup) or the **kube-apiserver audit webhook** (full coverage, [setup required](audit-webhook.md))
- 30-second deduplication, persisted; default 500 events with a 30-day TTL

### Audit Log

- Every change made through Sentinel (quarantine, protect mode, policy and user changes, and the rest), with who did it, the target, and whether it succeeded. Recorded by middleware on every admin write, so no action route is missed
- Append-only, persisted, capped at 5000 entries, with CSV export. Sign-in attempts (success and wrong credentials) are recorded too

## Dashboard

- **Tetragon Agents** — per-node health (ready / total), red when an agent is not ready or its gRPC stream is not actually delivering events; a banner appears when any source (Tetragon or Hubble) has failed. Full per-source ingestion detail is on the **Event Sources** page
- Security and Admission event counts by severity, updating live, plus Global Protect Mode status
- Recent Tracing Policy, Admission Policy and Network Policy lists
- **Quarantine** — what is currently contained, with who asked and when. The count turns red when it is not zero, because a contained pod is an incident in progress

## Settings

- The running version is shown at the bottom of the sidebar, so a `kubectl rollout restart` can be confirmed from the UI
- **Users** — local accounts with JWT sessions and revocation on logout, Admin / Viewer roles, session timeout. The default admin must change its password on first login; passwords are at least 8 characters, changing your own requires the current one, and failed logins are rate limited per source IP
- **Event Retention** — Security Events (warning and critical caps, TTL 1–90 days) and Admission Events (cap, TTL 1–365 days)
- **Alerts** — push Security and Admission events to Slack, Teams, Discord or any webhook, with filters and cooldown
- **Syslog** — forward events to a rsyslog/syslog server over UDP or TCP

## Things worth knowing before you enforce

Each of these is a real way to cause an outage or to think you are protected when you are not.

- **A whitelist blocks more than it names.** In Cilium an allow section switches the selected endpoint to default-deny for that direction. A policy permitting `app=frontend` on ingress also drops **kubelet's liveness and readiness probes**, which come from the node and match no pod label, and Cilium's own health checks. Add rules for the `host` and `health` entities alongside the one you wanted:

  | Rule | Peer | Why |
  |---|---|---|
  | 1 | Labels `app=frontend` | what you wanted |
  | 2 | Entity `host` | kubelet probes |
  | 3 | Entity `health` | Cilium health checks |

- **Deny rules are L3/L4 only.** Cilium rejects an HTTP rule inside `ingressDeny`/`egressDeny`, which is why the form disables the L7 fields under Blacklist. "Deny POST /admin" has to be expressed as a whitelist of what *is* allowed
- **A drop is not always attributable.** Default-deny drops are caused by the *absence* of an allow rule, so Hubble has no rule to report. Sentinel resolves those by asking which of your policies govern the pod in that direction, and stays silent when none do — the Policy column never shows something that is not in the cluster
- **Global Protect Mode is a switch on live enforcement.** Flipping every Tracing Policy to Monitoring stops them killing anything. The change is recorded in the Audit Log, like every other admin action
- **Tetragon cannot see pre-SNAT inbound addresses.** Its `tcp_connect` kprobe fires after the kernel has rewritten the source, which is why network observation is Cilium's job here and the network templates were removed from Tracing Policy
