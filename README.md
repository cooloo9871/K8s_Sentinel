# K8s Sentinel

<p align="center">
  <img src="assets/sentinel-lockup-light.svg" alt="K8s Sentinel" width="340" />
</p>

**K8s Sentinel** is a Kubernetes security management console that runs inside the cluster. It combines Cilium Tetragon runtime monitoring, Cilium network policy enforcement and ValidatingAdmissionPolicy admission control behind one web UI, so you can manage policies, watch security events, route alerts and see live network topology without reaching for `kubectl` or hand-writing YAML.

Each layer does what only it can do:

| Layer | Responsibility |
|---|---|
| **Tracing Policy** (Tetragon) | Process execution and file access, with full process context — it can tell a legitimate server process apart from a cryptominer inside the same pod, and kill it |
| **Network Policy** (Cilium) | Network access control by workload identity — cannot be bypassed by connecting straight to a backend pod IP, covers ingress and egress, drops packets instead of killing processes |
| **Admission Policy** (VAP) | Rejects non-compliant resources before they are admitted to the cluster |

---

## Features

### Policies

#### Tracing Policy

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

#### Network Policy (Cilium)

- Manage **CiliumNetworkPolicy** and **CiliumClusterwideNetworkPolicy** through a form builder, with a raw YAML editor for anything the form cannot express
- A policy is anchored on **one** `endpointSelector`, which is what the form shows: **Applies to**, **Direction** and **Mode** belong to the policy, while each rule contributes a peer with its own ports and HTTP rules
- **Mode** is the choice that matters, and it is named for what it does rather than as Allow/Deny:
  - **Blacklist** — blocks only what the rules name; everything else is untouched. Writes `ingressDeny`/`egressDeny` with `enableDefaultDeny: false` for that direction, so one deny rule does not lock the whole direction down
  - **Whitelist** — permits only what the rules name and **drops everything else** reaching the endpoint, because in Cilium an allow section switches the endpoint to default-deny for that direction
- **Scope** — namespaced, or cluster-wide. A namespaced policy's `endpointSelector` only ever matches its own namespace, so governing pods elsewhere requires `CiliumClusterwideNetworkPolicy`
- Labels are **Key / Value** fields, not free text: a mistyped `app=web` does not fail, it selects nothing
- A peer is either **Labels** or an **Entity** — `world`, `cluster`, `host`, `remote-node` and the rest, for peers that have no labels to select
- **A peer in another namespace has to name it.** A namespaced policy's `toEndpoints`/`fromEndpoints` match only its own namespace, so allowing egress to CoreDNS from another namespace needs the namespace as a label alongside the selector. Add a row keyed `namespace` (or `ns`) and the form writes `io.kubernetes.pod.namespace` — without it the rule selects nothing and the traffic is dropped by the default deny the allow section created
- Ports are rows with a protocol each; **L7 HTTP rules** are a list of alternatives (method and path), and are disabled under Blacklist because Cilium deny rules match on L3/L4 only
- Policies built here carry `sentinel.io/builder: "true"`, so **Edit** reopens the form; anything else opens as YAML, since a hand-written policy can hold rules the form cannot show
- The list shows what is easy to miss in raw YAML: whether a policy carries **L7** rules, and which direction it puts into **default deny**
- Policy denials become Security Events, fire webhook alerts, reach syslog and show as red edges in Network Topology

#### Quarantine

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
  - fromEntities: [host, health]   # the kubelet's probes still get through
egressDeny:
  - toEntities: [all]              # a deny beats any allow
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

#### Admission Policy (ValidatingAdmissionPolicy)

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

### Behavior Discovery

- Learns the processes each pod actually executes from the Tetragon base sensor — **no TracingPolicy required**
- Grouped by Deployment, DaemonSet and StatefulSet
- **Create Policy** prefills a policy form with the observed pod selector and binaries

### Network Topology

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
  | `gateway` | Gateway API `HTTPRoute` / `GRPCRoute` `backendRefs`, including cross-namespace ones |
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

  Known gaps: Gateway API `TCPRoute` / `TLSRoute` / `UDPRoute`, and controller-specific CRDs that are neither Ingress nor Gateway API — Traefik `IngressRoute`, Contour `HTTPProxy`, Emissary `Mapping`, Gloo `VirtualService`, `CiliumEnvoyConfig`. A workload exposed only through one of those carries no badge. A pod receiving external traffic with **no declared exposure path** is flagged red, which catches config drift, a hostPort bypass or an active probe
- **L7 detail** — HTTP method, path and status code on edges where Cilium's proxy is in the path
- Traffic arriving from outside is identified by Cilium's `reserved:world` identity rather than by its address, so a connection SNATed to a node's `cilium_host` still reads as external — labelled **world via `<node>`**, with the detail panel explaining that the address is the node's and how to keep the client's
- **Traffic between two node addresses is never drawn.** It is Cilium's own plumbing — inter-node health probing and tunnel chatter — and never a workload's traffic. Node-to-pod is always shown, because that is how the outside reaches a workload
- **ICMP error messages do not become edges.** An unreachable or time-exceeded report names the *reporter* as the source, so drawing one states the opposite of what happened: a pod whose metadata lookup went nowhere appeared to be receiving traffic from an unknown address. Echo request and reply are kept — a ping is real traffic, and a ping sweep is worth seeing
- **Kubelet probes** are recognised and hidden by default. Detection needs both the source node *and* a port the pod declares, so the same port reached from anywhere else is ordinary traffic. It covers `httpGet` / `tcpSocket` / `grpc` probes, named ports resolved against the container's own declarations, `postStart` and `preStop` httpGet lifecycle hooks, and **native sidecars** — restartable init containers, which is how Istio injects its proxy on Kubernetes 1.29+, and where its readiness probe on 15021 lives. `kubectl port-forward` arrives from the node too and is deliberately **not** hidden: that is a person reaching into a pod

- A **hostNetwork** pod never appears as its own node. It shares the node's IP with the kubelet, the API server and every other hostNetwork pod there, and a flow carries only that address — so attributing one to a particular pod would be a guess. Its traffic shows as the node's
- Dagre auto-layout, pod search, and a namespace filter that takes several at once. Auto refresh every 60 seconds, and it can be turned off. The poll is silent — it does not replace the graph with a loading state, and only redraws when it brings something new, so a count ticking up neither blanks the view nor moves the camera

### Notifications

#### Security Events

- Live stream of Tetragon kprobe events and Cilium policy denials; persisted across restarts
- Warning / Critical severity, with content-based deduplication over 30 seconds. The client-side port is collapsed for that comparison, so a pod retrying a denied destination accumulates a count rather than filling the list
- A network denial names the workload that **attempted** the connection, the same way a process or file event names the pod that acted, and carries its containers. All of them are listed when a pod has several: they share one network namespace, so the flow cannot say which opened the connection
- **Only policies that exist are ever named.** A drop Hubble cannot correlate is attributed by asking which of your policies govern that pod in that direction; if none match, no event is recorded rather than one naming nothing
- Expand a row for the triggering file path, connection endpoints, process UID, policy name, drop reason and more
- **Filters** — search by pod, several namespaces at once, and one panel for **Severity** (Warning, Critical) and **Rule** (Process, File, Network). Every group is multi-select, and nothing ticked in a group means no filter for that group
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

#### Admission Events

- ValidatingAdmissionPolicy violations, with several namespaces selectable at once and one panel for **Severity** and **Source**. The audit log alone is the default view
- **Critical** for `Deny` (request blocked) and **Warning** for `Audit` (request allowed but recorded)
- Sourced from Kubernetes Warning Events (no setup) or the **kube-apiserver audit webhook** (full coverage, setup required)
- 30-second deduplication, persisted; default 500 events with a 30-day TTL

### Dashboard

- **Tetragon Agents** — per-node agent readiness (ready / total), red when any agent is not ready
- Security and Admission event counts by severity, updating live, plus Global Protect Mode status
- Recent Tracing Policy, Admission Policy and Network Policy lists
- **Quarantine** — what is currently contained, with who asked and when. The count turns red when it is not zero, because a contained pod is an incident in progress

### Settings

- The running version is shown at the bottom of the sidebar, so a `kubectl rollout restart` can be confirmed from the UI
- **Users** — local accounts with JWT sessions and revocation on logout, Admin / Viewer roles, session timeout
- **Event Retention** — Security Events (warning and critical caps, TTL 1–90 days) and Admission Events (cap, TTL 1–365 days)
- **Alerts** — push Security and Admission events to Slack, Teams, Discord or any webhook, with filters and cooldown
- **Syslog** — forward events to a rsyslog/syslog server over UDP or TCP

### Things worth knowing before you enforce

Each of these is a real way to cause an outage or to think you are protected when you are not.

- **A whitelist blocks more than it names.** In Cilium an allow section switches the selected endpoint to default-deny for that direction. A policy permitting `app=frontend` on ingress also drops **kubelet's liveness and readiness probes**, which come from the node and match no pod label, and Cilium's own health checks. Add rules for the `host` and `health` entities alongside the one you wanted:

  | Rule | Peer | Why |
  |---|---|---|
  | 1 | Labels `app=frontend` | what you wanted |
  | 2 | Entity `host` | kubelet probes |
  | 3 | Entity `health` | Cilium health checks |

- **Deny rules are L3/L4 only.** Cilium rejects an HTTP rule inside `ingressDeny`/`egressDeny`, which is why the form disables the L7 fields under Blacklist. "Deny POST /admin" has to be expressed as a whitelist of what *is* allowed
- **A drop is not always attributable.** Default-deny drops are caused by the *absence* of an allow rule, so Hubble has no rule to report. Sentinel resolves those by asking which of your policies govern the pod in that direction, and stays silent when none do — the Policy column never shows something that is not in the cluster
- **Global Protect Mode is a switch on live enforcement.** Flipping every Tracing Policy to Monitoring stops them killing anything. There is currently no audit record of who changed it
- **Tetragon cannot see pre-SNAT inbound addresses.** Its `tcp_connect` kprobe fires after the kernel has rewritten the source, which is why network observation is Cilium's job here and the network templates were removed from Tracing Policy

---

## Deployment

### Requirements

- **Kubernetes 1.32+** and a configured `kubectl`. ValidatingAdmissionPolicy is GA from 1.30, and 1.32 is the floor this project is developed and tested against
- **Cilium Tetragon** installed in the cluster (process, file and runtime security)
- **Cilium CNI** with kube-proxy replacement and the Hubble agent (network policy management and Network Topology)

Install Cilium with the settings this project relies on:

```bash
cilium install --version <version> \
  --set kubeProxyReplacement=true \
  --set k8sServiceHost=<api-server-ip> \
  --set k8sServicePort=6443 \
  --set hubble.enabled=true \
  --set rollOutCiliumPods=true \
  --set operator.rollOutPods=true
```

Which of these K8s Sentinel actually reads, and which are there for other reasons:

| Flag | Needed by Sentinel | Why |
|---|---|---|
| `hubble.enabled=true` | **Yes — required** | Opens the agent's observation socket. Sentinel execs `hubble observe` inside `cilium-agent` and reads it directly, which is the only source for Network Topology and Cilium policy denials |
| `kubeProxyReplacement=true` | **Yes** | Cilium's socket-level load balancer rewrites a Service address to the backend pod *before* the flow is observed, so the topology sees the real endpoint. Left to kube-proxy, iptables does the translation after the packet leaves the pod, the flow carries the ClusterIP, and Sentinel drops that edge — a VIP is not an endpoint. It is also what lets Hubble see inbound NodePort traffic before SNAT |
| `k8sServiceHost` / `k8sServicePort` | Indirectly | Not read by Sentinel. Required *by Cilium* once kube-proxy is gone: the agents can no longer reach the API server through a Service VIP |
| `rollOutCiliumPods` / `operator.rollOutPods` | **No** | Nothing to do with Sentinel. They restart the agent and operator on a config change, so a `cilium upgrade` takes effect without a manual rollout — worth having, for its own sake |

**Recommended in addition:**

```bash
  --set hubble.metrics.enableNetworkPolicyCorrelation=true
```

This makes Hubble report *which* policy denied a flow, in `egress_denied_by` / `ingress_denied_by`. It is not required — without it Sentinel resolves the policy by asking which of yours govern that pod in that direction — but correlation is authoritative where the fallback is an inference, and lists one policy where the fallback may list several candidates.

Note what it cannot do: correlation only names a policy for an **explicit** `ingressDeny` / `egressDeny` rule. A whitelist denies by the *absence* of an allow rule, so there is no rule to report and the fallback is used either way. If your policies are mostly whitelists, this flag changes little.

**Not needed at all:**

- **`hubble.tls.enabled`.** Deliberately absent above. It defaults to `true`, Sentinel is unaffected either way — the setting secures Hubble's *network* listener for Relay and remote clients, while Sentinel reads the local socket inside the agent over its own exec channel — and Cilium's own chart calls disabling it "highly discouraged" because the Hubble API exposes potentially sensitive information. Leave it at the default
- **Hubble Relay and Hubble UI.** Sentinel reads the agent socket directly and is the only UI
- **`hubble.metrics`** beyond the correlation flag. Sentinel does not scrape Hubble metrics
- **Tetragon's `podInfo`** — see below

##### Preserving the client source IP

Inbound NodePort traffic forwarded to a pod on **another** node is SNATed to the ingress node's `cilium_host` address, so the original client IP is lost before the flow is observed. Cilium still reports the source identity as `reserved:world`, and Network Topology labels such an edge **world via `<node>`** rather than pretending the node initiated it.

Two ways to keep the real address, if you need it:

```bash
# Simplest: only nodes running a backend pod serve the Service, so nothing is forwarded
kubectl patch svc <name> -p '{"spec":{"externalTrafficPolicy":"Local"}}'
```

```bash
# Or Direct Server Return, which keeps any node able to accept the connection
cilium install --version <version> \
  --set kubeProxyReplacement=true \
  --set loadBalancer.mode=hybrid \
  --set loadBalancer.dsrDispatch=geneve
```

`hybrid` uses DSR for TCP and SNAT for UDP, which avoids DSR's MTU edge cases. `dsrDispatch=geneve` avoids the default IP-option dispatch, which intermediate routers and firewalls sometimes drop. Note that DSR makes the return path asymmetric — a stateful firewall between the client and the cluster may reject it.

Behind an **Ingress or Gateway API**, the client IP is not available at L3/L4 at all: the proxy terminates the connection and opens its own to the backend, so the flow reaching the pod comes from the ingress controller. The client address survives only in `X-Forwarded-For`.

Install Tetragon separately:

```bash
helm repo add cilium https://helm.cilium.io/
helm install tetragon cilium/tetragon -n kube-system
```

No extra settings are needed. What attributes events to pods is the agent's
Kubernetes metadata enrichment — `tetragon.enableK8sAPIAccess`, on by default —
which is what fills the `process.pod` field that Security Events read for
namespace, pod and container.

> `tetragon.podInfo.enabled` is **not** required, despite what earlier versions of
> this file said. That flag enables the `PodInfo` CRD, which maps pod IPs for
> network-event enrichment; K8s Sentinel does not use it. Pod IPs are resolved
> from the Kubernetes API directly, and network observation comes from Hubble.
> The Tetragon manifest bundled in `deploy/tetragon.yaml` runs with
> `enable-pod-info: "false"`.

### Install

```bash
git clone https://github.com/cooloo9871/K8s_Sentinel.git
cd K8s_Sentinel
```

**Option A — Kubernetes Job** — installs Tetragon and K8s Sentinel, no local
helm needed. Runs in the cluster, so it needs egress to `helm.cilium.io` and
`raw.githubusercontent.com`.

```bash
kubectl apply -f deploy/install-job.yaml
kubectl logs -n kube-system job/sentinel-installer -f
```

**Option B — local script** — the same two steps, run from your machine.

```bash
bash deploy/install.sh
```

**Option C — manifests only** — when Tetragon is already installed. One file,
no kustomize:

```bash
kubectl apply -f deploy/sentinel.yaml
```

### Architecture

[`docs/architecture.md`](docs/architecture.md) covers how the pieces fit together
— the two ingestion pipelines, how the topology graph decides what to draw, and
the known limitations.

### Container image

```
ghcr.io/cooloo9871/sentinel:latest
```

Per-version tags are listed under [Releases](https://github.com/cooloo9871/K8s_Sentinel/releases). For production, pin a version in `deploy/sentinel.yaml` (for example `:v0.34.0`) instead of `:latest` so deployments are reproducible.

### Access the UI

```bash
kubectl port-forward -n sentinel-system svc/sentinel 8080:80
# open http://localhost:8080
```

Default credentials are `admin` / `admin` — change the password immediately after the first login.

### Persistent storage

K8s Sentinel stores the following under `/data/sentinel/` (override with the `DATA_DIR` environment variable).

> **The bundled manifests mount an `emptyDir`, which means every restart resets all of it** — accounts back to the default `admin`, alert rules and syslog targets gone, custom templates gone, event history gone. Attach a PersistentVolume before configuring anything you expect to keep. A single-instance deployment should also use `strategy: { type: Recreate }`, so a rollout does not briefly run two pods that both stream events.

| File | Contents |
|---|---|
| `users.json` | Accounts and session settings |
| `.jwt-secret` | JWT signing secret |
| `templates.json` | Custom policy templates |
| `alerts.json` | Webhook alert rules |
| `rsyslog.json` | Syslog forwarding settings |
| `admission-events.json` | Admission events (default 500, 30-day TTL) |
| `security-events.json` | Security events (default 800, 7-day TTL) |

```yaml
volumeMounts:
  - name: data
    mountPath: /data/sentinel
volumes:
  - name: data
    persistentVolumeClaim:
      claimName: sentinel-data
```

> The pod runs as user `sentinel` (UID 10001), so the volume needs `fsGroup: 10001`.

### Admission Events — audit webhook

The kube-apiserver audit webhook gives K8s Sentinel complete VAP violation coverage, including requests rejected straight from `kubectl apply`:

```yaml
# /etc/kubernetes/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Metadata
    verbs: ["create", "update", "patch", "delete"]
    omitStages: ["RequestReceived"]
```

```yaml
# /etc/kubernetes/audit-webhook.yaml
apiVersion: v1
kind: Config
clusters:
  - name: sentinel
    cluster:
      server: http://<sentinel-clusterip>/api/admission-events/webhook
users:
  - name: sentinel
contexts:
  - name: default
    context: { cluster: sentinel, user: sentinel }
current-context: default
```

Add to the kube-apiserver flags:

```
--audit-policy-file=/etc/kubernetes/audit-policy.yaml
--audit-webhook-config-file=/etc/kubernetes/audit-webhook.yaml
--audit-webhook-batch-max-wait=5s
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `DATA_DIR` | `/data/sentinel` | Data directory; a warning is logged at startup if it is not writable |
| `TETRAGON_NAMESPACE` | `kube-system` | Namespace where Tetragon is installed |
| `CILIUM_NAMESPACE` | `kube-system` | Namespace where Cilium is installed |

---

## Resource requirements

| | requests | limits |
|---|---|---|
| CPU | 200m | 500m |
| Memory | 128Mi | 256Mi |

> On larger clusters (more than 5 Tetragon pods) or with dense TracingPolicy rules, raise the CPU limit to around 750m.

---

## RBAC

`create` on `pods/exec` is what reaches the Tetragon and Cilium agents, and
`patch` on `pods` is what applies the quarantine label. Both are broad: `create`
on `pods/exec` means Sentinel can run a command in any container in the cluster,
which is the direct cost of collecting flows by running `hubble observe` inside
cilium-agent.

| API Group | Resources | Verbs |
|---|---|---|
| `cilium.io` | `tracingpolicies`, `tracingpoliciesnamespaced` | CRUD |
| `cilium.io` | `ciliumnetworkpolicies`, `ciliumclusterwidenetworkpolicies` | CRUD |
| `cilium.io` | `ciliumnodes` | get, list |
| `admissionregistration.k8s.io` | `validatingadmissionpolicies`, `validatingadmissionpolicybindings` | CRUD |
| `""` (core) | `namespaces` | get, list |
| `""` (core) | `pods`, `pods/log`, `pods/exec` | get, list, watch, create, **patch** |
| `""` (core) | `events` | get, list, watch |
| `""` (core) | `nodes`, `services` | get, list |
| `discovery.k8s.io` | `endpointslices` | get, list |
| `""` (core) | `configmaps` (`cilium-config`, `kube-proxy`) | get, list |
| `networking.k8s.io` | `ingresses` | get, list |
| `gateway.networking.k8s.io` | `gateways`, `httproutes`, `grpcroutes` | get, list |
| `networking.istio.io` | `virtualservices`, `gateways` | get, list |
| `apps` | `replicasets`, `deployments`, `daemonsets`, `statefulsets` | get, list |

---

## License

[MIT License](LICENSE)
