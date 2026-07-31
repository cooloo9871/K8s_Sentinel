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
- **Process Rules** — control which binaries may execute (whitelist / blacklist)
- **File Rules** — control which paths may be accessed, optionally restricted to reads or writes, with per-rule process exceptions
- Switch each policy between **Monitoring** (observe) and **Protect** (block) mode, or flip every policy at once with **Global Protect Mode**
- **Created By** records who created each policy; resources applied with `kubectl` show as `k8s-apply`
- Form builder and raw YAML editor with round-trip conversion between the two
- **Policy Templates** — built-in and custom, searchable and filterable by scope:
  - **Monitor All Process Executions** — observe process execution across every pod
  - **Monitor All File Access** — observe reads and writes on sensitive paths
  - **Block Egress From Unexpected Binaries** (advanced) — kill processes that open outbound connections unless allow-listed. This is the one network control CiliumNetworkPolicy cannot express, because CNP judges by workload identity and cannot distinguish processes within a pod

#### Network Policy (Cilium)

- Manage **CiliumNetworkPolicy** and **CiliumClusterwideNetworkPolicy** through a list view and YAML editor
- The list surfaces what is easy to miss in raw YAML: whether a policy carries **L7** rules, and which direction it puts into **default deny** — adding any ingress rule silently switches the selected endpoints to ingress default-deny
- Seven starter templates, each enforcing one carrying an explicit warning above the editor:
  - **L7 HTTP Visibility** — route traffic through the Cilium proxy so Hubble reports method, path and status
  - **Namespace Isolation** — accept ingress only from the same namespace
  - **Egress: Cluster DNS Only** — lock a workload down to DNS as a base layer
  - **Egress: FQDN Allowlist** — restrict outbound traffic to named domains
  - **Allow Ingress Controller Only** — prevent direct access that bypasses the routing layer
  - **Deny Egress Outside Cluster** — a direct control against data exfiltration and C2 callbacks
  - **Cluster-wide: Allow DNS Everywhere** — baseline so DNS never becomes the thing that breaks
- Templates are raw YAML on purpose: a network policy mistake causes an outage, so the operator sees exactly what will be applied
- Policy denials become Security Events, fire webhook alerts, reach syslog and show as red edges in Network Topology

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

- **Node kinds** — Pod (purple), Node (grey), External IP (amber). Service ClusterIPs are not drawn: a VIP is an intermediate routing concept, not an endpoint, and under Cilium the destination is already rewritten to the backend pod before the flow is observed
- **Edges** — coloured solid lines for allowed traffic, red dashed lines for policy-denied traffic. Blocked edges survive even a very small event retention setting, because the topology buffer is bounded by TTL rather than event count
- **Aggregated per source/destination pair** with a per-port breakdown in the detail panel, so ephemeral client ports do not fan out into parallel lines
- **Hover focus** — labels appear only on the hovered node's edges and unrelated traffic dims out; **Hide kube-system** (on by default) removes control-plane noise
- **Exposure badges** — pods reachable from outside are marked, with each path listed in the detail panel: NodePort, LoadBalancer, Ingress rule, hostNetwork or hostPort. A pod receiving external traffic with **no declared exposure path** is flagged red, which catches config drift, a hostPort bypass or an active probe
- **L7 detail** — HTTP method, path and status code on edges where Cilium's proxy is in the path
- Real inbound source IPs (pre-SNAT), Dagre auto-layout, namespace and pod filters, 30-second auto refresh

### Notifications

#### Security Events

- Live stream of Tetragon kprobe events and Cilium policy denials; persisted across restarts
- Warning / Critical severity, with content-based deduplication over 30 seconds
- Expand a row for the triggering file path, connection endpoints, process UID, policy name and more
- **Pause / Resume** freezes the view while buffering new events with an unread count
- **Export CSV**
- Default retention: 500 warnings, 300 criticals, 7-day TTL (adjustable in Settings)

#### Admission Events

- ValidatingAdmissionPolicy violations, filterable by source, namespace and severity
- **Critical** for `Deny` (request blocked) and **Warning** for `Audit` (request allowed but recorded)
- Sourced from Kubernetes Warning Events (no setup) or the **kube-apiserver audit webhook** (full coverage, setup required)
- 30-second deduplication, persisted; default 500 events with a 30-day TTL

### Dashboard

- **Tetragon Agents** — per-node agent readiness (ready / total), red when any agent is not ready
- Security and Admission event counts by severity, updating live, plus Global Protect Mode status
- Recent Tracing Policy and Admission Policy lists

### Settings

- **Users** — local accounts with JWT sessions and revocation on logout, Admin / Viewer roles, session timeout
- **Event Retention** — Security Events (warning and critical caps, TTL 1–90 days) and Admission Events (cap, TTL 1–365 days)
- **Alerts** — push Security and Admission events to Slack, Teams, Discord or any webhook, with filters and cooldown
- **Syslog** — forward events to a rsyslog/syslog server over UDP or TCP

---

## Deployment

### Requirements

- Kubernetes 1.26+ and a configured `kubectl`
- **Cilium Tetragon** installed in the cluster (process, file and runtime security)
- **Cilium CNI** with kube-proxy replacement and the Hubble agent (network policy management and Network Topology)

Install Cilium with the settings this project relies on:

```bash
cilium install --version 1.18.3 \
  --set kubeProxyReplacement=true \
  --set k8sServiceHost=<api-server-ip> \
  --set k8sServicePort=6443 \
  --set hubble.enabled=true
```

`kubeProxyReplacement` is what lets Hubble observe NodePort traffic before SNAT, so inbound connections report their real source IP. `hubble.enabled` only opens the agent's local socket — **no Hubble UI or Hubble Relay is needed**, K8s Sentinel reads that socket directly and is the only UI.

Install Tetragon separately:

```bash
helm repo add cilium https://helm.cilium.io/
helm install tetragon cilium/tetragon -n kube-system \
  --set tetragon.podInfo.enabled=true
```

> `tetragon.podInfo.enabled=true` is what attributes events to pods. Without it, Security Events arrive with empty Namespace and Pod fields.

### Install

```bash
git clone https://github.com/cooloo9871/K8s_Sentinel.git
cd K8s_Sentinel
```

**Option A — Kubernetes Job** (no local helm needed)

```bash
kubectl apply -f deploy/install-job.yaml
kubectl logs -n kube-system job/sentinel-installer -f
```

**Option B — local script**

```bash
bash deploy/install.sh
```

### Container image

```
ghcr.io/cooloo9871/sentinel:latest
```

Per-version tags are listed under [Releases](https://github.com/cooloo9871/K8s_Sentinel/releases). For production, pin a version in `deploy/base/deployment.yaml` (for example `:v0.2.0`) instead of `:latest` so deployments are reproducible.

### Access the UI

```bash
kubectl port-forward -n sentinel-system svc/sentinel 8080:80
# open http://localhost:8080
```

Default credentials are `admin` / `admin` — change the password immediately after the first login.

### Persistent storage

K8s Sentinel stores the following under `/data/sentinel/` (override with the `DATA_DIR` environment variable). **Mounting a PersistentVolume is strongly recommended** — without it every setting and event is lost when the pod restarts:

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

| API Group | Resources | Verbs |
|---|---|---|
| `cilium.io` | `tracingpolicies`, `tracingpoliciesnamespaced` | CRUD |
| `cilium.io` | `ciliumnetworkpolicies`, `ciliumclusterwidenetworkpolicies` | CRUD |
| `cilium.io` | `ciliumnodes` | get, list |
| `admissionregistration.k8s.io` | `validatingadmissionpolicies`, `validatingadmissionpolicybindings` | CRUD |
| `""` (core) | `namespaces`, `pods`, `pods/log`, `pods/exec` | get, list, watch, create |
| `""` (core) | `events` | get, list, watch |
| `""` (core) | `nodes`, `services`, `endpoints` | get, list |
| `""` (core) | `configmaps` (`cilium-config`, `kube-proxy`) | get, list |
| `networking.k8s.io` | `ingresses` | get, list |
| `apps` | `replicasets`, `deployments`, `daemonsets`, `statefulsets` | get, list |

---

## License

[MIT License](LICENSE)
