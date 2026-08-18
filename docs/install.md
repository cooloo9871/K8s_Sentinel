# Installation

How to set up Cilium and Tetragon the way K8s Sentinel expects, install Sentinel
itself, and run it with persistent storage. The kube-apiserver audit-webhook
integration has [its own page](audit-webhook.md).

## Requirements

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

### Preserving the client source IP

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

## Install

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

## Container image

```
ghcr.io/cooloo9871/sentinel:latest
```

Per-version tags are listed under [Releases](https://github.com/cooloo9871/K8s_Sentinel/releases). For production, pin a version in `deploy/sentinel.yaml` (for example `:v0.34.0`) instead of `:latest` so deployments are reproducible.

## Access the UI

```bash
kubectl port-forward -n sentinel-system svc/sentinel 8080:80
# open http://localhost:8080
```

Default credentials are `admin` / `admin` — change the password immediately after the first login.

## Persistent storage

K8s Sentinel stores the following under `/data/sentinel/` (override with the `DATA_DIR` environment variable).

> **The bundled manifests mount an `emptyDir`, which means every restart resets all of it** — accounts back to the default `admin`, alert rules and syslog targets gone, custom templates gone, event history gone. Attach a PersistentVolume before configuring anything you expect to keep. A single-instance deployment should also set the Deployment's update strategy to `Recreate`, so a rollout does not briefly run two pods that both stream events.

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

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `DATA_DIR` | `/data/sentinel` | Data directory; a warning is logged at startup if it is not writable |
| `TETRAGON_NAMESPACE` | `kube-system` | Namespace where Tetragon is installed |
| `CILIUM_NAMESPACE` | `kube-system` | Namespace where Cilium is installed |
| `AUDIT_WEBHOOK_TOKEN` | *(unset)* | Token the [audit webhook](audit-webhook.md) requires when set, carried at the end of the webhook URL; unset leaves the endpoint open |

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
| `gateway.networking.k8s.io` | `gateways`, `httproutes`, `grpcroutes`, `tcproutes`, `tlsroutes`, `udproutes` | get, list |
| `traefik.io`, `traefik.containo.us` | `ingressroutes`, `ingressroutetcps`, `ingressrouteudps` | get, list |
| `projectcontour.io` | `httpproxies` | get, list |
| `networking.istio.io` | `virtualservices`, `gateways` | get, list |
| `apps` | `replicasets`, `deployments`, `daemonsets`, `statefulsets` | get, list |
