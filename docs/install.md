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
  --set hubble.relay.enabled=true \
  --set rollOutCiliumPods=true \
  --set operator.rollOutPods=true
```

Which of these K8s Sentinel actually reads, and which are there for other reasons:

| Flag | Needed by Sentinel | Why |
|---|---|---|
| `hubble.enabled=true` | **Yes — required** | Turns on flow observation, the only source for Network Topology and Cilium policy denials |
| `hubble.relay.enabled=true` | **Yes — required** | Deploys Hubble Relay, which aggregates every node's flows behind one gRPC endpoint. Sentinel connects to `hubble-relay` over gRPC rather than reaching into each agent; without Relay there is no aggregated flow source to read |
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

- **Hubble UI.** Sentinel is the only UI; Relay is required (above) but the UI is not.
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
helm install tetragon cilium/tetragon -n kube-system \
  --set tetragon.grpc.address=0.0.0.0:54321
```

The one required setting is **`tetragon.grpc.address=0.0.0.0:54321`**. Sentinel
collects runtime events over the Tetragon gRPC API, and the agent's default
bind is `localhost:54321` — reachable only from inside the pod. Binding it to
the pod network lets Sentinel connect. (The `deploy/install-job.yaml` and
`deploy/install.sh` installers set this for you.)

> **Upgrading an existing Tetragon?** The installer skips Tetragon when its
> DaemonSet is already present, so it will not reconfigure one installed before
> gRPC collection. Set the address on the running config and restart:
>
> ```bash
> kubectl -n kube-system patch cm tetragon-config --type merge \
>   -p '{"data":{"server-address":"0.0.0.0:54321"}}'
> kubectl -n kube-system rollout restart ds/tetragon
> ```

What attributes events to pods is the agent's Kubernetes metadata enrichment —
`tetragon.enableK8sAPIAccess`, on by default — which fills the `process.pod`
field that Security Events read for namespace, pod and container.

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

**Option A — Kubernetes Job** — installs Tetragon, K8s Sentinel and Trivy
Operator, no local helm needed. Runs in the cluster, so it needs egress to
`helm.cilium.io`, `raw.githubusercontent.com`, `aquasecurity.github.io` and
`github.com`.

```bash
kubectl apply -f deploy/install-job.yaml
kubectl logs -n kube-system job/sentinel-installer -f
```

**Option B — local script** — the same three steps, run from your machine.

```bash
bash deploy/install.sh
```

**Option C — manifests only** — when Tetragon is already installed. One file,
no kustomize. This does not install Trivy Operator; see the next section.

```bash
kubectl apply -f deploy/sentinel.yaml
```

## Vulnerability scanning

The Vulnerabilities page shows what [Trivy Operator](https://github.com/aquasecurity/trivy-operator) finds. Sentinel does not scan images itself, so without the operator the page says scanning is not enabled and everything else works as before.

Options A and B install the operator into `sentinel-system`, next to Sentinel, as the Helm release `trivy-operator`, and skip it when a Trivy Operator Deployment already exists in any namespace. With Option C, or to add it to an existing install, run the same command yourself after `deploy/sentinel.yaml` has created the namespace:

```bash
helm repo add aqua https://aquasecurity.github.io/helm-charts/
helm repo update
helm install trivy-operator aqua/trivy-operator \
  --namespace sentinel-system \
  --values deploy/trivy-operator-values.yaml
```

`deploy/trivy-operator-values.yaml` does three things:

- **Turns off every scanner except the vulnerability scanner.** Sentinel reads `VulnerabilityReport` and nothing else, so configuration audit, RBAC and infrastructure assessment, compliance, exposed-secret scanning and SBOM generation would only add load. The infrastructure assessment also starts a `node-collector` pod with host access on every node
- **Fits the pods to the namespace.** `sentinel-system` enforces the restricted Pod Security level, so the operator and its scan pods run as a non-root user with the default seccomp profile
- **Runs one Trivy server for all scans.** A `trivy-server` pod holds the vulnerability database and the scan cache, and the scan pods are its clients. Left to the chart's default, every scan pod downloads the database for itself, and the containers of one scan pod compete for a single cache lock: the ones that lose fail with `cache may be in use by another process`, and a workload with several images stays partly scanned or not scanned. The server keeps its database in an `emptyDir`, so it needs no StorageClass and downloads the database again after a restart

The operator scans every workload once after it starts and again when a workload changes or a report expires (24 hours by default). Each scan is a short-lived `scan-vulnerabilityreport-*` pod in `sentinel-system`, one per workload with one container per image, at most ten at a time (`operator.scanJobsConcurrentLimit`). A burst of them right after install is the first pass over the cluster; they are removed as they finish. Reports appear as they complete:

```bash
kubectl get vulnerabilityreports -A
```

**Moving an operator installed into `trivy-system` by an earlier version:**

```bash
helm uninstall trivy-operator --namespace trivy-system
kubectl delete namespace trivy-system
bash deploy/install.sh
```

Existing vulnerability reports stay where they are, in the namespaces of the workloads they describe.

**Clearing what the other scanners left behind.** An operator that ever ran with the chart's defaults wrote reports for every scanner, and switching a scanner off does not remove what it already wrote. Nothing reads them now, nothing will expire them, and the SBOM reports alone can outweigh all the vulnerability reports put together. Delete them once:

```bash
kubectl delete sbomreports,configauditreports,exposedsecretreports,rbacassessmentreports,infraassessmentreports --all --all-namespaces
kubectl delete clustersbomreports,clusterconfigauditreports,clusterrbacassessmentreports,clusterinfraassessmentreports --all
```

Leave these alone if you read them with another tool; Sentinel does not use them.

**Upgrading to a version with registry scanning (v0.62.0):** re-apply `deploy/sentinel.yaml`, which adds a Role in `sentinel-system` for the scan Jobs; without it every registry scan fails with a permission error. Then pass the current values to the operator, so it leaves those Jobs alone:

```bash
helm upgrade trivy-operator aqua/trivy-operator \
  --namespace sentinel-system \
  --values deploy/trivy-operator-values.yaml
```

**Workloads that stay partial or not scanned :** an operator installed from an earlier copy of the values file runs without the Trivy server described above. Pass it the current values with the same `helm upgrade` command, then restart it so it scans what is missing:

```bash
kubectl -n sentinel-system rollout restart deployment/trivy-operator
```

**Upgrading Sentinel from a version before the Vulnerabilities page:** re-apply `deploy/sentinel.yaml`. The ClusterRole gained read-only rules for `vulnerabilityreports` and for `jobs`; without the first the page reports that Sentinel is not permitted to read reports.

### Air-gapped clusters

Trivy downloads its vulnerability database as an OCI artifact, and by default pulls it and its own image from `mirror.gcr.io`. In a cluster with no internet access, copy these into a registry the cluster can reach and point the chart at it:

| What | Default location |
|---|---|
| Trivy image | `mirror.gcr.io/aquasec/trivy` |
| Vulnerability database | `mirror.gcr.io/aquasec/trivy-db` |
| Java index database | `mirror.gcr.io/aquasec/trivy-java-db` |

```yaml
trivy:
  image:
    registry: registry.internal.example
  dbRegistry: registry.internal.example
  dbRepository: aquasec/trivy-db
  javaDbRegistry: registry.internal.example
  javaDbRepository: aquasec/trivy-java-db
```

```bash
helm install trivy-operator aqua/trivy-operator \
  --namespace sentinel-system \
  --values deploy/trivy-operator-values.yaml \
  --values trivy-values.yaml
```

Registry scans are started by Sentinel, not by the operator, so they take the same locations from Sentinel's own environment: `TRIVY_IMAGE`, `TRIVY_DB_REPOSITORY` and `TRIVY_JAVA_DB_REPOSITORY` (see [Environment variables](#environment-variables)).

The database is only as current as the copy in your registry, so refresh the mirror on a schedule. The operator's own image and the registries your workloads pull from need the same treatment; the [Trivy Operator documentation](https://aquasecurity.github.io/trivy-operator/) covers private registries and credentials.

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

Default credentials are `admin` / `admin`. The first login is forced to a password change before the console opens, and the new password must be at least 8 characters. Login attempts are rate limited per source IP to slow brute forcing.

## Persistent storage

K8s Sentinel stores the following under `/data/sentinel/` (override with the `DATA_DIR` environment variable).

The bundled manifests mount `/data/sentinel` as an `emptyDir`, which needs no StorageClass and suits evaluation. To keep data across Pod restarts (accounts, alert and syslog settings, custom templates, event history), mount a PersistentVolume instead, as shown below. For a single-instance deployment, also set the Deployment's update strategy to `Recreate` so a rollout does not briefly run two pods that both stream events.

| File | Contents |
|---|---|
| `users.json` | Accounts and session settings |
| `.jwt-secret` | JWT signing secret (skipped entirely when `JWT_SECRET` is set, which keeps sessions valid across restarts even on an `emptyDir`) |
| `templates.json` | Custom policy templates |
| `alerts.json` | Webhook alert rules |
| `rsyslog.json` | Syslog forwarding settings |
| `admission-events.json` | Admission events (default 500, 30-day TTL) |
| `security-events.json` | Security events (default 800, 7-day TTL) |
| `registries.json` | Registries to scan, including their credentials |
| `registry-scans/` | Registry scan results, a directory per registry |

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
| `TETRAGON_GRPC_PORT` | `54321` | Port of the Tetragon agent's gRPC server |
| `HUBBLE_RELAY_ADDRESS` | `hubble-relay.<ns>.svc.cluster.local:80` | Hubble Relay endpoint; the default resolves the namespace Cilium was found in |
| `HUBBLE_RELAY_TLS` / `TETRAGON_GRPC_TLS` | *(unset)* | Set to `true` when the endpoint serves TLS; `*_CA` names a CA file when the certificate is not signed by a system root, and `*_SERVER_NAME` names the identity to verify against (required for the Tetragon agents, which are dialed by pod IP) |
| `AUDIT_WEBHOOK_TOKEN` | *(unset)* | Token the [audit webhook](audit-webhook.md) requires when set, carried at the end of the webhook URL; unset leaves the endpoint open |
| `JWT_SECRET` | *(unset)* | Session-token signing key, at least 32 characters. Inject it from a Kubernetes Secret and sessions survive Pod restarts without a PersistentVolume; unset, the key lives in `DATA_DIR/.jwt-secret` and on an `emptyDir` regenerates on every restart, logging everyone out |
| `TRIVY_IMAGE` | `mirror.gcr.io/aquasec/trivy:0.76.1` | The Trivy image registry scans run |
| `TRIVY_DB_REPOSITORY` / `TRIVY_JAVA_DB_REPOSITORY` | *(Trivy's defaults)* | Where registry scans download the vulnerability databases from; set both to your mirror in an air-gapped cluster |
| `TRUST_PROXY_HEADERS` | *(unset)* | Set to `true` only behind a proxy or ingress that overwrites `X-Forwarded-For`; the login rate limiter and sign-in audit entries then use the forwarded client IP instead of the connection address. Never enable it when clients reach Sentinel directly, since the header is client-controlled |

---

## Resource requirements

| | requests | limits |
|---|---|---|
| CPU | 200m | 500m |
| Memory | 128Mi | 256Mi |

> On larger clusters (more than 5 Tetragon pods) or with dense TracingPolicy rules, raise the CPU limit to around 750m.

---

## RBAC

Sentinel collects events over the Tetragon and Hubble gRPC APIs, so it holds
**no `pods/exec`** — the permission that would let it run any command in any
container. The only write it keeps is `patch` on `pods`, for the quarantine
label; everything else is read-only.

| API Group | Resources | Verbs |
|---|---|---|
| `cilium.io` | `tracingpolicies`, `tracingpoliciesnamespaced` | CRUD |
| `cilium.io` | `ciliumnetworkpolicies`, `ciliumclusterwidenetworkpolicies` | CRUD |
| `cilium.io` | `ciliumnodes` | get, list |
| `admissionregistration.k8s.io` | `validatingadmissionpolicies`, `validatingadmissionpolicybindings` | CRUD |
| `""` (core) | `namespaces` | get, list |
| `""` (core) | `pods`, `pods/log` | get, list, watch, **patch** |
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
| `aquasecurity.github.io` | `vulnerabilityreports` | get, list |
| `batch` | `jobs` | get, list |

Registry scanning adds a **Role in `sentinel-system` only**, for the Trivy Jobs Sentinel starts there:

| API Group | Resources | Verbs |
|---|---|---|
| `batch` | `jobs` | create, get, list, delete |
| `""` (core) | `pods` | get, list |
| `""` (core) | `pods/log` | get |
| `""` (core) | `secrets` | create, delete |

The Secret verbs carry a registry's credentials to its scan pod, so the password is never written into a Job. Sentinel cannot read Secrets.
