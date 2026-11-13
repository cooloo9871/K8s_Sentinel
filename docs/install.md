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
  --set hostNetwork=false \
  --set tetragon.grpc.address=0.0.0.0:54321
kubectl apply -f deploy/tetragon-grpc-policy.yaml
```

- **`tetragon.grpc.address=0.0.0.0:54321`** is required. Sentinel collects runtime events over the Tetragon gRPC API, and by default the agent does not listen anywhere Sentinel can reach from another pod
- **`hostNetwork=false` and the NetworkPolicy** are what keep that API to Sentinel. Tetragon's gRPC server has no authentication and no TLS: whoever can connect reads every process started on the node, command line included, and can list, disable or delete tracing policies. On the host network, which is the chart's default, the port is open on every node's address to every pod in the cluster, and a NetworkPolicy does not apply to it. Off the host network it is an ordinary pod port, and `deploy/tetragon-grpc-policy.yaml` admits only the Sentinel pod. Edit the namespaces in that file if Tetragon or Sentinel is installed elsewhere A NetworkPolicy governs traffic between pods: a process on the node itself, or a pod on the host network of that node, can still reach the port

`deploy/install-job.yaml` and `deploy/install.sh` do all of this for you.

Off the host network Tetragon starts once the node's CNI is up, so the first seconds of a node's boot are not observed.

> **Moving an existing Tetragon off the host network.** The installers skip Tetragon when its DaemonSet is already present, so one installed earlier is still on the host network with its gRPC port open to the cluster. Installed as a Helm release (`helm list -n kube-system` shows `tetragon`):
>
> ```bash
> helm upgrade tetragon cilium/tetragon -n kube-system --reset-then-reuse-values \
>   --set hostNetwork=false \
>   --set tetragon.grpc.address=0.0.0.0:54321
> kubectl apply -f deploy/tetragon-grpc-policy.yaml
> ```
>
> Installed by an earlier `deploy/install.sh`, which applied rendered templates and left no release:
>
> ```bash
> helm template tetragon cilium/tetragon -n kube-system \
>   --set hostNetwork=false \
>   --set tetragon.grpc.address=0.0.0.0:54321 | kubectl apply -f -
> kubectl apply -f deploy/tetragon-grpc-policy.yaml
> ```
>
> Sentinel finds the agents at their new addresses by itself within half a minute. To check, from any other pod: `nc -zv <tetragon pod IP> 54321` must time out.

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
kubectl wait --for=condition=ready pod -l job-name=sentinel-installer -n kube-system --timeout=120s
kubectl logs -n kube-system job/sentinel-installer -f
```

The Job always installs what is on the `main` branch: it fetches `deploy/sentinel.yaml`, `deploy/tetragon-grpc-policy.yaml` and `deploy/trivy-operator-values.yaml` from GitHub and does not read your clone. To install a pinned version or edited manifests, use Option B or C. The Job runs as cluster-admin and removes that binding itself as its last step, once everything is installed; the Job is deleted ten minutes after it finishes. A Job that failed keeps the binding so that it can retry: remove it with `kubectl delete -f deploy/install-job.yaml`.

**Option B — local script** — the same three steps, run from your machine.

```bash
bash deploy/install.sh
```

**Option C — manifests only** — when Tetragon is already installed. One file,
no kustomize. This does not install Trivy Operator; see the next section.

```bash
kubectl apply -f deploy/sentinel.yaml
```

## Offline install

For a cluster with no internet access. Every [release](https://github.com/cooloo9871/K8s_Sentinel/releases) from v0.71.0 on carries two assets:

| Asset | What it is |
|---|---|
| `sentinel-images-<version>.txt` | Every image that release needs: Sentinel, Tetragon, Trivy Operator, Trivy, and Trivy's two vulnerability databases |
| `sentinel-offline-<version>.tar.gz` | The manifests and scripts. It holds no images, so it is small |

The bundle installs the versions the image list names and no others: Tetragon and Trivy Operator are rendered from their charts when the release is built, so the cluster side needs `kubectl` only, not Helm.

**1. On a machine with internet access**, download the bundle and save the images:

```bash
tar xzf sentinel-offline-v0.71.0.tar.gz
cd sentinel-offline-v0.71.0
bash mirror-images.sh save        # about 2 GB, into ./images
```

**2. Carry the directory to the offline side** and push the images to a registry the cluster's nodes pull from:

```bash
bash mirror-images.sh push harbor.example.com/sentinel
```

**3. Install**, on a machine with `kubectl` access to the cluster:

```bash
bash install.sh --registry harbor.example.com/sentinel
```

An image keeps its path under the registry: `quay.io/cilium/tetragon:v1.8.0` becomes `harbor.example.com/sentinel/cilium/tetragon:v1.8.0`. With Harbor, `sentinel` is a project you create first. `bash install.sh --registry ... --render-only out/` writes the manifests it would apply and applies nothing.

What to know before you start:

- **Tools.** `mirror-images.sh` uses `skopeo` when it is installed. Without it, `docker`, `podman` or `nerdctl` carry the images, but not Trivy's databases: those are OCI artifacts, not container images, and need `skopeo` or `oras`. Without the databases in the registry Sentinel installs and runs, and no image can be scanned
- **The registry has to be pullable without credentials** by the nodes and by Trivy, and its certificate trusted by both. The bundle sets no image pull secret. `INSECURE=1 bash mirror-images.sh push ...` is for pushing to a registry on plain HTTP or with a certificate the pushing machine does not trust; it does not change what the cluster trusts
- **CPU architecture.** Images are saved for the architecture of the machine that runs `save`. Run it on one that matches your nodes
- **The vulnerability databases age.** A scan knows the vulnerabilities published up to the day the databases were saved. Run `save` and `push` again on a schedule to refresh them
- **A Tetragon or a Trivy Operator already in the cluster is left as it is**, as with the online installers. For Tetragon, see [Requirements](#requirements) for the gRPC setting Sentinel needs
- **Upgrading** is the same three steps with the new release's bundle. `install.sh` re-applies Sentinel's manifest, so the note under [Vulnerability scanning](#vulnerability-scanning) about re-applying it holds here too
- **Uninstalling** uses the `uninstall.sh` in the bundle; see [Uninstall](#uninstall)

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

`deploy/trivy-operator-values.yaml` does four things:

- **Turns off every scanner except the vulnerability scanner.** Sentinel reads `VulnerabilityReport` and nothing else, so configuration audit, RBAC and infrastructure assessment, compliance, exposed-secret scanning and SBOM generation would only add load. The infrastructure assessment also starts a `node-collector` pod with host access on every node
- **Fits the pods to the namespace.** `sentinel-system` enforces the restricted Pod Security level, so the operator and its scan pods run as a non-root user with the default seccomp profile
- **Runs one Trivy server for all scans.** A `trivy-server` pod holds the vulnerability database and the scan cache, and the scan pods are its clients. Left to the chart's default, every scan pod downloads the database for itself, and the containers of one scan pod compete for a single cache lock: the ones that lose fail with `cache may be in use by another process`, and a workload with several images stays partly scanned or not scanned. The server keeps its database in an `emptyDir`, so it needs no StorageClass and downloads the database again after a restart
- **Gives a scan 15 minutes instead of 5.** Pulling a large image over a slow link can take longer than the chart's default, and a scan that runs out of time is removed without an error in the operator's log: the workload just stays not scanned

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

**Re-applying `deploy/sentinel.yaml` puts back what the file says.** If you changed the Deployment or the Service by editing the file (a PersistentVolumeClaim in place of the `emptyDir`, `AUDIT_WEBHOOK_TOKEN`, a pinned image tag, a `NodePort`), carry those edits into the new file before applying it, or apply your own copy. Applied as it comes, the data volume goes back to `emptyDir`, which is an empty Sentinel with the `admin` / `admin` account, and an audit webhook token set in the file is dropped. Changes made with `kubectl set env` or `kubectl patch`, and a `clusterIP` you chose, are kept.

**Upgrading to v0.70.0, from any version:** re-apply `deploy/sentinel.yaml`, then restart Sentinel. The `VulnerabilityGate` kind gains what the Scanned Images rule and the Not counted list of a Vulnerability Limit read. Without it a Scanned Images policy admits everything and a limit counts every vulnerability, and Sentinel's log says the kind is older than it. From this version the kind keeps fields it does not know, so later versions will not need this step for it. Policies made before v0.70.0 are unchanged and still open in the form.

**Upgrading to v0.69.0:** no manifest change is required. Vulnerability Limit, Blocked CVEs, Host Path Volumes and Environment Variables policies made before it keep working as they were written and open in the YAML editor; make them again in the form to get the corrected rules, of which the first two matter: the earlier ones could be passed by a manifest that names an owner for itself.

**Upgrading to v0.68.0, from any version:** re-apply `deploy/sentinel.yaml`, then restart Sentinel. The `VulnerabilityGate` kind gains the list of named vulnerabilities each image has; without it a Blocked CVEs policy admits everything, and Sentinel's log says the kind is older than it.

**Upgrading to v0.67.0, from any version:** re-apply `deploy/sentinel.yaml`, then restart Sentinel. The `VulnerabilityGate` kind gains the counts of vulnerabilities with a fix available; without them a Vulnerabilities policy set to count only those admits everything, and Sentinel's log says the kind is older than it. Registries scanned before the upgrade have no such counts until their next scan.

**Upgrading to v0.66.0, from any version:** re-apply `deploy/sentinel.yaml`, then restart Sentinel. It defines the `VulnerabilityGate` kind Sentinel keeps its scan counts in, which admission policies made with the Vulnerability Limit rule read; until then such a policy cannot be created, and nothing else is affected. v0.65.0 had this as a page of its own, Deployment Gate: the policy that page made is removed on upgrade, so make it again under Admission Policy.

**Upgrading to a version with registry scanning (v0.62.0):** re-apply `deploy/sentinel.yaml`, which adds a Role in `sentinel-system` for the scan Jobs; without it every registry scan fails with a permission error. Then pass the current values to the operator, so it leaves those Jobs alone:

```bash
helm upgrade trivy-operator aqua/trivy-operator \
  --namespace sentinel-system \
  --values deploy/trivy-operator-values.yaml
```

**Workloads that stay partial or not scanned:** an operator installed from an earlier copy of the values file runs without the Trivy server described above. Pass it the current values with the same `helm upgrade` command, then restart it so it scans what is missing:

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

## Uninstall

```bash
bash deploy/uninstall.sh --dry-run   # shows what would be removed
bash deploy/uninstall.sh             # asks, then removes
```

It removes K8s Sentinel with the `sentinel-system` namespace (settings, accounts and stored events included), Trivy Operator with its Trivy server, Tetragon, and what the installer Job left in `kube-system`. The quarantine policy and the quarantine labels go as well, because a pod left isolated with no Sentinel to release it would stay that way.

| Option | Effect |
|---|---|
| `--dry-run` | Lists what would be deleted and deletes nothing |
| `--keep-tetragon` | Leaves Tetragon alone, for a cluster where it was installed before Sentinel. The NetworkPolicy that limited its gRPC API to Sentinel is still removed, since it would let nobody in |
| `--purge` | Also deletes the tracing, network and admission policies made or edited in Sentinel, every vulnerability report, and the Tetragon and Trivy CRDs |
| `--yes` | Does not ask |

Without `--purge` the policies stay and go on being enforced: network policies by Cilium, admission policies by the API server. The exception is admission policies made with the Vulnerability Limit and Blocked CVEs rules: they go by Sentinel's scan results, which are removed, and admit everything from then on. Tracing policies are kept as objects but do nothing once Tetragon is gone. Set `TETRAGON_NAMESPACE` if Tetragon is not in `kube-system`. A Trivy Operator outside `sentinel-system`, or a Tetragon outside `kube-system` (or `TETRAGON_NAMESPACE`), was not installed by Sentinel and is left alone, with its reports and CRDs. A persistent volume you added for Sentinel's data is deleted with the namespace's claim, subject to its reclaim policy.

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
| `sentinel.io` | `vulnerabilitygates` | get, create, update |
| `""` (core) | `namespaces` | get, list |
| `""` (core) | `pods` | get, list, watch, **patch** |
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
