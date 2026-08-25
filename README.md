# K8s Sentinel

<p align="center">
  <img src="assets/sentinel-lockup-light.svg" alt="K8s Sentinel" width="340" />
</p>

**K8s Sentinel** is a Kubernetes security console that runs inside the cluster. It puts Cilium Tetragon runtime monitoring, Cilium network policy enforcement and ValidatingAdmissionPolicy admission control behind one web UI — manage policies, watch security events, route alerts and see live network topology without hand-writing YAML.

Each layer does what only it can do:

| Layer | Responsibility |
|---|---|
| **Tracing Policy** (Tetragon) | Process execution and file access, with full process context — it can tell a legitimate server process apart from a cryptominer inside the same pod, and kill it |
| **Network Policy** (Cilium) | Network access control by workload identity — cannot be bypassed by connecting straight to a pod IP; drops packets instead of killing processes |
| **Admission Policy** (VAP) | Rejects non-compliant resources before they are admitted to the cluster |

## Features

- **Tracing Policy** — process whitelists/blacklists and file access rules through a form builder, with Monitoring / Protect modes and a global switch
- **Network Policy** — CiliumNetworkPolicy builder with ingress and egress in one policy, whitelist/blacklist per direction, cross-namespace peers and L7 HTTP rules
- **Admission Policy** — a CEL builder covering seven rule types (labels, annotations, images, replicas, resource limits, security context, host access), plus bindings
- **Quarantine** — cut a suspect pod off from the network without killing it, so the evidence survives; one click from a Security Event, one to release
- **Behavior Discovery** — learns what each workload actually executes, and turns it into a policy prefill
- **Network Topology** — live connection graph from Hubble flows: policy denials in red with the denying policy named, exposure paths traced hop by hop, quarantined pods marked
- **Security & Admission Events** — persisted, deduplicated, filterable, exportable; webhook alerts (Slack / Teams / Discord) and syslog forwarding fire once per event
- **Audit Log** — every administrative action recorded (who did what, when), filterable, with CSV export
- **Event Sources** — live ingestion health per source, so a Tetragon agent that is Ready but whose gRPC stream is not actually delivering shows as down rather than falsely healthy
- **Dashboard & Settings** — agent and ingestion health, event counts, quarantine status; local accounts with Admin / Viewer roles (forced first-login password change, per-IP login rate limiting), retention tuning

## Quick start

Requires **Kubernetes 1.32+**, **Cilium** (kube-proxy replacement + Hubble Relay), and **Tetragon** with its gRPC server on the pod network — setup details in [docs/install.md](docs/install.md).

```bash
git clone https://github.com/cooloo9871/K8s_Sentinel.git && cd K8s_Sentinel

# Installs Tetragon and Sentinel from inside the cluster
kubectl apply -f deploy/install-job.yaml

kubectl port-forward -n sentinel-system svc/sentinel 8080:80
# open http://localhost:8080 — admin / admin, change it on first login
```

Image: `ghcr.io/cooloo9871/sentinel` — pin a [release tag](https://github.com/cooloo9871/K8s_Sentinel/releases) in production.

## Documentation

| Doc | Covers |
|---|---|
| [docs/install.md](docs/install.md) | Cilium and Tetragon setup with the flags explained, install options, persistent storage, environment variables, resources, RBAC |
| [docs/audit-webhook.md](docs/audit-webhook.md) | Wiring the kube-apiserver audit log to Sentinel for full admission-event coverage |
| [docs/features.md](docs/features.md) | Every feature in detail, and what to know before switching on enforcement |
| [docs/architecture.md](docs/architecture.md) | How the pieces fit together — ingestion pipelines, topology decisions, known limitations |

## License

[MIT License](LICENSE)
