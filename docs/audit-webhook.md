# Admission Events — kube-apiserver audit webhook

Without any setup, Admission Events are sourced from Kubernetes Warning Events,
which only cover violations that raise one. Pointing the kube-apiserver audit
webhook at Sentinel gives complete coverage, including requests rejected
straight from `kubectl apply`.

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

The apiserver posts audit batches to Sentinel's ClusterIP, so this endpoint is
deliberately unauthenticated — it accepts audit events and nothing else. After
changing the flags, the kube-apiserver restarts itself (static pod) and events
start arriving within a few seconds; the **Source** filter on Admission Events
shows which pipeline each event came from.
