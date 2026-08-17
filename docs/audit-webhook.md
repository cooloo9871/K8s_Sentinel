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
    verbs:
      - create
      - update
      - patch
      - delete
    omitStages:
      - RequestReceived
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
    context:
      cluster: sentinel
      user: sentinel
current-context: default
```

Add to the kube-apiserver flags:

```
--audit-policy-file=/etc/kubernetes/audit-policy.yaml
--audit-webhook-config-file=/etc/kubernetes/audit-webhook.yaml
--audit-webhook-batch-max-wait=5s
```

## Protecting the endpoint

The apiserver posts audit batches to Sentinel's ClusterIP, so this endpoint sits
outside the session auth — the apiserver has no session. Left open, anything in
the cluster could forge admission events, and since retention evicts the oldest
first, flooding fakes can push the real ones out. Protect it with a shared
token:

```bash
kubectl -n sentinel-system create secret generic sentinel-audit-webhook \
  --from-literal=token="$(openssl rand -hex 24)"
```

Give Sentinel the token as an environment variable, in the container spec of
`deploy/sentinel.yaml`:

```yaml
        env:
        - name: AUDIT_WEBHOOK_TOKEN
          valueFrom:
            secretKeyRef:
              name: sentinel-audit-webhook
              key: token
```

Then put the same value at the **end of the server URL** in the audit-webhook
kubeconfig:

```yaml
# /etc/kubernetes/audit-webhook.yaml
apiVersion: v1
kind: Config
clusters:
  - name: sentinel
    cluster:
      server: http://<sentinel-clusterip>/api/admission-events/webhook/<the same value>
users:
  - name: sentinel
contexts:
  - name: default
    context:
      cluster: sentinel
      user: sentinel
current-context: default
```

In the URL, not as a kubeconfig `user.token` — **client-go silently refuses to
send bearer tokens to a plain-HTTP server**. No error is raised anywhere: the
apiserver just posts without the token and every delivery is rejected. The URL
is sent as-is, so the token always arrives; Sentinel strips it before access
logging, so it does not end up in its own logs. (A `user.token` does work if
Sentinel is served over TLS — the endpoint accepts it as a bearer token too.)

The apiserver reads this file at startup, so restart it after the change —
editing the webhook kubeconfig alone does not restart the static pod; move its
manifest out and back:

```bash
sudo mv /etc/kubernetes/manifests/kube-apiserver.yaml /tmp/ && sleep 5 && \
  sudo mv /tmp/kube-apiserver.yaml /etc/kubernetes/manifests/
```

With `AUDIT_WEBHOOK_TOKEN` unset the endpoint stays open, so existing setups
keep working — but set it anywhere the cluster runs workloads you do not fully
trust.

## When the tokens do not match

If Sentinel has the token but the audit-webhook kubeconfig does not (or carries
a different value), the apiserver's audit events are rejected and **silently
stop appearing** — the Admission Events page just shows nothing new from the
`audit` source. Two places say why:

Sentinel's own log prints an explicit line, at most once a minute:

```bash
kubectl -n sentinel-system logs deploy/sentinel | grep audit-webhook
# audit-webhook: rejected a request whose bearer token is missing or wrong —
# AUDIT_WEBHOOK_TOKEN is set here, so the kube-apiserver's audit-webhook config
# must carry the same value in its user token (see docs/audit-webhook.md);
# its audit events are NOT being recorded
```

The kube-apiserver logs the failed deliveries on its side (a static pod, so on
the control-plane node):

```bash
kubectl -n kube-system logs kube-apiserver-<node> | grep -i audit
# ... Failed to send audit events ... the server has asked for the client to
# provide credentials
```

After fixing the token in `/etc/kubernetes/audit-webhook.yaml`, restart the
kube-apiserver the same way as above — the audit-webhook kubeconfig is read at
startup. The most common cause of a mismatch is carrying the token as a
kubeconfig `user.token` instead of in the server URL: over plain HTTP,
client-go silently drops bearer tokens, so the apiserver posts with no token
at all and no error anywhere says why. After
changing the flags, the kube-apiserver restarts itself (static pod) and events
start arriving within a few seconds; the **Source** filter on Admission Events
shows which pipeline each event came from.
