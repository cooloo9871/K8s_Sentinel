#!/usr/bin/env bash
# Removes what deploy/install.sh and deploy/install-job.yaml installed:
# K8s Sentinel, Trivy Operator and Tetragon.
#
#   bash deploy/uninstall.sh                 # asks before doing anything
#   bash deploy/uninstall.sh --dry-run       # shows what would be removed
#   bash deploy/uninstall.sh --keep-tetragon # Tetragon was here before Sentinel
#   bash deploy/uninstall.sh --purge         # also policies, reports and CRDs
#   bash deploy/uninstall.sh --yes           # no question
#
# Without --purge the security policies stay: tracing policies, network
# policies and admission policies made in Sentinel are yours and go on being
# enforced (network and admission policies by Cilium and the API server;
# tracing policies only while Tetragon runs). Vulnerability reports and the
# CRDs stay too.
set -euo pipefail

DRY_RUN=false
KEEP_TETRAGON=false
PURGE=false
ASSUME_YES=false
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --keep-tetragon) KEEP_TETRAGON=true ;;
    --purge) PURGE=true ;;
    --yes|-y) ASSUME_YES=true ;;
    -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

SENTINEL_NS="sentinel-system"
TETRAGON_NS="${TETRAGON_NAMESPACE:-kube-system}"

# kubectl delete that never fails the script on "not there", and only reports
# under --dry-run.
del() {
  if $DRY_RUN; then
    kubectl delete "$@" --ignore-not-found --dry-run=server
  else
    kubectl delete "$@" --ignore-not-found
  fi
}

# True when the API serves the resource; a CRD that is not installed would
# otherwise turn every get into an error.
served() { kubectl get "$1" -A --ignore-not-found -o name >/dev/null 2>&1; }

# Removes a Helm release. Without helm on this machine, or for a Tetragon that
# an earlier install.sh applied as plain manifests, it removes the objects by
# the instance label the chart puts on them, and the release records with them.
remove_release() {
  local name="$1" ns="$2"
  if command -v helm >/dev/null 2>&1 && helm status "$name" -n "$ns" >/dev/null 2>&1; then
    if $DRY_RUN; then
      echo "would run: helm uninstall $name -n $ns"
    else
      helm uninstall "$name" -n "$ns" --wait
    fi
    return
  fi
  local sel="app.kubernetes.io/instance=$name"
  del daemonset,deployment,statefulset,service,configmap,secret,serviceaccount,role,rolebinding,podmonitor,servicemonitor \
    -n "$ns" -l "$sel" 2>/dev/null \
    || del daemonset,deployment,statefulset,service,configmap,secret,serviceaccount,role,rolebinding -n "$ns" -l "$sel"
  del clusterrole,clusterrolebinding -l "$sel"
  del secret -n "$ns" -l "owner=helm,name=$name"
}

echo "This removes from the cluster $(kubectl config current-context 2>/dev/null || echo '(current context)'):"
echo "  - K8s Sentinel and the namespace $SENTINEL_NS, with its settings, accounts and events"
echo "  - Trivy Operator and its Trivy server"
$KEEP_TETRAGON || echo "  - Tetragon in $TETRAGON_NS"
if $PURGE; then
  echo "  - the policies made in Sentinel, every vulnerability report, and the Tetragon and Trivy CRDs"
else
  echo "Policies, vulnerability reports and CRDs are kept (--purge removes them)."
fi
$DRY_RUN && echo "Dry run: nothing is deleted."

if ! $ASSUME_YES && ! $DRY_RUN; then
  read -r -p "Continue? [y/N] " answer
  case "$answer" in y|Y|yes|YES) ;; *) echo "Nothing was removed."; exit 0 ;; esac
fi

# ── Quarantine ────────────────────────────────────────────────────────────────
# The quarantine policy cuts labelled pods off the network. Left behind with no
# Sentinel to release them, it would isolate those pods for good.
if served ciliumclusterwidenetworkpolicies; then
  echo "[quarantine] removing the quarantine policy and its pod labels"
  del ciliumclusterwidenetworkpolicy sentinel-quarantine
  if ! $DRY_RUN; then
    kubectl get pods -A -l sentinel.io/quarantine -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{"\n"}{end}' 2>/dev/null \
      | while read -r ns pod; do
          if [ -n "$pod" ]; then
            kubectl label pod -n "$ns" "$pod" sentinel.io/quarantine- >/dev/null
            kubectl annotate pod -n "$ns" "$pod" sentinel.io/quarantined-by- sentinel.io/quarantined-at- >/dev/null
          fi
        done || true
  fi
fi

# ── Policies made in Sentinel (--purge) ───────────────────────────────────────
# Before Tetragon and the CRDs go, while the objects can still be listed.
if $PURGE; then
  echo "[policies] removing the policies made in Sentinel"
  for kind in tracingpolicies tracingpoliciesnamespaced ciliumnetworkpolicies ciliumclusterwidenetworkpolicies \
              validatingadmissionpolicies validatingadmissionpolicybindings; do
    served "$kind" || continue
    kubectl get "$kind" -A -o jsonpath='{range .items[*]}{.metadata.annotations.sentinel\.io/created-by}{"|"}{.metadata.namespace}{"|"}{.metadata.name}{"\n"}{end}' 2>/dev/null \
      | while IFS='|' read -r by ns name; do
          if [ -z "$by" ] || [ -z "$name" ]; then continue; fi
          if [ -n "$ns" ]; then del "$kind" -n "$ns" "$name"; else del "$kind" "$name"; fi
        done || true
  done
fi

# ── Trivy Operator ────────────────────────────────────────────────────────────
echo "[trivy-operator] removing"
remove_release trivy-operator "$SENTINEL_NS"
# Scan Jobs the operator or a registry scan left running.
del job -n "$SENTINEL_NS" --all

# ── Sentinel ──────────────────────────────────────────────────────────────────
echo "[sentinel] removing"
del clusterrolebinding sentinel
del clusterrole sentinel
del namespace "$SENTINEL_NS"

# What deploy/install-job.yaml leaves in kube-system.
del job -n kube-system sentinel-installer
del clusterrolebinding sentinel-installer
del serviceaccount -n kube-system sentinel-installer

# ── Tetragon ──────────────────────────────────────────────────────────────────
if $KEEP_TETRAGON; then
  echo "[tetragon] kept"
else
  echo "[tetragon] removing"
  del networkpolicy -n "$TETRAGON_NS" tetragon-grpc
  remove_release tetragon "$TETRAGON_NS"
fi

# ── Reports and CRDs (--purge) ────────────────────────────────────────────────
if $PURGE; then
  echo "[crds] removing reports and CRDs"
  crds="$(kubectl get crd -o name 2>/dev/null | grep -E '\.aquasecurity\.github\.io$' || true)"
  if ! $KEEP_TETRAGON; then
    crds="$crds $(kubectl get crd -o name 2>/dev/null | grep -E '/(tracingpolicies|tracingpoliciesnamespaced|podinfo)\.cilium\.io$' || true)"
  fi
  # shellcheck disable=SC2086
  if [ -n "${crds// /}" ]; then del $crds; fi
fi

if $DRY_RUN; then
  echo "Dry run finished: nothing was deleted."
else
  echo "Done."
  kubectl get pods -A 2>/dev/null | grep -E "sentinel|trivy|tetragon" || echo "No Sentinel, Trivy or Tetragon pods remain."
fi
