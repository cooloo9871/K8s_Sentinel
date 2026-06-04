#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Optional extra Helm flags: EXTRA_HELM_FLAGS=(--set x=y) bash deploy/install.sh
if [ -z "${EXTRA_HELM_FLAGS+x}" ]; then
  EXTRA_HELM_FLAGS=()
fi

# ── Tetragon ──────────────────────────────────────────────────────────────────

if kubectl get daemonset tetragon -n kube-system &>/dev/null; then
  echo "[tetragon] already installed, skipping"
else
  echo "[tetragon] not found, installing via Helm..."
  helm repo add cilium https://helm.cilium.io
  helm repo update
  helm install tetragon "${EXTRA_HELM_FLAGS[@]}" cilium/tetragon -n kube-system
  echo "[tetragon] waiting for DaemonSet to be ready..."
  kubectl rollout status daemonset/tetragon -n kube-system --timeout=120s
  echo "[tetragon] ready"
fi

# ── Sentinel ──────────────────────────────────────────────────────────────────

echo "[sentinel] creating namespace..."
kubectl get namespace sentinel-system &>/dev/null \
  || kubectl create namespace sentinel-system

echo "[sentinel] applying manifests..."
kubectl apply -k "${SCRIPT_DIR}/base/"

echo "[sentinel] waiting for deployment to be ready..."
kubectl rollout status deployment/sentinel -n sentinel-system --timeout=120s

echo ""
echo "Done. Access via:"
echo "  kubectl port-forward -n sentinel-system svc/sentinel 8080:80"
