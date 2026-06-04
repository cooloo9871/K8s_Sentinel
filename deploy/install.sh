#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Tetragon ──────────────────────────────────────────────────────────────────
# Manifests are pre-rendered from cilium/tetragon Helm chart v1.7.0.
# To upgrade, run: helm template tetragon cilium/tetragon -n kube-system > deploy/tetragon.yaml

if kubectl get daemonset tetragon -n kube-system &>/dev/null; then
  echo "[tetragon] already installed, skipping"
else
  echo "[tetragon] not found, installing..."
  kubectl apply -f "${SCRIPT_DIR}/tetragon.yaml"
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
