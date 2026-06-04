#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Pin a specific Tetragon version or leave empty for latest
# Usage: TETRAGON_VERSION=v1.2.0 bash deploy/install.sh
TETRAGON_VERSION="${TETRAGON_VERSION:-}"

# ── Tetragon ──────────────────────────────────────────────────────────────────

if kubectl get daemonset tetragon -n kube-system &>/dev/null; then
  echo "[tetragon] already installed, skipping"
else
  echo "[tetragon] not found, installing via YAML..."

  if [ -n "${TETRAGON_VERSION}" ]; then
    MANIFEST_URL="https://github.com/cilium/tetragon/releases/download/${TETRAGON_VERSION}/tetragon.yaml"
  else
    MANIFEST_URL="https://github.com/cilium/tetragon/releases/latest/download/tetragon.yaml"
  fi

  echo "[tetragon] applying ${MANIFEST_URL}"
  kubectl apply -f "${MANIFEST_URL}"

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
