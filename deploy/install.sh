#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Helm (used only for Tetragon, auto-downloaded if absent) ──────────────────

find_or_download_helm() {
  if command -v helm &>/dev/null; then
    echo "helm"
    return
  fi

  echo "[helm] not found, downloading to temp dir..." >&2

  local os arch helm_version tmp_dir
  tmp_dir="$(mktemp -d)"
  trap "rm -rf '${tmp_dir}'" RETURN

  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  case "${arch}" in
    x86_64)         arch="amd64" ;;
    aarch64|arm64)  arch="arm64" ;;
  esac

  helm_version="$(curl -fsSL https://api.github.com/repos/helm/helm/releases/latest \
    | grep '"tag_name"' | head -1 | cut -d'"' -f4)"

  curl -fsSL "https://get.helm.sh/helm-${helm_version}-${os}-${arch}.tar.gz" \
    | tar xz -C "${tmp_dir}"

  # Copy binary out of temp (trap deletes tmp_dir on RETURN, so copy first)
  local bin_dir
  bin_dir="$(mktemp -d)"
  cp "${tmp_dir}/${os}-${arch}/helm" "${bin_dir}/helm"
  chmod +x "${bin_dir}/helm"

  # Register cleanup of bin_dir on script exit
  trap "rm -rf '${bin_dir}'" EXIT

  echo "${bin_dir}/helm"
}

# ── Tetragon ──────────────────────────────────────────────────────────────────

if kubectl get daemonset tetragon -n kube-system &>/dev/null; then
  echo "[tetragon] already installed, skipping"
else
  echo "[tetragon] not found, installing latest version..."

  HELM="$(find_or_download_helm)"

  "${HELM}" repo add cilium https://helm.cilium.io --force-update
  "${HELM}" repo update cilium
  # Expose the Tetragon gRPC server on the pod network (default is localhost),
  # so Sentinel can collect events over it instead of kubectl exec.
  "${HELM}" template tetragon cilium/tetragon -n kube-system \
    --set tetragon.grpc.address=0.0.0.0:54321 | kubectl apply -f -

  echo "[tetragon] waiting for DaemonSet to be ready..."
  kubectl rollout status daemonset/tetragon -n kube-system --timeout=120s
  echo "[tetragon] ready"
fi

# ── Sentinel ──────────────────────────────────────────────────────────────────

# The namespace is the first document in the manifest, so there is nothing to
# create up front.
echo "[sentinel] applying manifests..."
kubectl apply -f "${SCRIPT_DIR}/sentinel.yaml"

echo "[sentinel] waiting for deployment to be ready..."
kubectl rollout status deployment/sentinel -n sentinel-system --timeout=120s

echo ""
echo "Done. Access via:"
echo "  kubectl port-forward -n sentinel-system svc/sentinel 8080:80"
