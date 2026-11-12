#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Helm (for Tetragon and Trivy Operator, auto-downloaded if absent) ──────────────────

HELM=""

# Sets HELM. Called directly rather than through $(...): the download's cleanup
# trap would otherwise fire when the subshell exits, deleting the binary before
# it is used.
ensure_helm() {
  if [[ -n "${HELM}" ]]; then
    return
  fi
  if command -v helm &>/dev/null; then
    HELM="helm"
    return
  fi

  echo "[helm] not found, downloading to temp dir..."

  local os arch helm_version
  HELM_TMP="$(mktemp -d)"
  trap 'rm -rf "${HELM_TMP}"' EXIT

  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  case "${arch}" in
    x86_64)         arch="amd64" ;;
    aarch64|arm64)  arch="arm64" ;;
  esac

  helm_version="$(curl -fsSL https://api.github.com/repos/helm/helm/releases/latest \
    | grep '"tag_name"' | head -1 | cut -d'"' -f4)"

  curl -fsSL "https://get.helm.sh/helm-${helm_version}-${os}-${arch}.tar.gz" \
    | tar xz -C "${HELM_TMP}"

  HELM="${HELM_TMP}/${os}-${arch}/helm"
}

# ── Tetragon ──────────────────────────────────────────────────────────────────

if kubectl get daemonset tetragon -n kube-system &>/dev/null; then
  echo "[tetragon] already installed, skipping"
else
  echo "[tetragon] not found, installing latest version..."

  ensure_helm

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

# ── Trivy Operator ────────────────────────────────────────────────────────────

# Scans the images of running workloads; the Vulnerabilities page reads its
# reports. Last, so a failure here leaves Sentinel itself installed.
if kubectl get crd vulnerabilityreports.aquasecurity.github.io &>/dev/null; then
  echo "[trivy-operator] already installed, skipping"
else
  echo "[trivy-operator] not found, installing latest version..."

  ensure_helm

  "${HELM}" repo add aqua https://aquasecurity.github.io/helm-charts/ --force-update
  "${HELM}" repo update aqua
  "${HELM}" install trivy-operator aqua/trivy-operator \
    -n trivy-system --create-namespace

  echo "[trivy-operator] waiting for Deployment to be ready..."
  kubectl rollout status deployment/trivy-operator -n trivy-system --timeout=180s
  echo "[trivy-operator] ready"
fi

echo ""
echo "Done. Access via:"
echo "  kubectl port-forward -n sentinel-system svc/sentinel 8080:80"
