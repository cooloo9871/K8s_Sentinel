#!/usr/bin/env bash
# Installs K8s Sentinel, Tetragon and Trivy Operator on a cluster with no
# internet access, from a private registry that mirror-images.sh has filled.
# Needs kubectl and nothing else.
#
#   bash install.sh --registry harbor.example.com/sentinel
#   bash install.sh --registry harbor.example.com/sentinel --insecure-registry
#   bash install.sh --registry harbor.example.com/sentinel --render-only out/
#
# --registry is where the images are: a registry host, with a project or path
# under it if you use one. An image keeps its path there, so
# quay.io/cilium/tetragon:v1.8.0 is looked for at
# harbor.example.com/sentinel/cilium/tetragon:v1.8.0.
#
# --render-only writes the manifests it would apply into a directory and
# applies nothing: to read them first, or to apply them your own way.
#
# --insecure-registry is for a registry whose certificate is signed by a CA
# of your own, or that serves plain HTTP. Trivy, which downloads its
# vulnerability databases from the registry, then verifies no certificate, of
# this registry or of any it scans. It does nothing for the nodes: their
# container runtime has to trust the registry by its own configuration.
#
# The nodes have to be able to pull from the registry without credentials.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRY=""
RENDER_ONLY=""
INSECURE=false
while [ $# -gt 0 ]; do
  case "$1" in
    --registry) REGISTRY="${2:-}"; shift 2 ;;
    --registry=*) REGISTRY="${1#*=}"; shift ;;
    --render-only) RENDER_ONLY="${2:-}"; shift 2 ;;
    --render-only=*) RENDER_ONLY="${1#*=}"; shift ;;
    --insecure-registry) INSECURE=true; shift ;;
    -h|--help) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
REGISTRY="${REGISTRY%/}"
case "$REGISTRY" in
  "") echo "--registry is required: where mirror-images.sh pushed the images" >&2; exit 2 ;;
  *://*) echo "--registry is a host and path, without http:// or https://" >&2; exit 2 ;;
  *[!A-Za-z0-9._:/-]*) echo "--registry has a character an image reference cannot hold" >&2; exit 2 ;;
esac

# The manifests, with every image moved to the registry. An image is known by
# its repository, the reference without its tag, which is also how the Trivy
# Operator's configuration names the ones it starts itself.
if [ -n "$RENDER_ONLY" ]; then
  WORK="$RENDER_ONLY"
  mkdir -p "$WORK"
else
  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT
fi
script="$WORK/.rewrite.sed"
: > "$script"
grep -v '^#' "$HERE/images.txt" | grep -v '^ *$' | while read -r ref; do
  repo="${ref%@*}"
  # A colon after the last slash is a tag; before it, a registry port.
  case "${repo##*/}" in *:*) repo="${repo%:*}" ;; esac
  echo "s#${repo}\\([\":@ ]\\|\$\\)#${REGISTRY}/${repo#*/}\\1#g" >> "$script"
done
for f in "$HERE"/manifests/*.yaml; do
  sed -f "$script" "$f" > "$WORK/$(basename "$f")"
done
rm -f "$script"

if $INSECURE; then
  # The operator's own download of the databases, the Trivy server's, and the
  # scan pods reading images from this registry: three settings, one each.
  host="${REGISTRY%%/*}"
  sed -i \
    -e 's#^\(  trivy\.dbRepositoryInsecure:\) .*#\1 "true"\n  trivy.insecureRegistry.mirror: "'"$host"'"#' \
    -e 's#^\(  TRIVY_INSECURE:\) .*#\1 "true"#' \
    "$WORK/trivy-operator.yaml"
  # Sentinel's registry scans.
  sed -i 's#^\( *\)- name: TRIVY_IMAGE$#\1- name: TRIVY_INSECURE\n\1  value: "true"\n&#' "$WORK/sentinel.yaml"
  for want in 'trivy.dbRepositoryInsecure: "true"' 'trivy.insecureRegistry.mirror:' 'TRIVY_INSECURE: "true"'; do
    grep -q "^  $want" "$WORK/trivy-operator.yaml" || { echo "--insecure-registry: could not set $want" >&2; exit 1; }
  done
  grep -q 'name: TRIVY_INSECURE' "$WORK/sentinel.yaml" || { echo "--insecure-registry: could not set TRIVY_INSECURE for Sentinel" >&2; exit 1; }
fi

if [ -n "$RENDER_ONLY" ]; then
  echo "Manifests written to $WORK; nothing was applied."
  exit 0
fi

# ── Tetragon ──────────────────────────────────────────────────────────────────
# Asked on its own line: a kubectl that failed must not read as "not installed".
existing_tetragon="$(kubectl get daemonset -A -l app.kubernetes.io/name=tetragon -o name)"
if [ -n "$existing_tetragon" ]; then
  echo "[tetragon] already installed, skipping"
else
  echo "[tetragon] installing"
  kubectl apply -f "$WORK/tetragon.yaml"
  kubectl rollout status daemonset/tetragon -n kube-system --timeout=300s
fi
kubectl apply -f "$WORK/tetragon-grpc-policy.yaml"

# ── Sentinel ──────────────────────────────────────────────────────────────────
echo "[sentinel] installing"
kubectl apply -f "$WORK/sentinel.yaml"
kubectl rollout status deployment/sentinel -n sentinel-system --timeout=300s

# ── Trivy Operator ────────────────────────────────────────────────────────────
existing_operator="$(kubectl get deployment -A -l app.kubernetes.io/name=trivy-operator -o name)"
if [ -n "$existing_operator" ]; then
  echo "[trivy-operator] already installed, skipping"
else
  echo "[trivy-operator] installing"
  # Server side: its CRDs are too large for the annotation a plain apply keeps.
  kubectl apply --server-side --force-conflicts -f "$WORK/trivy-operator.yaml"
  kubectl rollout status deployment/trivy-operator -n sentinel-system --timeout=300s
fi

echo ""
echo "Done. Access via:"
echo "  kubectl port-forward -n sentinel-system svc/sentinel 8080:80"
