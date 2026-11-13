#!/usr/bin/env bash
# Builds the offline bundle of one K8s Sentinel release, on a machine with
# internet access and helm:
#
#   bash deploy/offline/build.sh v0.71.0
#
# It writes two files into dist/, both of which go on the release as assets:
#
#   sentinel-offline-v0.71.0.tar.gz   manifests and scripts; no images
#   sentinel-images-v0.71.0.txt       every image the bundle needs
#
# Tetragon and Trivy Operator are rendered from their charts here, so that the
# cluster side needs kubectl and nothing else.
set -euo pipefail

VERSION="${1:?usage: build.sh <version>, e.g. v0.71.0}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY="$(dirname "$HERE")"
ROOT="$(dirname "$DEPLOY")"
# shellcheck disable=SC1091
. "$HERE/versions.env"

NAME="sentinel-offline-$VERSION"
OUT="$ROOT/dist"
B="$OUT/$NAME"
rm -rf "$B"
mkdir -p "$B/manifests"

# The same settings deploy/install.sh installs them with.
helm template tetragon tetragon --repo https://helm.cilium.io --version "$TETRAGON_CHART_VERSION" \
  --namespace kube-system --include-crds \
  --set hostNetwork=false --set tetragon.grpc.address=0.0.0.0:54321 \
  > "$B/manifests/tetragon.yaml"
helm template trivy-operator trivy-operator --repo https://aquasecurity.github.io/helm-charts/ \
  --version "$TRIVY_OPERATOR_CHART_VERSION" --namespace sentinel-system --include-crds \
  --values "$DEPLOY/trivy-operator-values.yaml" \
  > "$B/manifests/trivy-operator.yaml"
cp "$DEPLOY/tetragon-grpc-policy.yaml" "$B/manifests/"

# A value of the operator's configuration, without its quotes.
config() { sed -n "s/^  $1: \"\{0,1\}\([^\"]*\)\"\{0,1\}\$/\1/p" "$B/manifests/trivy-operator.yaml" | head -1; }
trivy_image="$(config trivy.repository):$(config trivy.tag)"
trivy_db="$(config trivy.dbRepository):$TRIVY_DB_TAG"
trivy_java_db="$(config trivy.javaDbRepository):$TRIVY_JAVA_DB_TAG"
case "$trivy_image$trivy_db$trivy_java_db" in
  :*|*::*) echo "build: the Trivy Operator chart no longer says where Trivy and its databases come from" >&2; exit 1 ;;
esac

# Sentinel: this release's image, not "latest", and its registry scans told to
# use the same Trivy and databases as the operator. All three are rewritten to
# the private registry at install time with the rest.
awk -v version="$VERSION" -v trivy="$trivy_image" -v db="$trivy_db" -v javadb="$trivy_java_db" '
  /image: ghcr.io\/cooloo9871\/sentinel:latest/ { sub(/:latest/, ":" version); print; pinned = 1; next }
  /imagePullPolicy: Always/ {
    sub(/Always/, "IfNotPresent"); print
    print "          env:"
    print "            - name: TRIVY_IMAGE"
    print "              value: " trivy
    print "            - name: TRIVY_DB_REPOSITORY"
    print "              value: " db
    print "            - name: TRIVY_JAVA_DB_REPOSITORY"
    print "              value: " javadb
    env = 1; next
  }
  { print }
  END { if (!pinned || !env) { print "build: deploy/sentinel.yaml no longer has the lines this rewrites" > "/dev/stderr"; exit 1 } }
' "$DEPLOY/sentinel.yaml" > "$B/manifests/sentinel.yaml"

# Every image: what a container runs, and the Trivy the operator starts for
# each scan, which is in its configuration and not in any pod spec here.
{
  echo "# K8s Sentinel $VERSION: every image an offline install needs."
  echo "# Tetragon chart $TETRAGON_CHART_VERSION, Trivy Operator chart $TRIVY_OPERATOR_CHART_VERSION."
  {
    grep -h '^ *image: ' "$B"/manifests/*.yaml | sed 's/^ *image: *//; s/"//g'
    echo "$trivy_image"
  } | sort -u
  echo "# artifacts"
  echo "# Trivy's vulnerability databases. They are OCI artifacts, not container"
  echo "# images: docker pull cannot fetch them; skopeo and oras can. They change"
  echo "# daily, and a scan is as current as the copy in your registry."
  echo "$trivy_db"
  echo "$trivy_java_db"
} > "$B/images.txt"

cp "$HERE/install.sh" "$HERE/mirror-images.sh" "$DEPLOY/uninstall.sh" "$B/"
echo "$VERSION" > "$B/VERSION"

# The install rewrites every image to the private registry. Proven here, with
# a registry that does not exist, so that a chart that starts keeping an image
# somewhere this does not look fails the build and not somebody's install.
# Named in the operator's configuration and never fetched: they belong to the
# node and configuration scanners, which deploy/trivy-operator-values.yaml
# turns off.
UNUSED='^\S+:[0-9]+: *(node\.collector\.imageRef|policies\.bundle\.oci\.ref):'
check="$(mktemp -d)"
trap 'rm -rf "$check"' EXIT
bash "$B/install.sh" --registry offline.invalid/mirror --render-only "$check" >/dev/null
if left="$(grep -nE '(quay\.io|ghcr\.io|gcr\.io|docker\.io|registry\.k8s\.io|public\.ecr\.aws)/[a-z0-9]' "$check"/*.yaml | grep -vE '^\S+:[0-9]+: *(#|description:)' | grep -v 'offline.invalid' | grep -vE "$UNUSED")" && [ -n "$left" ]; then
  echo "build: these would still be pulled from the internet:" >&2
  echo "$left" >&2
  exit 1
fi

tar -C "$OUT" -czf "$OUT/$NAME.tar.gz" "$NAME"
cp "$B/images.txt" "$OUT/sentinel-images-$VERSION.txt"
echo "built:"
echo "  $OUT/$NAME.tar.gz"
echo "  $OUT/sentinel-images-$VERSION.txt"
