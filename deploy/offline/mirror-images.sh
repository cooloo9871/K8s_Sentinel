#!/usr/bin/env bash
# Carries the images in images.txt from the internet into a private registry,
# with docker or podman, whichever this machine has.
#
# On a machine with internet access:
#   bash mirror-images.sh save                  # downloads into ./images
#
# Take this directory to the offline side, then, on a machine that reaches the
# registry and is logged in to it (docker login, podman login):
#   bash mirror-images.sh push harbor.example.com/sentinel
#
# A machine that reaches both can do it in one go:
#   bash mirror-images.sh save && bash mirror-images.sh push harbor.example.com/sentinel
#
# --insecure-registry, after "push", is for a registry on plain HTTP or with a
# certificate this machine does not trust:
#   bash mirror-images.sh push harbor.example.com/sentinel --insecure-registry
# docker has no such switch for images: the registry has to be listed under
# insecure-registries in its daemon's configuration as well.
#
# docker is used when both are installed. CONTAINER_CLI names the command to
# use instead ("podman", "sudo podman").
#
# Images are saved for this machine's CPU architecture. Run "save" on a machine
# of the architecture your nodes have.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIST="$HERE/images.txt"
DIR="${IMAGES_DIR:-$HERE/images}"

# Trivy's databases are OCI artifacts, which neither docker nor podman can pull
# or push as they do images. skopeo can, and is run from this image, which
# "save" takes along with the rest so that "push" has it offline.
SKOPEO_IMAGE="quay.io/skopeo/stable:v1.18"

usage() { sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

# INSECURE=1 in the environment does the same as the option.
INSECURE="${INSECURE:-}"
MODE=""
REGISTRY=""
for arg in "$@"; do
  case "$arg" in
    --insecure-registry) INSECURE=1 ;;
    -h|--help) usage ;;
    -*) echo "unknown option: $arg" >&2; exit 2 ;;
    *)
      if [ -z "$MODE" ]; then MODE="$arg"
      elif [ -z "$REGISTRY" ]; then REGISTRY="$arg"
      else echo "unexpected argument: $arg" >&2; exit 2
      fi ;;
  esac
done
REGISTRY="${REGISTRY%/}"
case "$MODE" in
  save) ;;
  push)
    case "$REGISTRY" in
      "") echo "push needs the registry to push to" >&2; exit 2 ;;
      *://*) echo "the registry is a host and path, without http:// or https://" >&2; exit 2 ;;
    esac ;;
  *) usage 2 ;;
esac

CLI="${CONTAINER_CLI:-}"
if [ -z "$CLI" ]; then
  for c in docker podman; do
    if command -v "$c" >/dev/null 2>&1; then CLI="$c"; break; fi
  done
fi
if [ -z "$CLI" ]; then
  echo "neither docker nor podman is installed on this machine" >&2
  exit 1
fi
case "$CLI" in *podman*) PODMAN=1 ;; *) PODMAN="" ;; esac
echo "using $CLI"

# An image where the registry keeps it: the same path, under the registry.
target() { echo "$REGISTRY/${1#*/}"; }
# A file name for a reference.
file() { echo "$1" | tr '/:@' '___'; }

# Where the login to the registry is kept, for skopeo to push with it.
authfile() {
  if [ -n "${REGISTRY_AUTH_FILE:-}" ]; then
    echo "$REGISTRY_AUTH_FILE"
  elif [ -n "$PODMAN" ]; then
    echo "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/containers/auth.json"
  else
    echo "${DOCKER_CONFIG:-$HOME/.docker}/config.json"
  fi
}

# skopeo, from its image, with the images directory at /work.
# shellcheck disable=SC2086  # CLI may be two words
skopeo() {
  local auth mount=()
  auth="$(authfile)"
  if [ "$1" = copy ] && [ "$MODE" = push ] && [ -f "$auth" ]; then
    mount=(-v "$auth:/auth.json:ro,z")
    set -- copy --authfile /auth.json "${@:2}"
  fi
  $CLI run --rm --network host -v "$DIR:/work:z" "${mount[@]}" "$SKOPEO_IMAGE" "$@"
}

# shellcheck disable=SC2086
save_image() {
  local ref="$1" out="$DIR/$(file "$1").tar"
  rm -f "$out"
  $CLI pull -q "$ref" >/dev/null
  $CLI save -o "$out" "$ref"
}

# shellcheck disable=SC2086
push_image() {
  local ref="$1" in="$DIR/$(file "$1").tar" to
  to="$(target "$1")"
  [ -f "$in" ] || { echo "$in is missing: run \"save\" first" >&2; exit 1; }
  $CLI load -q -i "$in" >/dev/null
  $CLI tag "$ref" "$to"
  if [ -n "$PODMAN" ]; then
    $CLI push -q ${INSECURE:+--tls-verify=false} "$to"
  else
    $CLI push -q "$to"
  fi
}

save_artifact() {
  local name
  name="$(file "$1")"
  rm -rf "${DIR:?}/$name"
  skopeo copy --quiet "docker://$1" "oci:/work/$name:db"
}

push_artifact() {
  local name
  name="$(file "$1")"
  [ -d "$DIR/$name" ] || { echo "$DIR/$name is missing: run \"save\" first" >&2; exit 1; }
  skopeo copy --quiet ${INSECURE:+--dest-tls-verify=false} "oci:/work/$name:db" "docker://$(target "$1")"
}

mkdir -p "$DIR"
# shellcheck disable=SC2086
if [ "$MODE" = save ]; then
  echo "saving $SKOPEO_IMAGE (the tool that carries the databases)"
  save_image "$SKOPEO_IMAGE"
else
  [ -f "$DIR/$(file "$SKOPEO_IMAGE").tar" ] || { echo "$DIR holds no saved images: run \"save\" first" >&2; exit 1; }
  $CLI load -q -i "$DIR/$(file "$SKOPEO_IMAGE").tar" >/dev/null
fi

kind=image
while read -r ref; do
  case "$ref" in
    "# artifacts") kind=artifact; continue ;;
    "#"*|"") continue ;;
  esac
  if [ "$MODE" = save ]; then
    echo "saving $ref"
  else
    echo "pushing $(target "$ref")"
  fi
  "${MODE}_${kind}" "$ref" </dev/null
done < "$LIST"

if [ "$MODE" = save ]; then
  echo "Saved to $DIR."
else
  echo "Pushed. Install with: bash install.sh --registry $REGISTRY"
fi
