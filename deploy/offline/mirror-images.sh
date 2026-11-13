#!/usr/bin/env bash
# Carries the images in images.txt from the internet into a private registry.
#
# On a machine with internet access:
#   bash mirror-images.sh save                  # downloads into ./images
#
# Take this directory to the offline side, then, on a machine that reaches the
# registry:
#   bash mirror-images.sh push harbor.example.com/sentinel
#
# A machine that reaches both can do it in one go:
#   bash mirror-images.sh save && bash mirror-images.sh push harbor.example.com/sentinel
#
# Uses skopeo when it is installed. Without it, docker, podman or nerdctl carry
# the images, and oras the two Trivy databases, which are not container images
# and which those three cannot pull. CONTAINER_CLI names another command to use
# in their place ("sudo podman", say).
#
# INSECURE=1 is for a registry on plain HTTP or with a certificate this machine
# does not trust. docker has no such switch: the registry has to be listed
# under insecure-registries in its daemon's configuration.
#
# Images are saved for this machine's CPU architecture. Run "save" on a machine
# of the architecture your nodes have.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIST="$HERE/images.txt"
DIR="${IMAGES_DIR:-$HERE/images}"
MODE="${1:-}"
REGISTRY="${2:-}"
REGISTRY="${REGISTRY%/}"
INSECURE="${INSECURE:-}"

usage() { sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
case "$MODE" in
  save) ;;
  push)
    case "$REGISTRY" in
      "") echo "push needs the registry to push to" >&2; exit 2 ;;
      *://*) echo "the registry is a host and path, without http:// or https://" >&2; exit 2 ;;
    esac ;;
  -h|--help) usage ;;
  *) usage 2 ;;
esac

CLI="${CONTAINER_CLI:-}"
if [ -z "$CLI" ]; then
  for c in docker podman nerdctl; do
    if command -v "$c" >/dev/null 2>&1; then CLI="$c"; break; fi
  done
fi
have() { command -v "$1" >/dev/null 2>&1; }

# An image where the registry keeps it: the same path, under the registry.
target() { echo "$REGISTRY/${1#*/}"; }
# A file name for a reference.
file() { echo "$1" | tr '/:@' '___'; }

# shellcheck disable=SC2086  # CLI may be two words
save_image() {
  local ref="$1" out="$DIR/$(file "$1").tar"
  rm -f "$out"
  if have skopeo; then
    skopeo copy --quiet "docker://$ref" "docker-archive:$out:$ref"
  elif [ -n "$CLI" ]; then
    $CLI pull -q "$ref" >/dev/null
    $CLI save -o "$out" "$ref"
  else
    echo "no skopeo, docker, podman or nerdctl on this machine" >&2; exit 1
  fi
}

# shellcheck disable=SC2086
push_image() {
  local ref="$1" in="$DIR/$(file "$1").tar" to
  to="$(target "$1")"
  [ -f "$in" ] || { echo "$in is missing: run \"save\" first" >&2; exit 1; }
  if have skopeo; then
    skopeo copy --quiet ${INSECURE:+--dest-tls-verify=false} "docker-archive:$in" "docker://$to"
  elif [ -n "$CLI" ]; then
    $CLI load -q -i "$in" >/dev/null
    $CLI tag "$ref" "$to"
    case "$CLI" in
      *podman*) $CLI push -q ${INSECURE:+--tls-verify=false} "$to" ;;
      *nerdctl*) $CLI push -q ${INSECURE:+--insecure-registry} "$to" ;;
      *) $CLI push -q "$to" ;;
    esac
  else
    echo "no skopeo, docker, podman or nerdctl on this machine" >&2; exit 1
  fi
}

# The databases are kept as OCI layouts, which skopeo and oras both read.
no_artifact_tool() {
  echo "  no skopeo or oras on this machine: $1 was not $2." >&2
  echo "  Without the databases in the registry no image can be scanned." >&2
  MISSED=1
}

save_artifact() {
  local ref="$1" out="$DIR/$(file "$1")"
  rm -rf "$out"
  if have skopeo; then
    skopeo copy --quiet "docker://$ref" "oci:$out:db"
  elif have oras; then
    oras copy "$ref" --to-oci-layout "$out:db" >/dev/null
  else
    no_artifact_tool "$ref" saved
  fi
}

push_artifact() {
  local in="$DIR/$(file "$1")" to
  to="$(target "$1")"
  if ! have skopeo && ! have oras; then no_artifact_tool "$1" pushed; return; fi
  [ -d "$in" ] || { echo "$in is missing: run \"save\" with skopeo or oras installed" >&2; exit 1; }
  if have skopeo; then
    skopeo copy --quiet ${INSECURE:+--dest-tls-verify=false} "oci:$in:db" "docker://$to"
  else
    oras copy ${INSECURE:+--to-plain-http} --from-oci-layout "$in:db" "$to" >/dev/null
  fi
}

mkdir -p "$DIR"
MISSED=""
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

if [ -n "$MISSED" ]; then
  exit 1
fi
if [ "$MODE" = save ]; then
  echo "Saved to $DIR."
else
  echo "Pushed. Install with: bash install.sh --registry $REGISTRY"
fi
