#!/usr/bin/env bash
# Build the launcher image only when Dockerfile inputs changed. The input hash
# is stored in an image label so repeated runs and snapshot.sh reuse the image.
set -Eeuo pipefail

cd "$(dirname "$0")"

IMAGE=${1:-localhost/penguinbox:latest}
LABEL=org.penguinbox.build-inputs

log() { printf '[penguinbox] %s\n' "$*"; }

inputs_hash() {
    {
        printf '%s\0' Dockerfile .dockerignore go.mod entrypoint.sh
        find cmd internal cloud-init guest -type f -print0
    } | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1
}

want=$(inputs_hash)
have=$(podman image inspect --format "{{ index .Labels \"${LABEL}\" }}" "$IMAGE" 2>/dev/null || true)
if [[ "$have" == "$want" ]]; then
    log "image up to date: $IMAGE"
    exit 0
fi

log "building $IMAGE"
podman build --label "${LABEL}=${want}" -t "$IMAGE" .
