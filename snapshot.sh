#!/usr/bin/env bash
# Freeze the current guest disk as a golden qcow2 and restart from a fresh
# overlay. Subsequent ./reset.sh runs revert to this snapshot instead of
# reprovisioning from the base cloud image.
set -Eeuo pipefail

cd "$(dirname "$0")"

IMAGE=${PENGUINBOX_IMAGE:-localhost/penguinbox:latest}
HOST_DATA=storage/penguinbox
DATA_DIR=/storage/penguinbox
GOLDEN="$DATA_DIR/golden.qcow2"
DISK="$DATA_DIR/disk.qcow2"

if [[ ! -d storage/penguinbox ]]; then
    echo "penguinbox: storage/penguinbox does not exist; start the VM first" >&2
    exit 1
fi

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
    podman build -t "$IMAGE" . >/dev/null
fi

podman stop penguinbox >/dev/null 2>&1 || true
podman rm -f penguinbox >/dev/null 2>&1 || true

qemu_img() {
    podman run --rm --entrypoint qemu-img \
        -v "$(pwd)/storage:/storage:z" \
        "$IMAGE" "$@"
}

if [[ ! -f storage/penguinbox/disk.qcow2 ]]; then
    echo "penguinbox: storage/penguinbox/disk.qcow2 does not exist" >&2
    exit 1
fi

tmp="$GOLDEN.tmp"
rm -f "$HOST_DATA/golden.qcow2.tmp"
echo "penguinbox: freezing $DISK as $GOLDEN"
qemu_img convert -O qcow2 "$DISK" "$tmp"
mv "$HOST_DATA/golden.qcow2.tmp" "$HOST_DATA/golden.qcow2"
rm -f "$HOST_DATA/disk.qcow2" "$HOST_DATA/seed.iso" \
    "$HOST_DATA/console.log" "$HOST_DATA/known_hosts"

echo "penguinbox: creating a clean run overlay from the golden snapshot"
qemu_img create -q -f qcow2 -F qcow2 -b "$GOLDEN" "$DISK"

RESET=0 SKIP_BUILD=1 exec ./run.sh
