#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")"

mkdir -p storage

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
    podman build -t localhost/penguinbox:latest .
fi

HOST_SSH_PORT=${HOST_SSH_PORT:-2223}
HOST_WEB_PORT=${HOST_WEB_PORT:-8007}
HOST_API_PORT=${HOST_API_PORT:-1338}

args=(
    --rm
    --replace
    --name penguinbox
    -p "127.0.0.1:${HOST_SSH_PORT}:2222"
    -p "127.0.0.1:${HOST_WEB_PORT}:8006"
    -p "127.0.0.1:${HOST_API_PORT}:1338"
    -e "VM_NAME=penguinbox"
    -e "VM_DISK_SIZE=${VM_DISK_SIZE:-40G}"
    -e "RAM_SIZE=${RAM_SIZE:-4G}"
    -e "CPU_CORES=${CPU_CORES:-4}"
    -e "SSH_PORT=2222"
    -e "WEB_PORT=8006"
    -e "HOST_SSH_PORT=${HOST_SSH_PORT}"
    -e "HOST_WEB_PORT=${HOST_WEB_PORT}"
    -e "HOST_API_PORT=${HOST_API_PORT}"
    -e "ENABLE_VNC=${ENABLE_VNC:-1}"
    -e "GUEST_RESTRICT_NET=${GUEST_RESTRICT_NET:-0}"
    -e "SSH_PUBLIC_KEY=${SSH_PUBLIC_KEY:-}"
    -e "RESET=${RESET:-0}"
    -v "$(pwd)/storage:/storage:z"
)

if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    args+=(--device /dev/kvm)
fi

exec podman run "${args[@]}" localhost/penguinbox:latest
