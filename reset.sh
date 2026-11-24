#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")"

podman stop penguinbox >/dev/null 2>&1 || true
podman rm -f penguinbox >/dev/null 2>&1 || true
rm -rf storage/penguinbox/disk.qcow2 storage/penguinbox/seed.iso storage/penguinbox/console.log storage/penguinbox/known_hosts storage/penguinbox/share

RESET=1 exec ./run.sh
