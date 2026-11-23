#!/usr/bin/env bash
set -Eeuo pipefail

: "${VM_NAME:=penguinbox}"
: "${VM_IMAGE_URL:=https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img}"
: "${VM_IMAGE_SHA256:=}"
: "${VM_DISK_SIZE:=40G}"
: "${RAM_SIZE:=4G}"
: "${CPU_CORES:=4}"
: "${SSH_PORT:=2222}"
: "${WEB_PORT:=8006}"
: "${HOST_SSH_PORT:=2223}"
: "${HOST_WEB_PORT:=8007}"
: "${HOST_API_PORT:=1338}"
: "${VNC_PORT:=5900}"
: "${ENABLE_VNC:=1}"
: "${GUEST_RESTRICT_NET:=0}"
: "${STORAGE:=/storage}"
: "${RESET:=0}"
: "${SSH_PUBLIC_KEY:=}"

if [[ ! "$VM_NAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$ ]]; then
    printf '[penguinbox] error: invalid VM_NAME: %s\n' "$VM_NAME" >&2
    exit 1
fi

DATA_DIR="${STORAGE}/${VM_NAME}"
SHARE_DIR="${DATA_DIR}/share"
SSH_DIR="${DATA_DIR}/ssh"
BASE_IMAGE="${DATA_DIR}/base.img"
GOLDEN_IMAGE="${DATA_DIR}/golden.qcow2"
DISK_IMAGE="${DATA_DIR}/disk.qcow2"
SEED_ISO="${DATA_DIR}/seed.iso"
USER_DATA="${DATA_DIR}/user-data"
META_DATA="${DATA_DIR}/meta-data"
CLOUD_TEMPLATE="/etc/penguinbox/cloud-init/user-data.tpl"
CLOUD_META="/etc/penguinbox/cloud-init/meta-data"

log() { printf '[penguinbox] %s\n' "$*"; }
die() {
    printf '[penguinbox] error: %s\n' "$*" >&2
    exit 1
}

require() {
    command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

for command in qemu-system-x86_64 qemu-img cloud-localds ssh-keygen base64 python3 passt; do
    require "$command"
done

# The guest network is provided by passt, not QEMU user-mode slirp. passt
# proxies guest traffic through the container network namespace, so the guest
# leaves with the container's address and reaches the same peers.
passt_addresses() {
    local ip prefix last
    ip=$(ip -4 route get 1.1.1.1 2>/dev/null |
        awk '{ for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit } }')
    if [[ -z "$ip" ]]; then
        ip=$(ip -4 -o addr show scope global 2>/dev/null |
            awk '$2 != "lo" { sub(/\/.*/, "", $4); print $4; exit }')
    fi
    [[ -n "$ip" ]] || return 1
    prefix=$(ip -4 -o addr show 2>/dev/null |
        awk -v ip="$ip" 'index($4, ip "/") == 1 { sub(/.*\//, "", $4); print $4; exit }')
    [[ "$prefix" =~ ^[0-9]+$ ]] || prefix=24
    last="${ip##*.}"
    if [[ ! "$last" =~ ^[0-9]+$ ]] || ((last < 2 || last > 253)); then
        ip="${ip%.*}.2"
    fi
    printf '%s %s\n' "$ip" "$prefix"
}

mkdir -p "$DATA_DIR" "$SHARE_DIR" "$SSH_DIR"
chmod 0700 "$DATA_DIR" "$SSH_DIR"

if [[ ! -f "$BASE_IMAGE" ]]; then
    log "downloading base image: $VM_IMAGE_URL"
    tmp="${BASE_IMAGE}.part"
    rm -f "$tmp"
    curl -fL --retry 3 --retry-delay 5 -o "$tmp" "$VM_IMAGE_URL"
    if [[ -n "$VM_IMAGE_SHA256" ]]; then
        printf '%s  %s\n' "$VM_IMAGE_SHA256" "$tmp" | sha256sum -c -
    else
        log "warning: VM_IMAGE_SHA256 is unset; base image checksum was not verified"
    fi
    mv "$tmp" "$BASE_IMAGE"
fi

if [[ "$RESET" == "1" ]]; then
    log "resetting overlay disk"
    rm -f "$DISK_IMAGE" "$SEED_ISO" "$DATA_DIR/known_hosts"
fi

if [[ ! -f "$DISK_IMAGE" ]]; then
    if [[ -f "$GOLDEN_IMAGE" ]]; then
        log "creating run overlay from golden snapshot: $GOLDEN_IMAGE"
        qemu-img create -q -f qcow2 -F qcow2 -b "$GOLDEN_IMAGE" "$DISK_IMAGE"
    else
        log "creating qcow2 overlay: $VM_DISK_SIZE"
        qemu-img create -q -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$DISK_IMAGE" "$VM_DISK_SIZE"
    fi
fi

SSH_KEY="$SSH_DIR/id_ed25519"
if [[ -n "${SSH_PUBLIC_KEY:-}" ]]; then
    if [[ "$SSH_PUBLIC_KEY" == *$'\n'* || "$SSH_PUBLIC_KEY" == *$'\r'* ]]; then
        die "SSH_PUBLIC_KEY must be a single line"
    fi
    if [[ "$SSH_PUBLIC_KEY" != ssh-* && "$SSH_PUBLIC_KEY" != ecdsa-* && "$SSH_PUBLIC_KEY" != sk-* ]]; then
        die "SSH_PUBLIC_KEY is not an OpenSSH public key"
    fi
    if ! printf '%s\n' "$SSH_PUBLIC_KEY" | ssh-keygen -lf /dev/stdin >/dev/null 2>&1; then
        die "SSH_PUBLIC_KEY failed ssh-keygen validation"
    fi
fi
if [[ -z "$SSH_PUBLIC_KEY" ]]; then
    if [[ ! -s "$SSH_KEY" ]]; then
        log "provisioning guest SSH key: $SSH_KEY"
        ssh-keygen -q -t ed25519 -N '' -C "$VM_NAME" -f "$SSH_KEY"
    else
        log "reusing guest SSH key: $SSH_KEY"
        if [[ ! -s "$SSH_KEY.pub" ]]; then
            ssh-keygen -y -f "$SSH_KEY" >"$SSH_KEY.pub"
        fi
    fi
    chmod 0600 "$SSH_KEY"
    chmod 0644 "$SSH_KEY.pub"
    SSH_PUBLIC_KEY=$(ssh-keygen -y -f "$SSH_KEY")
else
    log "using provided SSH_PUBLIC_KEY for guest authorization"
    if [[ ! -r "$SSH_KEY" ]]; then
        log "no private key at $SSH_KEY; set PENGUINBOX_SSH_KEY for guest SSH"
    fi
fi

rm -rf "$SHARE_DIR"
mkdir -p "$SHARE_DIR"
cp -a /etc/penguinbox/guest "$SHARE_DIR/guest"
install -m 0755 /usr/local/bin/penguinboxd "$SHARE_DIR/guest/bin/penguinboxd"

# penguinboxd points host.containers.internal in payload containers at the
# Podman host that runs this container, not at the guest's own bridge.
HOST_INTERNAL=$(awk '$2 == "host.containers.internal" { print $1; exit }' /etc/hosts)
if [[ -n "$HOST_INTERNAL" ]]; then
    printf '%s\n' "$HOST_INTERNAL" >"$SHARE_DIR/host-internal"
    chmod 0644 "$SHARE_DIR/host-internal"
    log "payload host alias: host.containers.internal -> $HOST_INTERNAL"
fi

PROVISION_B64=$(base64 -w0 /etc/penguinbox/guest/provision.sh)

python3 - "$CLOUD_TEMPLATE" "$USER_DATA" \
    "HOSTNAME=$VM_NAME" \
    "SSH_PUBLIC_KEY=$SSH_PUBLIC_KEY" \
    "PROVISION_B64=$PROVISION_B64" <<'PY'
import json
import sys

template, output = sys.argv[1], sys.argv[2]
quoted_keys = {"HOSTNAME", "SSH_PUBLIC_KEY"}
values = {}
for item in sys.argv[3:]:
    key, _, value = item.partition("=")
    if key in quoted_keys:
        value = json.dumps(value)
    values["__" + key + "__"] = value

with open(template, "r", encoding="utf-8") as handle:
    data = handle.read()
for key, value in values.items():
    data = data.replace(key, value)
with open(output, "w", encoding="utf-8") as handle:
    handle.write(data)
PY

cp "$CLOUD_META" "$META_DATA"
INSTANCE_ID="${VM_NAME}-$(cat /proc/sys/kernel/random/uuid)"
sed "s/^instance-id: .*/instance-id: ${INSTANCE_ID}/" "$META_DATA" >"$META_DATA.tmp"
mv "$META_DATA.tmp" "$META_DATA"
cloud-localds "$SEED_ISO" "$USER_DATA" "$META_DATA"

VNC_DISPLAY=$((VNC_PORT - 5900))
if ((VNC_DISPLAY < 0)); then
    die "VNC_PORT must be 5900 or greater"
fi

WS_PID=""
cleanup() {
    if [[ -n "${PASST_PID:-}" ]]; then
        kill "$PASST_PID" 2>/dev/null || true
    fi
    if [[ -n "$WS_PID" ]]; then
        kill "$WS_PID" 2>/dev/null || true
    fi
    if [[ -n "${QEMU_PID:-}" ]]; then
        kill -TERM "$QEMU_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

display_args=(-display none)
if [[ "$ENABLE_VNC" == "1" ]]; then
    display_args=(-vnc "127.0.0.1:${VNC_DISPLAY}")
    if [[ -d /usr/share/novnc ]]; then
        if command -v websockify >/dev/null 2>&1; then
            websockify --web=/usr/share/novnc --heartbeat=30 \
                "0.0.0.0:${WEB_PORT}" "127.0.0.1:${VNC_PORT}" >/var/log/penguinbox-websockify.log 2>&1 &
        else
            python3 -m websockify --web=/usr/share/novnc --heartbeat=30 \
                "0.0.0.0:${WEB_PORT}" "127.0.0.1:${VNC_PORT}" >/var/log/penguinbox-websockify.log 2>&1 &
        fi
        WS_PID=$!
    fi
fi

accel="tcg"
cpu_args=(-cpu max)
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    accel="kvm"
    cpu_args=(-cpu host)
else
    log "warning: /dev/kvm is not accessible; falling back to TCG"
fi

read -r GUEST_IP GUEST_PREFIX < <(passt_addresses) || die "cannot determine the container IPv4 address"
GUEST_GATEWAY="${GUEST_IP%.*}.1"
UPLINK_DEV=$(ip -4 route show default 2>/dev/null |
    awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')
GUEST_MTU=1500
if [[ -n "$UPLINK_DEV" && -r "/sys/class/net/${UPLINK_DEV}/mtu" ]]; then
    UPLINK_MTU=$(<"/sys/class/net/${UPLINK_DEV}/mtu")
    if [[ "$UPLINK_MTU" =~ ^[0-9]+$ ]] && ((UPLINK_MTU > 0 && UPLINK_MTU < GUEST_MTU)); then
        GUEST_MTU="$UPLINK_MTU"
    fi
fi

PASST_SOCKET="/run/penguinbox-passt.socket"
PASST_LOG="/var/log/penguinbox-passt.log"
rm -f "$PASST_SOCKET"

passt_args=(
    -f -4
    -a "$GUEST_IP"
    -g "$GUEST_GATEWAY"
    -n "$GUEST_PREFIX"
    -m "$GUEST_MTU"
    -t "${SSH_PORT}:22"
    -t "1338:1338"
    --runas "$(id -u):$(id -g)"
    -P "${DATA_DIR}/passt.pid"
    -s "$PASST_SOCKET"
    -l "$PASST_LOG"
    -q
)
if [[ "$GUEST_RESTRICT_NET" == "1" ]]; then
    # Bind proxied connections to the container loopback, which only reaches
    # services inside the container, and stop mapping the guest gateway to it.
    passt_args+=(-o 127.0.0.1 --no-map-gw)
fi

log "network: passt guest=${GUEST_IP}/${GUEST_PREFIX} gateway=${GUEST_GATEWAY} ssh=${SSH_PORT}->22 api=1338"
passt "${passt_args[@]}" &
PASST_PID=$!

for _ in {1..100}; do
    [[ -S "$PASST_SOCKET" ]] && break
    if ! kill -0 "$PASST_PID" 2>/dev/null; then
        [[ -s "$PASST_LOG" ]] && tail -n 20 "$PASST_LOG" >&2
        die "passt exited before creating ${PASST_SOCKET}"
    fi
    sleep 0.1
done
[[ -S "$PASST_SOCKET" ]] || die "passt did not create ${PASST_SOCKET}"

log "booting $VM_NAME (accel=$accel, ${CPU_CORES} vCPU, $RAM_SIZE RAM)"
log "api:      http://127.0.0.1:${HOST_API_PORT}/ (after guest provisioning completes)"
if [[ "$ENABLE_VNC" == "1" ]]; then
    log "console:  http://127.0.0.1:${HOST_WEB_PORT}/?autoconnect=1&resize=scale"
else
    log "console:  disabled (set ENABLE_VNC=1 to enable noVNC)"
fi
if [[ -r "$SSH_KEY" ]]; then
    log "ssh:      ssh -i ${SSH_KEY} -p ${HOST_SSH_PORT} penguinbox@127.0.0.1"
fi
log "guest:    ${GUEST_IP}/${GUEST_PREFIX} gateway ${GUEST_GATEWAY} (passt)"
if [[ -n "$HOST_INTERNAL" ]]; then
    log "payload:  host.containers.internal -> ${HOST_INTERNAL}"
fi
log "storage:  $SHARE_DIR (read-only in guest)"

umask 0077
qemu-system-x86_64 \
    -name "$VM_NAME" \
    -machine "q35,accel=${accel}" \
    "${cpu_args[@]}" \
    -smp "$CPU_CORES" \
    -m "$RAM_SIZE" \
    -drive "file=${DISK_IMAGE},if=virtio,format=qcow2,cache=writeback" \
    -drive "file=${SEED_ISO},media=cdrom,readonly=on" \
    -netdev "stream,id=net0,server=off,addr.type=unix,addr.path=${PASST_SOCKET}" \
    -device "virtio-net-pci,netdev=net0" \
    -virtfs "local,path=${SHARE_DIR},mount_tag=host0,security_model=passthrough,id=host0,multidevs=remap,readonly=on" \
    "${display_args[@]}" \
    -serial "file:${DATA_DIR}/console.log" \
    -monitor "unix:${DATA_DIR}/monitor.sock,server=on,wait=off" \
    -qmp "unix:${DATA_DIR}/qmp.sock,server=on,wait=off" \
    -pidfile "${DATA_DIR}/qemu.pid" &
QEMU_PID=$!

wait "$QEMU_PID"
