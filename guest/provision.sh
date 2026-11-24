#!/usr/bin/env bash
set -Eeuxo pipefail

export DEBIAN_FRONTEND=noninteractive

GUEST_SRC=/mnt/penguinbox/guest
SHARE=/mnt/penguinbox

mkdir -p /var/log/penguinbox /opt/penguinbox /usr/local/bin

exec > >(tee -a /var/log/penguinbox/provision.log) 2>&1

# Progress goes to the VNC/serial console as well as the log. Without this a
# multi-minute first boot looks hung at a login prompt with no API or guest
# telemetry, and a failed step is invisible.
say() {
    printf 'penguinbox: %s\n' "$*"
    printf '\n[penguinbox] %s\n' "$*" >/dev/tty1 2>/dev/null || true
    # /dev/console is the serial console; entrypoint.sh follows console.log
    # and mirrors these lines into `podman logs`.
    printf '\n[penguinbox] %s\n' "$*" >/dev/console 2>/dev/null || true
}
trap 'rc=$?; say "provisioning failed (exit $rc) at line $LINENO; see /var/log/penguinbox/provision.log"; exit "$rc"' ERR

say "mounting host share"
mkdir -p "$SHARE"
if ! mountpoint -q "$SHARE"; then
    mount -t 9p -o ro,trans=virtio,version=9p2000.L,msize=104857600 host0 "$SHARE"
fi
if [[ ! -d "$GUEST_SRC" ]]; then
    say "guest share is not mounted at $SHARE; cannot install penguinboxd"
    exit 1
fi
cp -a "$GUEST_SRC"/. /opt/penguinbox/

if ! grep -q '^host0 /mnt/penguinbox ' /etc/fstab; then
    printf 'host0 /mnt/penguinbox 9p ro,trans=virtio,version=9p2000.L,msize=104857600,nofail 0 0\n' >>/etc/fstab
fi
systemctl daemon-reload
mount -a || true

# Serve /health while the package install and payload build run, so the
# published API port answers instead of resetting connections for minutes.
say "installing early sandbox API"
install -d -m 0700 /var/lib/penguinbox
install -m 0755 /opt/penguinbox/bin/penguinboxd /usr/local/bin/penguinboxd
install -m 0644 /opt/penguinbox/systemd/penguinboxd.service /etc/systemd/system/penguinboxd.service
systemctl daemon-reload
systemctl enable --now penguinboxd.service ||
    say "warning: sandbox API did not start; it is retried after provisioning"

say "installing base tools"
apt-get update
apt-get install -y --no-install-recommends \
    apt-transport-https \
    auditd \
    binutils \
    bpftrace \
    ca-certificates \
    curl \
    dnsutils \
    file \
    fuse-overlayfs \
    gcc \
    gdb \
    git \
    gnupg \
    iproute2 \
    jq \
    less \
    libc6-dev \
    linux-tools-common \
    lsof \
    ltrace \
    make \
    net-tools \
    netcat-openbsd \
    openssh-server \
    pkg-config \
    podman \
    procps \
    psmisc \
    python3 \
    python3-pip \
    slirp4netns \
    strace \
    sysstat \
    tcpdump \
    tmux \
    uidmap \
    unzip \
    vim \
    wget \
    xz-utils \
    yara \
    zstd

say "enabling podman"
systemctl enable --now podman.socket
systemctl enable --now ssh

say "installing falco"
install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc |
    gpg --batch --yes --dearmor -o /etc/apt/keyrings/falcosecurity.gpg
if [[ -n "${FALCO_GPG_FINGERPRINT:-}" ]]; then
    actual_fpr=$(gpg --show-keys --with-colons /etc/apt/keyrings/falcosecurity.gpg | awk -F: '$1 == "fpr" { print $10; exit }')
    if [[ "$actual_fpr" != "$FALCO_GPG_FINGERPRINT" ]]; then
        echo "penguinbox: falco GPG fingerprint mismatch: got $actual_fpr" >&2
        exit 1
    fi
fi
printf 'deb [signed-by=/etc/apt/keyrings/falcosecurity.gpg] https://download.falco.org/packages/deb stable main\n' \
    >/etc/apt/sources.list.d/falcosecurity.list
apt-get update
apt-get install -y --no-install-recommends falco

install -d -m 0755 /etc/falco/config.d /etc/falco/rules.d
install -d -m 0755 /etc/penguinbox/rules/yara /etc/penguinbox/rules/falco
# Remove rule files from older profiles so an upgraded guest does not load a
# duplicate or an ambient-noise ruleset next to the curated EDR profile.
rm -f /etc/falco/rules.d/99-penguinbox.yaml
rm -f /etc/penguinbox/rules/falco/penguinbox-custom.yaml
if [[ -d /opt/penguinbox/rules/yara ]]; then
    cp -a /opt/penguinbox/rules/yara/. /etc/penguinbox/rules/yara/
fi
if [[ -d /opt/penguinbox/rules/falco ]]; then
    cp -a /opt/penguinbox/rules/falco/. /etc/penguinbox/rules/falco/
fi
if [[ -f /opt/penguinbox/falco/penguinbox.yaml ]]; then
    install -m 0644 /opt/penguinbox/falco/penguinbox.yaml /etc/falco/config.d/99-penguinbox.yaml
fi

systemctl daemon-reload
if [[ -f /usr/lib/systemd/system/falco-modern-bpf.service ]]; then
    systemctl enable --now falco-modern-bpf.service || true
elif [[ -f /usr/lib/systemd/system/falco.service ]]; then
    systemctl enable --now falco.service || true
else
    cat >/etc/systemd/system/penguinbox-falco.service <<'EOF'
[Unit]
Description=Falco runtime security (PenguinBox)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/falco -o engine.kind=modern_ebpf
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now penguinbox-falco.service || true
fi
systemctl is-active falco-modern-bpf.service >/dev/null 2>&1 ||
    systemctl is-active falco.service >/dev/null 2>&1 ||
    systemctl is-active penguinbox-falco.service >/dev/null 2>&1 ||
    say "warning: falco is not active; inspect journalctl -u falco-modern-bpf"

say "installing tracee"
TRACEE_VERSION=v0.24.1
TRACEE_TARBALL="tracee-x86_64.${TRACEE_VERSION}.tar.gz"
TRACEE_BASE="https://github.com/aquasecurity/tracee/releases/download/${TRACEE_VERSION}"
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
curl -fsSL -o "$tmpdir/$TRACEE_TARBALL" "$TRACEE_BASE/$TRACEE_TARBALL"
if [[ -n "${TRACEE_SHA256:-}" ]]; then
    expected="$TRACEE_SHA256"
else
    curl -fsSL -o "$tmpdir/tracee.sha256" "$TRACEE_BASE/checksum-x86_64.${TRACEE_VERSION}.txt"
    expected=$(awk -v name="$TRACEE_TARBALL" '$2 ~ name { print $1; exit }' "$tmpdir/tracee.sha256")
fi
if [[ -z "$expected" ]]; then
    echo "penguinbox: tracee checksum not found in release" >&2
    exit 1
fi
printf '%s  %s\n' "$expected" "$tmpdir/$TRACEE_TARBALL" | sha256sum -c -
tar -xzf "$tmpdir/$TRACEE_TARBALL" -C "$tmpdir"
install -m 0755 "$tmpdir/dist/tracee" /usr/local/bin/tracee
install -m 0755 /opt/penguinbox/bin/penguinbox-tracee /usr/local/bin/penguinbox-tracee

say "building payload runtime image"
install -d -m 0755 /opt/penguinbox/payload
if [[ ! -f /opt/penguinbox/payload/Containerfile ]]; then
    echo "penguinbox: payload Containerfile is missing from the guest share" >&2
    exit 1
fi
podman build -t localhost/penguinbox-payload:latest -f /opt/penguinbox/payload/Containerfile /opt/penguinbox/payload

say "installing sandbox API"
install -d -m 0700 /var/lib/penguinbox
if [[ ! -f /opt/penguinbox/bin/penguinboxd ]]; then
    echo "penguinbox: penguinboxd binary is missing from the guest share" >&2
    exit 1
fi
install -m 0755 /opt/penguinbox/bin/penguinboxd /usr/local/bin/penguinboxd
install -m 0644 /opt/penguinbox/systemd/penguinboxd.service /etc/systemd/system/penguinboxd.service
systemctl daemon-reload
systemctl enable penguinboxd.service
systemctl restart penguinboxd.service

systemctl enable --now auditd || true

touch /var/lib/penguinbox-provisioned
say "provisioning complete"
