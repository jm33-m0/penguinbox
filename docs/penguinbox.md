# PenguinBox Reference

PenguinBox is a disposable Linux sandbox VM for analyzing Linux payloads. It runs as a Podman or Docker container that boots a KVM guest containing a Podman runtime for payloads, Tracee for kernel eBPF telemetry, and Falco for rule-based alerts.

## Architecture

| Layer | Component | Purpose |
| --- | --- | --- |
| Host | Container runtime, CLI/API client | Builds the image, runs the VM container, calls the sandbox API |
| Container | QEMU, `passt`, noVNC, cloud-init seed | Boots and exposes the guest over loopback ports |
| Guest | Tracee | Kernel syscall and LSM event stream |
| Guest | Falco | Behavioral detection rules and alerts |
| Guest | Podman + `penguinbox-payload` image | Executes uploaded payloads in an isolated container |
| Guest | `penguinboxd`, SSH, debug tools | Serves the sandbox API and provides manual inspection tools |

Payloads execute only inside the guest; the host interacts with the VM over loopback ports (`2223`, `8007`, `1338`).

## Security

QEMU/KVM is the payload isolation boundary. Inside the guest, payloads run in a rootful Podman container with a read-only root filesystem, dropped capabilities, `no-new-privileges`, a `noexec,nosuid` tmpfs `/tmp`, and CPU/memory/PID limits.

Key boundaries:

- A container escape inside the guest grants root inside the VM. Treat the guest as untrusted once a payload runs and reset it with `./reset.sh` when done.
- The guest is the payload boundary; it is not a defense against untrusted or model-edited build inputs, scripts, or Containerfiles on the host.
- By default, `passt` proxies guest traffic through the container network namespace (required for first-boot provisioning) and noVNC listens on `127.0.0.1:8007`.
- `storage/penguinbox/share` is mounted read-only in the guest (`readonly=on`). `penguinboxd` binds `127.0.0.1:1338` inside the guest with loopback `Host` header validation, and a guest relay exposes it only to the `passt` gateway so payload containers cannot reach the API.

Hardening options:

- Run PenguinBox inside a dedicated VM (with nested KVM) or lab host rather than a workstation containing credentials or sensitive files.
- After creating a golden snapshot, disable outbound guest networking and noVNC with `GUEST_RESTRICT_NET=1` and `ENABLE_VNC=0`, or pass `-payload-network none` and `-api-token <token>` to `penguinboxd`.
- Set `VM_IMAGE_SHA256`, `FALCO_GPG_FINGERPRINT`, and `TRACEE_SHA256` to pin download verification during provisioning.

## Prerequisites

- Linux host with `/dev/kvm` readable and writable by the container user.
- Podman or Docker (QEMU is bundled in the container image and does not need to be installed on the host).
- At least 2 GiB free for the base cloud image and 40 GiB sparse for the disk overlay.
- Outbound network access from the guest on first boot for package installation.

## First boot

1. `entrypoint.sh` downloads the Ubuntu Noble cloud image to `storage/penguinbox/base.img` if not cached.
2. It creates `storage/penguinbox/disk.qcow2` as a qcow2 overlay and builds a NoCloud seed ISO with the `penguinbox` user, SSH key, and provisioning script.
3. `entrypoint.sh` starts `passt` and boots QEMU with KVM (falling back to TCG if `/dev/kvm` is unavailable).
4. Cloud-init runs `/opt/penguinbox/provision.sh`, which installs Podman, Falco, Tracee, debug tools, builds `localhost/penguinbox-payload:latest`, installs `/usr/local/bin/penguinboxd`, and starts `penguinboxd.service`.
5. The guest writes `/var/lib/penguinbox-provisioned` when provisioning finishes.

To rerun provisioning manually inside the guest:

```sh
sudo /opt/penguinbox/provision.sh
```

Provisioning logs are written to `/var/log/penguinbox/provision.log`.

## Network

Guest networking uses `passt` inside the container network namespace, so guest traffic uses the container's IPv4 address and reaches the same network peers as the container.

| Host | Container | Guest | Service |
| --- | --- | --- | --- |
| `2223` | `2222` | `22` | SSH |
| `8007` | `8006` | — | noVNC web console |
| `1338` | `1338` | `1338` | Sandbox API relay |

All host ports are published on `127.0.0.1` only. Do not expose the VNC or API ports on an untrusted interface.

Inside the guest, `penguinboxd` binds `127.0.0.1:1338`. `passt` forwards container port `1338` to a guest relay that dials `127.0.0.1:1338` and accepts connections only from the `passt` gateway, blocking payload containers on the guest's Podman bridge from reaching the API.

```sh
curl http://127.0.0.1:1338/health
```

### Reaching host services from payloads

On the guest's Podman bridge, `host.containers.internal` would normally resolve to the guest itself (`10.88.0.1`). `entrypoint.sh` writes the outer container's `host.containers.internal` address to `storage/penguinbox/share/host-internal`, and `penguinboxd` passes it to payload containers via `--add-host` for `host.containers.internal` and `host.docker.internal`.

A payload connecting to `host.containers.internal:<port>` therefore reaches the host running the sandbox container (for example, `169.254.1.2` under rootless Podman with `pasta`). Services bound to `0.0.0.0` or the host's LAN interface are reachable; services bound only to the host's `127.0.0.1` are not.

## Guest SSH

On first start, `entrypoint.sh` generates an ed25519 key pair at `storage/penguinbox/ssh/id_ed25519` and authorizes its public key for the `penguinbox` user. The key is reused across restarts and preserved by `reset.sh`. Set `SSH_PUBLIC_KEY` to authorize a custom public key instead.

SSH is public-key only (password login, root login, and agent forwarding are disabled):

```sh
ssh -i storage/penguinbox/ssh/id_ed25519 -p 2223 penguinbox@127.0.0.1
```

The guest host key is recorded on first use in `storage/penguinbox/known_hosts` and fails closed on mismatch. `reset.sh` and `RESET=1` remove `known_hosts` because the recreated guest generates a new host key. Override the default paths with `PENGUINBOX_SSH_KEY` and `PENGUINBOX_KNOWN_HOSTS`.

## Sandbox API

`penguinboxd` serves a LitterBox-compatible HTTP API on `127.0.0.1:1338` inside the guest. It runs as root (required for eBPF and rootful Podman), rejects non-loopback listen addresses, and keeps one long-lived Tracee collector running so detonations do not pay eBPF startup cost.

| Route | Purpose |
| --- | --- |
| `GET /health` | Scanners, rule inventory, and missing tools |
| `POST /upload` | Store an artifact and return MD5, SHA-256, and detected type |
| `POST /analyze/static/<md5>` | ELF inspection and custom YARA scan |
| `POST /analyze/dynamic/<md5>` | Podman detonation with Tracee and Falco telemetry |
| `GET /api/results/info/<md5>` | Upload metadata and static summary |
| `GET /api/results/static/<md5>` | Static analyzer results |
| `GET /api/results/dynamic/<md5>` | Run metadata, telemetry coverage, and events |
| `GET /api/results/risk/<md5>` | Risk score derived from static and Falco findings |
| `GET /api/edr/profiles` | Empty list (no EDR profiles on Linux) |
| `GET /api/rules` | Custom YARA and Falco rule inventory |

### Custom rules

- **Static YARA (`/etc/penguinbox/rules/yara`):** `penguinboxd` evaluates every `.yar` and `.yara` file against uploaded artifacts and returns matches under `results.yara.matches`. Sample: `guest/rules/yara/penguinbox.yar`.
- **Behavioral Falco (`/etc/penguinbox/rules/falco`):** Falco includes and watches this directory. Matching alerts appear in `findings.events` with `collector=falco` and the rule name. Ships with `guest/rules/falco/penguinbox-custom.yaml` and the upstream Apache-2.0 `falcosecurity/rules` incubating (`falco-incubating_rules.yaml`, `falco-incubating-rules-6.0.1`) and sandbox (`falco-sandbox_rules.yaml`, `falco-sandbox-rules-6.2.0`) rulesets.

Add or replace files in the guest rule directories; no image rebuild is needed.

## Telemetry

### Tracee

Tracee attaches eBPF programs to Linux syscalls and LSM hooks and emits JSON events. `penguinboxd` keeps a single Tracee instance running with `-tracee-events default,openat` by default (`-tracee-events syscalls` captures every syscall).

For manual captures inside the guest, `penguinbox-tracee` wraps Tracee with syscall, process-exec, shared-object load, and file/socket security events, plus executed-binary capture:

```sh
# Start Tracee before the payload to scope to the next container:
sudo PENGUINBOX_CONTAINER_ID=new penguinbox-tracee /var/log/penguinbox/tracee.json
sudo podman run --rm localhost/penguinbox-payload:latest /payload
```

To scope to an already-running container by its host PID:

```sh
pid=$(sudo podman inspect -f '{{.State.Pid}}' <container-id>)
sudo PENGUINBOX_HOST_PID="$pid" penguinbox-tracee /var/log/penguinbox/tracee.json
```

Passing `PENGUINBOX_CONTAINER_ID=<id>` is also supported, though `new` and `PENGUINBOX_HOST_PID` avoid cgroup ambiguity when Podman exposes multiple cgroups per container.

Tracee observes Linux syscalls and LSM hooks (including `mmap`, `mprotect`, `memfd_create`, `ptrace`, and process-memory syscalls), not user-space API calls or full memory dumps. Use `gdb`, `/proc/<pid>/maps`, `bpftrace`, or `strace` in the guest for deeper inspection.

### Falco

Falco is a rule engine that emits matching alerts only (not a full event stream). Its drop-in configuration uses the `modern_ebpf` driver and writes JSON alerts to `/var/log/penguinbox/falco.json`.

The Falco log records alerts across all containers in the VM; `penguinboxd` filters it by run window and container ID. Built-in PenguinBox rules cover container exec, shell spawns, execution from writable paths, `memfd_create`, `ptrace`, `/proc/*/maps` reads, outbound connects, kernel module loads, and namespace or mount changes.

## Configuration

### Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `HOST_SSH_PORT` | `2223` | Host loopback port for guest SSH |
| `HOST_WEB_PORT` | `8007` | Host loopback port for noVNC web console |
| `HOST_API_PORT` | `1338` | Host loopback port for the sandbox API |
| `VM_NAME` | `penguinbox` | Guest hostname and storage subdirectory name |
| `VM_DISK_SIZE` | `40G` | Sparse qcow2 overlay size |
| `RAM_SIZE` | `4G` | Guest memory |
| `CPU_CORES` | `4` | Guest vCPU count |
| `VM_IMAGE_URL` | Ubuntu Noble cloud image | Base cloud image download URL |
| `VM_IMAGE_SHA256` | *(unset)* | Optional SHA-256 checksum for the base image |
| `ENABLE_VNC` | `1` | Set to `0` to disable VNC and noVNC |
| `GUEST_RESTRICT_NET` | `0` | Set to `1` to restrict `passt` to container loopback and disable gateway mapping |
| `SSH_PUBLIC_KEY` | *(unset)* | Authorize a custom OpenSSH public key instead of generating one |
| `RESET` | `0` | Set to `1` to recreate the disk overlay and clear `known_hosts` on boot |
| `SKIP_BUILD` | `0` | Set to `1` in `run.sh` / `snapshot.sh` to skip `podman build` |
| `PENGUINBOX_IMAGE` | `localhost/penguinbox:latest` | Container image used by `snapshot.sh` |
| `FALCO_GPG_FINGERPRINT` | *(unset)* | Optional GPG fingerprint pin for Falco apt repo during provisioning |
| `TRACEE_SHA256` | *(unset)* | Optional SHA-256 pin for the Tracee release tarball |
| `PENGUINBOX_SSH_KEY` | `storage/penguinbox/ssh/id_ed25519` | Private key path override for guest SSH |
| `PENGUINBOX_KNOWN_HOSTS` | `storage/penguinbox/known_hosts` | Known-hosts file override for guest SSH |
| `PENGUINBOX_E2E_RESET` | `0` | Set to `1` to reset the VM before running e2e tests |
| `PENGUINBOX_E2E_KEEP` | `0` | Set to `1` to leave the VM running after e2e tests |
| `PENGUINBOX_E2E_SKIP_BUILD` | `0` | Set to `1` to skip rebuilding the container image in e2e tests |

### `penguinboxd` flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `-listen` | `127.0.0.1:1338` | Loopback listen address (non-loopback addresses are rejected) |
| `-state-dir` | `/var/lib/penguinbox` | Directory for uploads and analysis results |
| `-falco-log` | `/var/log/penguinbox/falco.json` | Falco JSON alert log path |
| `-image` | `localhost/penguinbox-payload:latest` | Podman image for payload detonation |
| `-payload-network` | *(default bridge)* | Optional Podman `--network` mode for payload containers (e.g. `none`) |
| `-api-token` | *(unset)* | Optional bearer token required on API requests |
| `-podman` | `podman` | Podman binary path |
| `-host-alias-file` | `/mnt/penguinbox/host-internal` | File containing the host IP for `host.containers.internal` |
| `-tracee` | `/usr/local/bin/tracee` | Tracee binary path |
| `-tracee-helper` | `/usr/local/bin/penguinbox-tracee` | Tracee wrapper script path |
| `-tracee-events` | `default,openat` | Tracee event set (`syscalls` captures every syscall) |
| `-yara` | `/usr/bin/yara` | YARA binary path |
| `-yara-rules` | `/etc/penguinbox/rules/yara` | Custom YARA rule directory |
| `-falco-rules` | `/etc/penguinbox/rules/falco` | Custom Falco rule directory |
| `-detonate-timeout` | `120s` | Wall-clock timeout per dynamic run |
| `-max-upload` | `104857600` (100 MiB) | Maximum upload size in bytes |
| `-max-events` | `100000` | Maximum telemetry events stored per run |

## Storage layout

```text
storage/penguinbox/
  base.img          cached cloud image
  golden.qcow2      optional frozen provisioned disk
  disk.qcow2        run overlay, recreated by reset
  seed.iso          cloud-init NoCloud seed
  user-data         rendered cloud-init user data
  meta-data         rendered cloud-init metadata
  console.log       guest serial console
  monitor.sock      QEMU monitor
  qmp.sock          QEMU QMP
  qemu.pid          QEMU PID
  ssh/id_ed25519    generated guest SSH key
  known_hosts       TOFU guest host key, cleared on reset
  share/            mounted read-only in the guest at /mnt/penguinbox
```

`storage/` is git-ignored. `base.img`, `golden.qcow2`, and `ssh/id_ed25519` survive `reset.sh`; `disk.qcow2`, `seed.iso`, `console.log`, `known_hosts`, and `share/` are removed.

## Snapshots and reset

`./snapshot.sh` stops the VM, flattens the provisioned disk into `storage/penguinbox/golden.qcow2`, creates a fresh run overlay backed by the golden image, and restarts the VM.

`./reset.sh` stops the VM and removes the run overlay, seed, console log, `known_hosts`, and `share/`. On the next boot, `entrypoint.sh` creates a new overlay backed by `golden.qcow2` if present (fast reset), or by `base.img` (full reprovision). Delete `storage/penguinbox/golden.qcow2` to return to base-image resets.

## Container lifecycle

Build and run manually (or use `./run.sh` or `compose.yaml`):

```sh
podman build -t localhost/penguinbox:latest .
podman run --rm --name penguinbox \
  --device /dev/kvm \
  -p 127.0.0.1:2223:2222 \
  -p 127.0.0.1:8007:8006 \
  -p 127.0.0.1:1338:1338 \
  -v "$PWD/storage:/storage:z" \
  localhost/penguinbox:latest
```

Stop the VM with `podman stop penguinbox`. QEMU receives SIGTERM and the disk overlay preserves its state until you run `./reset.sh`.

## Validation

Verify guest services after provisioning:

```sh
ssh -i storage/penguinbox/ssh/id_ed25519 -p 2223 penguinbox@127.0.0.1
sudo systemctl status penguinboxd.service
sudo systemctl status falco-modern-bpf
sudo systemctl status podman.socket
tracee version
sudo podman images
```

Run unit and end-to-end tests from the project root:

```sh
go test ./...
go test -race ./...
PENGUINBOX_E2E_RESET=1 go test -tags=e2e ./test/e2e -v -timeout 30m
```

Smoke-test telemetry inside the guest:

```sh
sudo podman run --rm localhost/penguinbox-payload:latest /bin/sh -c 'id; cat /proc/self/maps >/dev/null'
```

Falco should emit a container-exec or proc-maps alert in `/var/log/penguinbox/falco.json`, and Tracee should record the corresponding syscalls. If either source is silent, inspect `journalctl -u falco-modern-bpf` and `journalctl -u penguinboxd` before trusting a clean result.
