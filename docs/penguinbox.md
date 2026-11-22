# PenguinBox Linux sandbox

PenguinBox is a disposable Linux VM for the detection loop. It runs as a Podman or Docker container that boots a KVM guest, similar to [dockur/windows](https://github.com/dockur/windows). The guest hosts a Podman runtime for the payload and two telemetry layers: Tracee for full eBPF events and Falco for rule-based alerts.

## Name

PenguinBox follows LitterBox's naming: a box for a Linux guest. It is a standalone project, not a component of a particular operator harness.

## What runs where

| Layer         | Component                           | Purpose                                             |
| ------------- | ----------------------------------- | --------------------------------------------------- |
| Operator host | Detection harness, source builds    | Edits source, builds the payload, verifies check-in |
| Container     | QEMU, noVNC, cloud-init seed        | Boots and exposes the guest                         |
| Guest         | Tracee                              | Full kernel event stream                            |
| Guest         | Falco                               | Detection rules and alerts                          |
| Guest         | Podman + `penguinbox-payload` image | Runs the untrusted payload                          |
| Guest         | SSH and debug tools                 | Debugger worker and manual investigation            |

The operator host never executes the payload. The guest never receives host source or credentials other than the test payload's own embedded configuration.

## Threat model

PenguinBox uses QEMU/KVM as the payload isolation boundary. Inside the guest, payloads run in a rootful Podman container with a read-only root filesystem, dropped capabilities, `no-new-privileges`, a `noexec,nosuid` tmpfs `/tmp`, and CPU/memory/PID limits, while Tracee and Falco observe kernel activity.

Key boundary assumptions:

- The guest is disposable, but a container escape inside the guest gives a payload root inside the VM. Treat the guest as untrusted once a payload runs.
- The guest is the payload boundary; it is not a defense against untrusted or model-edited build inputs, scripts, or containerfiles on the host.
- By default, `passt` provides user-mode networking: guest traffic is proxied through the container network namespace, so the guest takes the container's address and reaches the same peers the container reaches (needed for first-boot provisioning and C2 testing). The noVNC console is enabled on `127.0.0.1:8007`.
- The host share (`storage/penguinbox/share`) is exported read-only to the guest (`readonly=on`), `penguinboxd` binds guest loopback only (`127.0.0.1:1338`) with loopback `Host` header enforcement, and a guest relay exposes that socket to the sandbox container only.

Operational recommendations:

- For untrusted or sensitive malware analysis, run PenguinBox inside a dedicated, isolated VM (with nested KVM) or a dedicated lab host rather than on a daily-driver workstation containing credentials or sensitive data.
- Run `./reset.sh` after your analysis work is done to wipe the guest overlay and shared directory and return to a clean state.
- When you do not need outbound network access or the web console after provisioning a golden snapshot, set `GUEST_RESTRICT_NET=1`, which binds `passt` proxied connections to the container loopback and stops mapping the guest gateway, and `ENABLE_VNC=0`; alternatively pass `-payload-network none` and `-api-token <token>` to `penguinboxd`. Set `VM_IMAGE_SHA256`, `FALCO_GPG_FINGERPRINT`, and `TRACEE_SHA256` if you want pinned download verification during provisioning.

## Prerequisites

- Linux with `/dev/kvm` readable by the Podman user.
- Podman or Docker.
- At least 2 GiB free for the base image and 40 GiB sparse for the overlay.
- Outbound network access from the guest for package installation on first boot.
- A C2 address reachable from inside the guest. A payload configured with `host.containers.internal` reaches the Podman host that runs the sandbox container; with rootless Podman on pasta that is `169.254.1.2`, which reaches the operator host's interfaces.

The container image includes QEMU, `cloud-localds`, `genisoimage`, noVNC, `websockify`, and `passt`. The host does not need QEMU installed.

## First boot

1. `entrypoint.sh` downloads the Ubuntu Noble cloud image to `storage/penguinbox/base.img` unless it is cached.
2. It creates `storage/penguinbox/disk.qcow2` as an overlay and a NoCloud seed ISO with the `penguinbox` user, SSH key, and provisioning script.
3. `entrypoint.sh` starts `passt` and boots QEMU with KVM when `/dev/kvm` is available, otherwise TCG.
4. Cloud-init runs `provision.sh`, which installs Podman, Falco, Tracee, debug tools, builds `localhost/penguinbox-payload:latest`, installs `/usr/local/bin/penguinboxd`, and starts `penguinboxd.service`.
5. The guest marks `/var/lib/penguinbox-provisioned` when it is ready.

Provisioning is idempotent enough to rerun manually:

```sh
sudo /opt/penguinbox/provision.sh
```

The log is `/var/log/penguinbox/provision.log`.

## Network

The guest network is provided by `passt`, the same user-mode backend LitterBox's Windows container uses. `entrypoint.sh` starts `passt` with an address derived from the container interface and a UNIX socket, then QEMU attaches with `-netdev stream`. `passt` runs inside the container network namespace, so guest traffic leaves with the container's address and reaches the peers the container can reach. QEMU's built-in slirp backend is not used.

| Host   | Container | Guest | Service           |
| ------ | --------- | ----- | ----------------- |
| `2223` | `2222`    | `22`  | SSH               |
| `8007` | `8006`    | —     | noVNC web console |
| `1338` | `1338`    | `1338` | Sandbox API relay |

The guest receives the container's IPv4 address by DHCP and uses `<subnet>.1` as its gateway. `passt` maps the gateway to the container's loopback, so a guest connection to `<subnet>.1:<port>` reaches a service that listens on the container's loopback.

The sandbox API binds `127.0.0.1:1338` inside the guest. `passt` forwards container port `1338` to a guest relay, and the relay dials that loopback address. The relay accepts only the passt gateway as a source, so payload containers on the guest's Podman bridge cannot reach the API. `run.sh` publishes the port on the host's loopback and you use it directly:

```sh
curl http://127.0.0.1:1338/health
```

`HOST_API_PORT` changes the host side of the published port; the container and guest sides stay `1338`.

### Payload C2 addressing

The payload container runs on the guest's Podman bridge, where Podman would otherwise resolve `host.containers.internal` to the guest itself (`10.88.0.1`). `entrypoint.sh` publishes the outer container's `host.containers.internal` address as `storage/penguinbox/share/host-internal`, and `penguinboxd` passes it with `--add-host` for `host.containers.internal` and `host.docker.internal`. A payload configured for `host.containers.internal:<port>` therefore reaches the Podman host that runs the sandbox container. With rootless Podman on pasta that address is `169.254.1.2`, which reaches the operator host's interface address, so a C2 listening on `0.0.0.0` (or the host's LAN address) is reachable; a service bound only to the host's `127.0.0.1` is not. `10.0.2.2` is not a valid address here: the guest gateway is the sandbox container, not the operator host.

If the C2 is external, restrict the guest's egress to that endpoint.

The noVNC endpoint is bound to `127.0.0.1` on the host. Do not expose the VNC or API ports on an untrusted interface.

## Guest SSH

The container provisions an ed25519 key pair at `storage/penguinbox/ssh/id_ed25519` on first start and injects `storage/penguinbox/ssh/id_ed25519.pub` into the cloud-init user data. It reuses the key on later starts; `reset.sh` preserves it. Set `SSH_PUBLIC_KEY` to authorize an operator key instead, and point `PENGUINBOX_SSH_KEY` at the matching private key for guest SSH.

The guest user is `penguinbox`. SSH is public-key only: `ssh_pwauth: false`, `disable_root: true`, a locked password, and no agent forwarding. The host endpoint is `127.0.0.1:2223`; Podman forwards it to container port `2222`, and `passt` forwards that to guest port 22.

```sh
ssh -i storage/penguinbox/ssh/id_ed25519 -p 2223 penguinbox@127.0.0.1
```

The first connection records the guest host key in `storage/penguinbox/known_hosts`. Verification fails closed if the key changes. `reset.sh` and `RESET=1` remove `known_hosts` because the recreated guest generates a new host key. The trust settings match the emp3r0r guest SSH flow: public-key authentication, TOFU host-key verification, and an operator-supplied key path.

A harness that uses the emp3r0r-style guest SSH surface sets:

```text
--guest-ssh penguinbox@127.0.0.1:2223
--guest-ssh-key storage/penguinbox/ssh/id_ed25519
```

`PENGUINBOX_SSH_KEY` and `PENGUINBOX_KNOWN_HOSTS` override the defaults.

## Sandbox API

`penguinboxd` implements the LitterBox contract for the detection harness. It runs one long-lived Tracee collector so a detonation does not pay eBPF initialization cost per cycle; `-tracee-events` controls the event set.

| Route                            | Purpose                                           |
| -------------------------------- | ------------------------------------------------- |
| `GET /health`                    | Scanners, rule inventory, and missing tools       |
| `POST /upload`                   | Store an artifact and return MD5/SHA-256/type     |
| `POST /analyze/static/<md5>`     | ELF inspection and every custom YARA rule         |
| `POST /analyze/dynamic/<md5>`    | Podman detonation with Tracee and Falco           |
| `GET /api/results/info/<md5>`    | Upload metadata and static summary                |
| `GET /api/results/static/<md5>`  | Static analyzer blocks                            |
| `GET /api/results/dynamic/<md5>` | Run metadata, coverage, and events                |
| `GET /api/results/risk/<md5>`    | Risk score derived from static and Falco findings |
| `GET /api/edr/profiles`          | Empty list; no EDR profiles on Linux              |
| `GET /api/rules`                 | Custom YARA and behavioral rule inventory         |

The service runs as root because it must open eBPF through Tracee and use rootful Podman. It binds a literal loopback IP and refuses any other listen address.

### Custom rules

Static rules are YARA files in `/etc/penguinbox/rules/yara`. The service runs every `.yar` and `.yara` file against the uploaded artifact and returns matches under `results.yara.matches`.

Behavioral rules are Falco rules in `/etc/penguinbox/rules/falco`. The PenguinBox Falco configuration includes that directory and watches it for changes. Alerts appear in `findings.events` with `collector=falco` and the rule name.

The repository samples are `guest/rules/yara/penguinbox.yar` and `guest/rules/falco/penguinbox-custom.yaml`. Add or replace files in the guest directories; no image rebuild is needed for rule changes.

## Telemetry design

### Tracee

Tracee is the telemetry source. It attaches eBPF programs to syscalls and LSM hooks and emits JSON events. `penguinboxd` keeps one Tracee collector running for the service lifetime with the `default,openat` event set; `-tracee-events syscalls` selects every syscall. The manual `penguinbox-tracee` helper starts a scoped capture with the broad syscall set plus process execution, shared-object load, and socket/file security events, and captures executed binaries:

```sh
# Tracee first, then the payload: select the next container.
sudo PENGUINBOX_CONTAINER_ID=new penguinbox-tracee /var/log/penguinbox/tracee.json
sudo podman run --rm localhost/penguinbox-payload:latest /payload
```

For a running container, use its process tree:

```sh
pid=$(sudo podman inspect -f '{{.State.Pid}}' <container-id>)
sudo PENGUINBOX_HOST_PID="$pid" penguinbox-tracee /var/log/penguinbox/tracee.json
```

`PENGUINBOX_CONTAINER_ID=<id>` is also accepted, but Podman can expose several cgroups for one container and Tracee may reject the ID as ambiguous. The `new` and process-tree scopes avoid that ambiguity. Tracee writes one JSON event per line.

Tracee does not capture Windows ETW providers or user-mode API calls; Linux syscalls and LSM hooks are the observable boundary. It captures memory behavior through `mmap`, `mprotect`, `memfd_create`, `ptrace`, and process-memory syscalls, not full process dumps. Use `gdb`, `/proc/<pid>/maps`, `bpftrace`, or `strace` in the guest when a finding needs more detail.

### Falco

Falco evaluates rules and emits only matches. It is not a full event recorder. It is installed for stable, named detections and for a rule vocabulary the model can reason about. Its drop-in configuration sets `modern_ebpf`, JSON output, and a file at `/var/log/penguinbox/falco.json`.

The Falco log covers every container in the VM, including image-build and session containers. The sandbox service filters it by run window and container ID; for a scoped capture, use Tracee with `PENGUINBOX_CONTAINER_ID=new` or `PENGUINBOX_HOST_PID`.

The PenguinBox rules cover container exec, shell spawns, execution from writable paths, `memfd_create`, `ptrace`, `/proc/*/maps` reads, outbound connects, kernel module loads, and namespace or mount changes.

### Other tools

`sysdig` is not installed by default. If a test needs a libscap `.scap` capture of every syscall with full arguments, install the `sysdig` package in the guest and capture inside the payload's namespace. Tracee is the default because its JSON event model is easier to map into the detection database.

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
  share/            mounted in the guest as /mnt/penguinbox
```

`storage/` is ignored by git. The base image, golden image, and SSH key survive a reset; the run overlay, seed, and console log do not.

## Snapshots and reset

`snapshot.sh` creates an external qcow2 snapshot chain. It stops the VM, flattens the current provisioned disk into `golden.qcow2`, creates a new run overlay whose backing file is the golden image, and starts the VM. The guest is not reprovisioned.

`reset.sh` stops the VM and removes the run overlay, seed, console log, and `known_hosts`. On the next start, `entrypoint.sh` creates a fresh overlay backed by `golden.qcow2` when it exists, otherwise by `base.img`. A golden-backed reset returns the whole disk to the frozen state in seconds; a base-backed reset reprovisions the guest.

Delete `storage/penguinbox/golden.qcow2` to return to base-image resets. Update the golden image by booting a clean guest, running `./snapshot.sh` again, or deleting the golden file and provisioning from base.

## Container lifecycle

Build and run from the project root:

```sh
podman build -t localhost/penguinbox:latest .
podman run --rm --name penguinbox \
  --device /dev/kvm \
  -p 127.0.0.1:2223:2222 \
  -p 127.0.0.1:8007:8006 \
  -v "$PWD/storage:/storage:z" \
  localhost/penguinbox:latest
```

Compose is provided as `compose.yaml`. `run.sh` does the same and omits `/dev/kvm` when it is unavailable.

Stop the VM with `podman stop penguinbox`. The QEMU process receives SIGTERM through the entrypoint, and the overlay keeps its state. Use `reset.sh` for a clean boot.

## Validation

After provisioning:

```sh
ssh -i storage/penguinbox/ssh/id_ed25519 -p 2223 penguinbox@127.0.0.1
sudo systemctl status penguinboxd.service
sudo systemctl status falco-modern-bpf
sudo systemctl status podman.socket
tracee version
sudo podman images
```

Run the unit and end-to-end tests from the project root:

```sh
go test ./...
go test -race ./...
PENGUINBOX_E2E_RESET=1 go test -tags=e2e ./test/e2e -v -timeout 30m
```

The e2e test builds the image, boots or reuses the VM, uploads a script containing `/proc/self/maps`, checks the custom YARA rule and the custom Falco rule, verifies Tracee and Falco coverage, and asserts that the API is published on the host loopback only. Set `PENGUINBOX_E2E_KEEP=1` to leave the VM running. Set `PENGUINBOX_E2E_SKIP_BUILD=1` to reuse the current image.

A smoke test can run a shell in the payload image and confirm both telemetry sources while it runs:

```sh
sudo podman run --rm localhost/penguinbox-payload:latest /bin/sh -c 'id; cat /proc/self/maps >/dev/null'
```

Falco should show a container exec or proc-maps alert, and Tracee should return the corresponding syscall events. If either source is silent, inspect `journalctl -u falco-modern-bpf` and the Tracee stderr before trusting a clean result.
