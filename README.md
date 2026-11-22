# PenguinBox

PenguinBox is a disposable Linux VM for runtime-detection research. It runs from a Podman or Docker container, boots a KVM guest, and serves a LitterBox-compatible sandbox API.

Payloads run inside the guest in their own Podman container. Tracee records kernel telemetry and Falco evaluates behavioral rules. Static YARA and custom Falco rules are supported.

## Requirements

- Linux host with KVM (`/dev/kvm` readable and writable by the container user).
- Podman or Docker.
- About 2.5 GiB of free space; the first boot downloads an Ubuntu cloud image.
- Outbound network access from the guest during first boot.

No host root, privileged container, host networking, or host PID namespace is required.

## Quick start

```sh
./run.sh
```

The first start downloads the base image, creates a 40G overlay, and provisions the guest. It also generates the guest SSH key at `storage/penguinbox/ssh/id_ed25519` and authorizes its public key for the `penguinbox` user. The key is reused on later starts and is not recreated by `reset.sh`.

Access the guest:

```sh
ssh -i storage/penguinbox/ssh/id_ed25519 -p 2223 penguinbox@127.0.0.1
```

Authentication is public-key only. Password login, root login, and agent forwarding are disabled. The guest host key is recorded on first use in `storage/penguinbox/known_hosts`; `reset.sh` removes that file so the next connection records the current guest host key.

Web console: `http://127.0.0.1:8007/?autoconnect=1&resize=scale`.

The sandbox API is published on `127.0.0.1:1338` on the host:

```sh
curl http://127.0.0.1:1338/health
```

Reset to a clean guest:

```sh
./reset.sh
```

After the first provisioning, freeze a clean state with:

```sh
./snapshot.sh
```

`snapshot.sh` stops the VM, converts the provisioned disk to `storage/penguinbox/golden.qcow2`, creates a fresh qcow2 overlay, and restarts. Later `reset.sh` runs revert to that golden image and are fast. Without a golden image, `reset.sh` recreates the overlay from the base cloud image and provisions again.

## Host privileges and threat model

The host container is a VM launcher and console. It receives `/dev/kvm`, loopback port mappings, and the `storage/` volume. It does not run with `--privileged`, does not use host networking or host PID, and does not mount host files outside `storage/`.

Everything after boot runs inside the guest: provisioning, Podman, Tracee, Falco, `penguinboxd`, and the payload. The guest's root account and nested Podman are local to the disposable VM.

QEMU/KVM is the payload isolation boundary, not a defense against untrusted or model-edited build inputs on the host. When analyzing untrusted or high-risk payloads, run PenguinBox itself inside a dedicated, isolated VM or lab host rather than on a primary workstation. The guest mounts `storage/penguinbox/share` read-only; do not place host secrets there. Run `./reset.sh` when your analysis work is done to discard guest state and return to a clean snapshot.

See [docs/penguinbox.md](docs/penguinbox.md) for the full threat model, optional network/VNC restrictions, and recovery steps.

## Sandbox API

`penguinboxd` implements the LitterBox HTTP contract:

- `GET /health`
- `POST /upload`
- `POST /analyze/static/<md5>`
- `POST /analyze/dynamic/<md5>`
- `GET /api/results/{info,static,dynamic,risk}/<md5>`
- `GET /api/edr/profiles`
- `GET /api/rules`

Dynamic runs use a fixed runtime image with a read-only root, dropped capabilities, no new privileges, a tmpfs `/tmp`, and resource limits.

## Custom rules

- Static YARA: `guest/rules/yara/`, installed to `/etc/penguinbox/rules/yara`.
- Behavioral Falco: `guest/rules/falco/`, installed to `/etc/penguinbox/rules/falco`.
- Samples: `guest/rules/yara/penguinbox.yar` and `guest/rules/falco/penguinbox-custom.yaml`.

Add or replace files in the guest rule directories; the next analysis picks them up. Tracee uses the `default,openat` event set by default; `-tracee-events syscalls` selects every syscall.

## Testing

```sh
go test ./...
go test -race ./...
PENGUINBOX_E2E_RESET=1 go test -tags=e2e ./test/e2e -v -timeout 30m
```

The end-to-end test is a Go test. It boots a clean guest, exercises the API and custom rules, and verifies that the API is published on the host loopback only.

See [docs/penguinbox.md](docs/penguinbox.md) for prerequisites, provisioning details, telemetry internals, rule behavior, and recovery.
