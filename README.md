# PenguinBox

PenguinBox is a disposable Linux sandbox VM for runtime-detection research. It runs from a Podman or Docker container, boots a KVM guest, and serves a LitterBox-compatible HTTP API.

Payloads run inside the guest in an isolated Podman container while Tracee records kernel telemetry and Falco evaluates behavioral rules. Custom YARA and Falco rules are supported.

## Requirements

- Linux host with `/dev/kvm` readable and writable by the container user.
- Podman or Docker.
- ~2.5 GiB free disk space (first boot downloads an Ubuntu cloud image).
- Outbound network access from the guest during first boot.

No host root, `--privileged`, host networking, or host PID namespace is required.

## Quick start

Start the VM (first boot downloads the base image, provisions the guest, and generates an SSH key at `storage/penguinbox/ssh/id_ed25519`):

```sh
./run.sh
```

Connect over SSH:

```sh
ssh -i storage/penguinbox/ssh/id_ed25519 -p 2223 penguinbox@127.0.0.1
```

- Web console: `http://127.0.0.1:8007/?autoconnect=1&resize=scale`
- Sandbox API: `http://127.0.0.1:1338`

```sh
curl http://127.0.0.1:1338/health
```

Freeze the provisioned guest as a golden snapshot so future resets take seconds:

```sh
./snapshot.sh
```

Discard guest state and boot a clean overlay (reverts to `golden.qcow2` if present, otherwise reprovisions from the base image):

```sh
./reset.sh
```

## Sandbox API

`penguinboxd` implements the LitterBox HTTP API:

- `GET /health`
- `POST /upload`
- `POST /analyze/static/<md5>`
- `POST /analyze/dynamic/<md5>`
- `GET /api/results/{info,static,dynamic,risk}/<md5>`
- `GET /api/edr/profiles`
- `GET /api/rules`

Dynamic runs execute inside a fixed Podman image with a read-only root filesystem, dropped capabilities, `no-new-privileges`, a `noexec,nosuid` tmpfs `/tmp`, and CPU/memory/PID limits.

## Custom rules

- Static YARA: `guest/rules/yara/` (installed to `/etc/penguinbox/rules/yara`, sample: `penguinbox.yar`).
- Behavioral Falco: `guest/rules/falco/` (installed to `/etc/penguinbox/rules/falco`, sample: `penguinbox-custom.yaml`).

Add or edit files in the guest rule directories; the next analysis picks them up without rebuilding the image.

## Security

The launcher container receives only `/dev/kvm`, loopback port mappings, and `./storage`. Everything else—Podman, Tracee, Falco, `penguinboxd`, and the payload—runs inside the disposable guest.

QEMU/KVM isolates the guest payload, not untrusted or model-edited build inputs on the host. For untrusted or high-risk samples, run PenguinBox on a dedicated VM or lab host, do not place host secrets in `storage/penguinbox/share`, and run `./reset.sh` when finished.

## Testing

```sh
go test ./...
go test -race ./...
PENGUINBOX_E2E_RESET=1 go test -tags=e2e ./test/e2e -v -timeout 30m
```

The e2e suite boots a clean guest, exercises the API and custom YARA/Falco rules, and verifies that the API is exposed on host loopback only.

See [docs/penguinbox.md](docs/penguinbox.md) for architecture, networking, telemetry, configuration, and troubleshooting.
