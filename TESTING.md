# Testing

This repository has two test layers:

- Fast package tests with `go test -race ./...`
- A Linux compatibility suite that runs this library against kernel-space WireGuard in Docker

## Standard Checks

Run the normal package checks during development:

```bash
just test
just vet
just tidy
```

`just test` runs `go test -race ./...`, which should remain the default pre-merge check.

## Compatibility Suite

Run the compatibility suite with:

```bash
just test-compat
```

The current `Justfile` uses `sudo` for this target because the suite needs Docker access and privileged containers.

### What It Tests

The compatibility suite validates interoperability between:

- A Linux kernel-space WireGuard peer
- A userspace peer built from this repository (`cmd/compat_wgo_peer`)

It covers three cases:

- Basic tunnel setup and bidirectional ping over the WireGuard tunnel
- Peer setup with a symmetric preshared key on both sides
- Dynamic peer changes through live configuration updates:
  remove peer, add peer back, and edit endpoint after listen-port change

### How It Works

The runner is [tests/compat/run.sh](/home/moth/projects/wgo/tests/compat/run.sh).

For each run it:

1. Builds two temporary Docker images:
   - [tests/compat/docker/kernel-peer.Dockerfile](/home/moth/projects/wgo/tests/compat/docker/kernel-peer.Dockerfile)
   - [tests/compat/docker/wgo-peer.Dockerfile](/home/moth/projects/wgo/tests/compat/docker/wgo-peer.Dockerfile)
2. Creates an isolated Docker network.
3. Starts two privileged containers:
   - `kernel-peer`: uses Linux kernel WireGuard via `ip link add ... type wireguard`
   - `wgo-peer`: runs `compat-wgo-peer`, which creates a native TUN, starts `device.Device`, and exposes a WireGuard-compatible UAPI socket
4. Configures both peers using real control surfaces:
   - `wg` commands on the kernel peer
   - UAPI `set=1` requests against `/var/run/wireguard/wg0.sock` on the `wgo` peer
   - `ip` commands for interface addresses, routes, MTU, and link state
5. Verifies tunnel behavior with `ping`.

### Prerequisites

The compatibility suite is Linux-only and expects:

- Docker installed and usable by the invoking user or through `sudo`
- Support for privileged containers
- A usable WireGuard kernel module on the host
- `/lib/modules` available to the kernel-peer container

The host also needs enough privileges for Docker to create TUN devices inside the containers.

### Artifacts

Temporary logs and captured interface state are written under:

```text
.tmp/compat/
```

That directory is gitignored.

The runner captures:

- Container logs
- `ip addr` / `ip route` snapshots
- `wg show` output
- UAPI request/response logs for the `wgo` peer

Containers, Docker network, and temporary Docker images are removed during cleanup.

## Scope And Limits

The compatibility suite is intentionally narrow. It is designed to catch protocol/configuration interoperability regressions, not to benchmark throughput or exhaustively test all kernel behavior.

Current gaps:

- Linux only
- IPv4 only
- No explicit roaming coverage
- No MTU or large-transfer stress case
- No concurrent multi-peer topology

If future refactors touch UAPI handling, peer mutation logic, native TUN attachment, or bind/listen-port behavior, this suite should be extended before merging.
