# Testing

This repository has two test layers:

- Fast package tests with `go test -race ./...`
- A Linux compatibility suite that runs this library against kernel-space WireGuard in Docker
- A Linux performance suite that benchmarks this library, upstream `wireguard-go`, and kernel-space WireGuard with `iperf3`

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

## Performance Suite

Run the performance suite with:

```bash
just test-performance
```

It follows the same high-level harness style as the compatibility suite: build temporary Docker images, create isolated networks, start privileged containers, configure real WireGuard peers, then exercise traffic through the tunnel.

### What It Benchmarks

The performance suite runs three subjects independently:

- Two peers implemented by this repository (`wgo`)
- Two peers implemented by upstream `wireguard-go`
- Two peers implemented by Linux kernel-space WireGuard

For each subject it:

1. Starts two paired peers in Docker.
2. Configures tunnel addresses, routes, private keys, public keys, endpoints, and listen ports.
3. Verifies bidirectional tunnel reachability with `ping`.
4. Runs `iperf3` TCP and UDP benchmarks in both directions across the WireGuard tunnel.
5. Stores raw `iperf3` JSON output under `.tmp/perf/` and writes a readable summary report to the repository-root `performance-log.md`.

The runner is [tests/perf/run.sh](/home/moth/projects/wgo/tests/perf/run.sh).

### Performance Artifacts

Temporary outputs are written under:

```text
.tmp/perf/
```

Each run gets its own directory with:

- Per-subject raw `iperf3` JSON output
- Container logs
- `ip addr` / `ip route` / `wg show` snapshots

The committed summary file is `performance-log.md`.

Like the compatibility suite, temporary containers, networks, and Docker images are removed during cleanup.

## Scope And Limits

The compatibility suite is intentionally narrow. It is designed to catch protocol/configuration interoperability regressions, not to benchmark throughput or exhaustively test all kernel behavior.

Current gaps:

- Linux only
- IPv4 only
- No explicit roaming coverage
- No MTU or large-transfer stress case
- No concurrent multi-peer topology

If future refactors touch UAPI handling, peer mutation logic, native TUN attachment, or bind/listen-port behavior, this suite should be extended before merging.
