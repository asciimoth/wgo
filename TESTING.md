# Testing

This repository has multiple test layers:

- Fast package tests with `go test -race ./...`
- A Linux compatibility suite that runs this library against kernel-space WireGuard and upstream `amneziawg-go` in Docker
- A Linux obfuscation-signature suite that captures Docker traffic and checks standard WireGuard packet signatures with `tshark`
- A Linux Amnezia import suite that parses self-hosted WireGuard/AmneziaWG
  `vpn://` and `.conf` guest inputs with `wgo/amnesia`, configures a `wgo`
  client, and verifies tunnel access to an upstream `amneziawg-go` server
- An opt-in Amnezia live service E2E command that contacts a real gateway with
  private local credentials
- A Linux performance suite that benchmarks this library, upstream `wireguard-go`, upstream `amneziawg-go`, and kernel-space WireGuard with `iperf3`

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
- An upstream `amneziawg-go` peer
- A userspace peer built from this repository (`cmd/compat_wgo_peer`)

It covers two interoperability tracks:

- Vanilla WireGuard against the Linux kernel peer:
  basic tunnel setup, shared preshared key, and dynamic peer mutation
- AmneziaWG against upstream `amneziawg-go`:
  non-default `jc/jmin/jmax`, `s1-s4`, `h1-h4`, and `i1-i5` parameters plus the same preshared-key and dynamic peer update flow
- A concurrent multi-peer topology:
  one `wgo` node talking to a vanilla kernel WireGuard peer and two upstream `amneziawg-go` peers with different non-default obfuscation profiles at the same time

### How It Works

The runner is [tests/compat/run.sh](tests/compat/run.sh).

For each run it:

1. Builds three temporary Docker images:
   - [tests/compat/docker/kernel-peer.Dockerfile](tests/compat/docker/kernel-peer.Dockerfile)
   - [tests/compat/docker/wgo-peer.Dockerfile](tests/compat/docker/wgo-peer.Dockerfile)
   - [tests/compat/docker/amnezia-peer.Dockerfile](tests/compat/docker/amnezia-peer.Dockerfile)
2. Creates an isolated Docker network.
3. Starts privileged containers for each track:
   - `kernel-peer`: uses Linux kernel WireGuard via `ip link add ... type wireguard`
   - `amnezia-peer`: runs upstream `amneziawg-go`
   - `wgo-peer`: runs `compat-wgo-peer`, which creates a native TUN, starts `device.Device`, and exposes a WireGuard-compatible UAPI socket
4. Configures both peers using real control surfaces:
   - `wg` commands on the kernel peer
   - UAPI `set=1` requests against `/var/run/wireguard/wg0.sock` on the `wgo` and `amneziawg-go` peers
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
- UAPI request/response logs for the `wgo` and `amneziawg-go` peers

Containers, Docker network, and temporary Docker images are removed during cleanup.

## Obfuscation Signature Suite

Run the obfuscation suite with:

```bash
just test-obfuscation
```

Like the compatibility suite, the current `Justfile` uses `sudo` because the runner needs Docker access and privileged containers.

### What It Tests

The obfuscation suite runs one pair of userspace peers built from this repository in two scenarios:

- Vanilla WireGuard defaults on both sides
- Matching non-default AmneziaWG parameters on both sides

For each scenario it:

1. Starts two privileged `wgo` peer containers on an isolated Docker network.
2. Configures the peers through the real UAPI socket.
3. Starts a dedicated analyzer container in one peer's network namespace and captures the outer UDP traffic on `eth0`.
4. Sends traffic through the tunnel with `ping`, so the capture includes handshake and transport packets.
5. Extracts UDP payloads from the resulting `pcapng` with `tshark` and checks them against standard WireGuard outer-packet signatures.

The expected assertions are:

- Vanilla traffic must expose standard WireGuard initiation, response, and transport signatures.
- Traffic produced with non-default AmneziaWG headers/padding must not expose those standard WireGuard signatures.

The runner is [tests/obfuscation/run.sh](tests/obfuscation/run.sh).

### Prerequisites

The obfuscation suite is Linux-only and expects:

- Docker installed and usable by the invoking user or through `sudo`
- Support for privileged containers
- Enough privileges for Docker to create TUN devices inside the peer containers

### Artifacts

Temporary outputs are written under:

```text
.tmp/obfuscation/
```

Each run stores:

- Peer container logs
- `ip addr` / `ip route` / `wg show` snapshots
- UAPI request/response logs
- The raw packet capture (`pcapng`)
- A signature-analysis summary with captured packet counts and counts of standard WireGuard packet signatures

## Amnezia Import Suite

Run the self-hosted Amnezia import suite with:

```bash
just test-amnesia-e2e
```

Like the other Docker E2E suites, this target uses `sudo` because it starts
privileged containers with TUN devices.

The runner is [tests/amnesia/run.sh](tests/amnesia/run.sh). It builds a `wgo`
client image with the `amnesia` import helper and a self-host test server
image that runs the pinned upstream `amneziawg-go` data plane. The server
container generates guest WireGuard and AmneziaWG inputs in both `vpn://` and
native `.conf` formats, serves the `vpn://` guest URL over HTTP, and the client
container fetches that URL with `curl`. The imported profile is applied to
`wgo` through UAPI. The suite verifies ping in both directions, `curl` from the
client to an HTTP endpoint on the server through the VPN tunnel, and an HTTP
client request from the server to an endpoint on the client through the same
tunnel.

## Amnezia Live Service E2E

Run the real-service Amnezia E2E command with:

```bash
just test-amnesia-live
```

This command is separate from `go test`, `just test-total`, and `just check`.
It uses private local fixtures under `amnesia/testdata/private` by default,
performs a non-interactive service-key negotiation against a real gateway, and
checks that the returned profile is complete enough to configure a tunnel. It
then builds a userspace `VTun`, applies the received profile to
`device.Device`, starts WireGuard/AmneziaWG, compares the visible public IP from
external services outside the tunnel and through `VTun.Dial`, prints GeoIP
location fields when a service returns them, resolves and pings `example.com`,
and sends HTTP requests to `http://example.com/` through `VTun.Dial`.

The command prints colored terminal output: grey for minor traces, normal text
for regular progress, cyan for important profile and public-IP highlights,
green for success, and red for failure. It prints config loading, client setup,
effective client metadata including `installation_uuid` and `cli_name`,
activation-key display name and service selectors, each HTTP request and
response status, interaction-required handling, pre-connect destinations and
byte counts, VTun setup, visible public IP and GeoIP results, ping attempts,
WGO device logs as grey minor traces, and a redacted profile summary. It must
not print activation keys, request bodies, pre-connect payload bytes, CAPTCHA
images, WireGuard private keys, native configs, or raw gateway configs.

For live runs, a missing or empty `metadata.installation_uuid` is generated and
saved back to `live_api.json` before the gateway request. An empty
`metadata.os_version` uses a descriptive local default instead of only `linux`,
for example the Linux distribution name plus `GOOS/GOARCH`.

Use `-traffic-host`, `-traffic-http-url`, `-ip-check-urls`, `-ping-count`,
`-http-count`, and `-traffic-timeout` to change traffic checks. Set
`-ip-check-urls ""` to disable only the visible-IP check. Use `-skip-traffic`
only when you need the earlier profile-only behavior.

Fixture format and alternate command flags are documented in
[amnesia/testdata/PRIVATE_TESTS.md](amnesia/testdata/PRIVATE_TESTS.md).

## Performance Suite

Run the performance suite with:

```bash
just test-performance
```

It follows the same high-level harness style as the compatibility suite: build temporary Docker images, create isolated networks, start privileged containers, configure real WireGuard peers, then exercise traffic through the tunnel.

### What It Benchmarks

The performance suite runs five subjects independently:

- Two peers implemented by this repository (`wgo`)
- Two peers implemented by this repository with a non-default Amnezia profile (`wgo-amnezia`)
- Two peers implemented by upstream `wireguard-go`
- Two peers implemented by upstream `amneziawg-go` with the same non-default Amnezia profile
- Two peers implemented by Linux kernel-space WireGuard

For each subject it:

1. Starts two paired peers in Docker.
2. Configures tunnel addresses, routes, private keys, public keys, endpoints, and listen ports.
3. For the Amnezia-specific subjects, also applies non-default `jc/jmin/jmax`, `s1-s4`, `h1-h4`, and `i1-i5` UAPI fields, including a positive `s4`.
4. Verifies bidirectional tunnel reachability with `ping`.
5. Runs `iperf3` TCP and UDP benchmarks in both directions across the WireGuard tunnel.
6. Stores raw `iperf3` JSON output under `.tmp/perf/` and writes a readable summary report to the repository-root `performance-log.md`.

The runner is [tests/perf/run.sh](tests/perf/run.sh).

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

If future refactors touch UAPI handling, peer mutation logic, native TUN attachment, or bind/listen-port behavior, this suite should be extended before merging.
