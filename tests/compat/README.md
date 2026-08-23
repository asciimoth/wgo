# Compatibility E2E

This suite tests `wgo` against Linux kernel WireGuard and upstream
`amneziawg-go`.

## Setup

Run it from the repository root:

```sh
just test-compat
```

The target runs [run.sh](./run.sh) with `sudo`. The host must have Docker,
`/dev/net/tun`, and enough privilege for Docker containers to create TUN
devices and network interfaces. Kernel WireGuard cases need a usable host
kernel WireGuard module.

## Test Logic

The runner builds temporary images for:

- kernel WireGuard peers;
- `wgo` peers using `cmd/compat_wgo_peer`;
- upstream `amneziawg-go` peers.

It creates isolated Docker networks and configures peers through UAPI or
`wg set`. The suite covers:

- vanilla WireGuard between `wgo` and kernel WireGuard;
- AmneziaWG with non-default obfuscation fields between `wgo` and
  `amneziawg-go`;
- AmneziaWG v3.1 protected-cookie handshakes;
- AmneziaWG v3.1 device-default and peer-override profiles;
- one `wgo` node with kernel WireGuard and multiple AmneziaWG peers.

The test also exercises dynamic behavior: preshared-key rotation, peer removal
and re-add, endpoint changes, wrong header keys, malformed protected packets,
content padding, random trailers, and per-peer profile isolation.

## Expected Behaviour

Traffic must pass only when both peers have compatible configuration. The
suite expects ping to succeed for valid configurations and to fail after
deliberate breaking changes such as peer removal, wrong endpoint, or wrong
header protection key. Restoring the correct configuration must make traffic
work again.

Artifacts are written under `.tmp/compat/<run-id>/`. They include container
logs, interface state, route state, `wg show` output, and UAPI request logs.
Temporary containers, networks, and images are removed during cleanup.
