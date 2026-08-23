# Obfuscation E2E

This suite checks that AmneziaWG obfuscation hides standard WireGuard packet
signatures on the outer Docker network.

## Setup

Run it from the repository root:

```sh
just test-obfuscation
```

The target runs [run.sh](./run.sh) with `sudo`. The host must have Docker,
`/dev/net/tun`, and enough privilege for privileged peer containers and a packet
capture container.

## Test Logic

The runner builds:

- a `wgo` peer image;
- an analyzer image with `tcpdump` and `tshark`.

It runs two cases:

- `vanilla`: two `wgo` peers with ordinary WireGuard settings;
- `amnezia`: two `wgo` peers with non-default AmneziaWG obfuscation fields.

For each case, the suite configures two peers on an isolated Docker network,
starts a capture container in one peer's network namespace, sends ping traffic
through the tunnel, and analyzes UDP payloads from the outer network.

## Expected Behaviour

The `vanilla` case must show standard WireGuard signatures: initiation,
response, and transport packets. The `amnezia` case must still pass tunnel
traffic, but the analyzer must find zero standard WireGuard signature packets.

Artifacts are written under `.tmp/obfuscation/<run-id>/`. They include packet
captures, analyzer reports, UAPI logs, and container state. Temporary
containers, networks, and images are removed during cleanup.
