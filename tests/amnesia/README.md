# Amnezia Self-hosted E2E

This suite tests that `wgo/amnesia` can import self-hosted Amnezia guest
access and configure a working `wgo` tunnel.

## Setup

Run it from the repository root:

```sh
just test-amnesia-e2e
```

The target runs [run.sh](./run.sh) with `sudo`. The host must have Docker,
`/dev/net/tun`, and enough privilege for Docker containers to create TUN
devices and network interfaces. The WireGuard cases also need a usable host
kernel WireGuard module.

## Test Logic

The runner builds two temporary images:

- a `wgo` client image with `compat-wgo-peer`, `wgo/amnesia` import helper,
  `curl`, ping, UAPI tools, and WireGuard tools;
- a self-host server image with pinned upstream `amneziawg-go`, the same import
  helper, `curl`, ping, and WireGuard tools.

For each case, the suite starts a server container and a client container on an
isolated Docker network. The server generates a guest access profile, serves
the `vpn://` guest URL over HTTP, and runs the real WireGuard or AmneziaWG data
plane. The client fetches the `vpn://` URL with `curl`, imports it through
`wgo/amnesia`, renders UAPI, and applies it to the running `wgo` node.

The suite also starts a mock encrypted Amnezia gateway that returns an AWG
profile pointing at the same real server. The client imports a service
activation key through the negotiation API and applies the resulting UAPI to
the same `wgo` backend.

The covered inputs are:

- WireGuard guest `vpn://`;
- WireGuard native `.conf`;
- AmneziaWG guest `vpn://`;
- AmneziaWG native `.conf`;
- AmneziaWG service-key negotiation through a mock gateway.

## Expected Behaviour

Each case must:

- connect the client to the server through the VPN tunnel;
- pass ping from client to server and from server to client;
- pass `curl` from the client to an HTTP endpoint on the server tunnel IP;
- pass an HTTP client request from the server to an HTTP endpoint on the client
  tunnel IP.

The suite writes logs, UAPI requests, and interface state under
`.tmp/amnesia-e2e/<run-id>/`. Temporary containers, networks, and images are
removed during cleanup.
