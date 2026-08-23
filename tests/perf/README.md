# Performance E2E

This suite compares tunnel throughput across `wgo`, upstream implementations,
and kernel WireGuard.

## Setup

Run it from the repository root:

```sh
just test-performance
```

The target runs [run.sh](./run.sh) with `sudo`. The host must have Docker,
`/dev/net/tun`, and enough privilege for Docker containers to create TUN
devices and network interfaces. Kernel WireGuard cases need a usable host
kernel WireGuard module.

Useful environment variables:

- `IPERF_SECONDS`: duration of each measured iperf run, default `10`;
- `IPERF_OMIT_SECONDS`: warm-up seconds omitted by iperf, default `1`;
- `MTU`: tunnel MTU, default `1420`.

## Test Logic

The runner builds temporary images for:

- `wgo`;
- `wgo` with non-default AmneziaWG fields;
- upstream `wireguard-go`;
- upstream `amneziawg-go`;
- Linux kernel WireGuard.

For each subject, it starts two peers on an isolated Docker network, configures
the tunnel, verifies ping in both directions, then runs `iperf3` in both
directions. It records TCP and UDP results as JSON and appends a summarized
table to [performance-log.md](../../performance-log.md).

## Expected Behaviour

Each subject must establish a tunnel, pass ping in both directions, and
complete TCP and UDP iperf runs in both directions. The suite is a benchmark,
so exact throughput is environment-dependent. A pass means the benchmarks
completed and the summary was written.

Artifacts are written under `.tmp/perf/<run-id>/`. They include iperf JSON,
container logs, interface state, route state, and `wg show` output. Temporary
containers, networks, and images are removed during cleanup.
