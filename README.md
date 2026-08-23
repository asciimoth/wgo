# [WireGuard](https://www.wireguard.com/) library for Go
[![Go Reference](https://pkg.go.dev/badge/github.com/asciimoth/wgo.svg)](https://pkg.go.dev/github.com/asciimoth/wgo)  

> [!IMPORTANT]
> This project is a fork of the original
> [wireguard-go](https://git.zx2c4.com/wireguard-go) project
> with some modifications.
> All credit goes to the original wireguard-go authors.

## Things done
- replaced the built-in TUN and conn implementations with reusable [gonnect/tun](https://github.com/asciimoth/gonnect/tree/master/tun) and [batchudp](https://github.com/asciimoth/batchudp) libraries
- support on-the-fly attach/detach/swap operations for `Bind` and `Tun` instances
- added usage [examples](./examples)
- added `Device` configuration methods matching UAPI get/set options
- added multi-controller peer and transport APIs with a [guide](./docs/multi-controller-guide.md)
- added leveled logging
- implemented [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go)-compatible obfuscation, including typed AWG 3.1 configuration fields
    - added support for per-peer obfuscation options, migration notes, and receive-profile guidance in [ARCHITECTURE.md](./ARCHITECTURE.md#amneziawg-extension)
- added [`amnesia`](./amnesia), a `wgo` subpackage that imports Amnezia service
  keys, self-hosted guest `vpn://` keys, and native WireGuard/AmneziaWG configs
  into backend-neutral profiles for `device`
- added more end-to-end and [compatibility](./tests/compat) tests with other WireGuard implementations
- added [self-hosted Amnezia import e2e tests](./tests/amnesia) that parse
  server-exported WireGuard and AmneziaWG `vpn://`/`.conf` guest inputs and
  verify ping and HTTP tunnel access through `wgo`
- added [performance tests](./tests/perf) with a [comparison](./performance-log.md) against other WireGuard implementations
- [WASM builds supported](https://asciimoth.github.io/wg-web-demo/)

## TODO
- [x] add WASM based web demo
- [ ] add a way to pass unknown non-WireGuard traffic to external code so different protocols can share the same port
- [ ] [PQC](https://github.com/WireGuard/wireguard-go/pull/133)
- [ ] onion routing
- [ ] wireguard over tcp
- [ ] peer auto-discovery
    - [wireguard endpoint discovery nat traversal](https://www.jordanwhited.com/posts/wireguard-endpoint-discovery-nat-traversal/)
    - [wgsd](https://coredns.io/explugins/wgsd/)
- [ ] use [bufpool](https://github.com/asciimoth/bufpool) to optimize allocations
