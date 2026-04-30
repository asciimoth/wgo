# Architecture

## Purpose

`wgo` is a Go library implementation of the WireGuard protocol, derived from `wireguard-go` and adapted to be embedded inside other Go applications.

Unlike the upstream project, this repository is structured as a reusable library rather than an executable tool. The main architectural boundary is:

- `device`: protocol engine and runtime orchestration
- `ipc`: WireGuard UAPI transport helpers
- helper packages: small protocol/runtime utilities used by `device`
- external transport dependencies: `github.com/asciimoth/batchudp` for UDP bind/endpoint abstractions and `github.com/asciimoth/gonnect` for network providers

## High-Level Model

At runtime, a host application wires together four things:

1. A `tun.Tun` implementation from `github.com/asciimoth/gonnect/tun`
2. A `gonnect.Network` implementation used to construct or back UDP transport
3. An optional `conn.Bind` implementation from `github.com/asciimoth/batchudp`
4. A `device.Device` from `device.NewDevice(...)`

For the default native transport, construction typically looks like:

```go
network := (&native.Config{}).Build()
defer network.Down()

bind := batchudp.NewDefaultBind(network)
dev := device.NewDevice(tunDevice, bind, logger)
```

`device.Device` is the central coordinator. It owns:

- interface state (`up`, `down`, `closed`)
- configured peers
- local static identity
- allowed IP routing table
- key index table
- handshake, encryption, and decryption worker queues
- TUN and UDP I/O lifecycles

The host application can configure the device either through direct typed `Device` methods or through the WireGuard configuration protocol implemented in `device/uapi.go`.
For embedded use, the typed `Device` API is the primary surface and UAPI is retained as a compatibility layer.

## Package Responsibilities

### `device`

`device` contains the WireGuard protocol implementation and almost all long-lived runtime state.

Important responsibilities:

- device lifecycle: `NewDevice`, `Up`, `Down`, `Close`
- peer lifecycle and per-peer workers
- Noise handshake state and key management
- transport packet framing, encryption, and decryption
- inbound and outbound packet routing
- timers, keepalives, cookies, replay protection, and rate limiting
- serialization/deserialization of the WireGuard UAPI configuration protocol

Important internal structures:

- `Device` in [device/device.go](/home/moth/projects/wgo/device/device.go)
- `Peer` in [device/peer.go](/home/moth/projects/wgo/device/peer.go)
- `AllowedIPs` trie in [device/allowedips.go](/home/moth/projects/wgo/device/allowedips.go)
- queue definitions in [device/channels.go](/home/moth/projects/wgo/device/channels.go)

### UDP Transport

UDP socket handling is no longer implemented inside this repository. `device` depends on the `Bind`, `Endpoint`, and `ReceiveFunc` interfaces from `github.com/asciimoth/batchudp`.

Responsibilities:

- opening and closing IPv4/IPv6 listeners
- batched receive and send
- endpoint parsing and cached source/destination metadata
- OS-specific socket features such as marks, sticky source handling, and UDP offload

In this project:

- transport abstractions are consumed from `batchudp`, not maintained locally
- the default bind is usually `batchudp.NewDefaultBind(network)`
- the supplied `gonnect.Network` controls how sockets are opened and how network lifecycle is managed

This keeps `wgo` focused on WireGuard protocol behavior while transport implementation evolves independently in the standalone `batchudp` module.

### Packet I/O

`device` depends on the `tun.Tun` contract from `github.com/asciimoth/gonnect/tun`.

Concrete providers now come from external packages:

- `github.com/asciimoth/tuntap` for native OS TUN devices
- `github.com/asciimoth/gonnect-netstack/vtun` for userspace virtual TUNs
- `github.com/asciimoth/gonnect/native` when the host wants a default OS-backed network for `batchudp`
- package-local test helpers in `device/*_test.go`

At the TUN boundary, `device` keeps two concepts separate:

- the internal WireGuard transport layout inside device buffers
- the adapter offsets required by a specific `tun.Tun`

The transport layout remains fixed:

- transport header starts at offset `0`
- transport plaintext content starts at offset `16`

TUN offsets are treated as adapter metadata computed for each attached `tun.Tun`:

- `readOffset`: offset passed to `tun.Read`
- `writeOffset`: offset passed to `tun.Write`
- `readNeedsCopy`: whether inbound TUN plaintext must be compacted left to offset `16`
- `writeNeedsCopy`: whether outbound plaintext must be shifted right before `tun.Write`

This preserves the existing crypto and packet layout logic while allowing arbitrary non-negative `MRO()`/`MWO()` values as long as they fit device buffer capacity.
The active TUN can be replaced at runtime without rebuilding the `Device`, so this adapter strategy is attachment-local rather than a permanent property of the device object.

### `ipc`

`ipc` is intentionally narrow in this repo. It provides platform-specific UAPI listener helpers such as Unix socket setup in [ipc/uapi_unix.go](/home/moth/projects/wgo/ipc/uapi_unix.go) and named pipe support on Windows.

The actual parsing and execution of `get`/`set` commands lives in `device/uapi.go`, not in `ipc`.

### Helper packages

- `ratelimiter`: handshake flood protection
- `replay`: replay window logic for transport counters
- `rwcancel`: cancelable blocking I/O support
- `tai64n`: WireGuard timestamp format helpers

These packages are small, focused dependencies of `device` and transport code.

## Runtime Lifecycle

### Construction

`device.NewDevice(tunDevice, bind, logger)` initializes the protocol engine and starts background workers immediately.

During construction it:

- records the provided bind implementation, which may be `nil` if the device should start detached from UDP transport
- attaches the provided initial TUN
- validates that TUN's offsets against buffer-capacity limits
- computes that attachment's read/write adapter strategy from `MRO()` and `MWO()`
- reads and stores the current MTU
- initializes peer maps, pools, rate limiter, and key index table
- creates handshake, encryption, and decryption queues
- starts worker goroutines for:
  - handshake processing
  - encryption
  - decryption
  - TUN reads for the active attachment
  - TUN event handling for the active attachment

The device starts in the `down` state. Network sockets are opened later by transitioning the device `up`.

The device batch size is fixed for the lifetime of the device from the maximum of `256`, `batchudp.IdealBatchSize`, the initial bind batch size (if any), and the initial TUN batch size. Replacement binds or TUNs may use a smaller batch size, but they may not exceed the device batch size because queue pools are pre-sized once at construction.

### State transitions

`Device` has three states:

- `down`
- `up`
- `closed`

`Up()` opens the UDP bind and starts per-bind receive routines.

`Down()` closes the bind and stops peer activity without destroying the device object.

TUN lifecycle is managed separately from `up`/`down` state:

- `ReplaceTUN()` swaps the active attachment in place, starts fresh TUN reader/event workers for the new attachment, and closes the old TUN to unblock its read loop
- `DetachTUN()` removes the active attachment and leaves the device running without TUN delivery until another TUN is attached
- `AttachTUN()` attaches a TUN to a currently detached device

Bind lifecycle is also managed separately from `up`/`down` state:

- `ReplaceBind()` swaps the active bind in place; if the device is up, peer sessions are restarted and endpoints are reparsed for the new bind implementation
- `DetachBind()` removes the active bind and leaves the device running without UDP transport until another bind is attached
- `AttachBind()` attaches a bind to a currently detached device

Detached-bind behavior:

- a device may be `up` while no bind is attached
- in that state no UDP receive routines exist
- outbound transport sends fail fast and packets are effectively dropped
- peer `endpoint=` UAPI updates are rejected while detached because endpoint parsing is bind-specific

`Close()` is terminal. It closes the active TUN if present, tears down the bind, removes peers, drains queues, stops background activity, and closes the `Wait()` channel.

## Data Flow

### Outbound path

The outbound path starts with packets read from the currently attached TUN by `RoutineReadFromTUN` in [device/send.go](/home/moth/projects/wgo/device/send.go).

Flow:

1. Read one or more plaintext IP packets from the active `tun.Tun` using that attachment's `readOffset`
2. If the TUN requires a larger read offset than the internal transport layout, compact plaintext left to offset `16`
3. Determine IP version and destination address
4. Look up the destination in `AllowedIPs`
5. Stage packets on the selected peer
6. Ensure a valid session exists, initiating handshake if needed
7. Assign nonces sequentially per peer
8. Encrypt transport packets in parallel worker goroutines
9. Send ciphertext through `batchudp.Bind`

Key design point:

- routing and nonce assignment are serialized where ordering matters
- expensive crypto work is parallelized
- transmission preserves per-peer ordering
- the encryption path always sees plaintext at the fixed transport content offset, regardless of TUN requirements

### Inbound path

The inbound path starts with UDP datagrams read from `batchudp.ReceiveFunc` instances created by the active bind.

Flow:

1. Read one or more datagrams from the bind
2. Classify each packet by WireGuard message type
3. Route handshake packets to the handshake queue
4. Route transport packets by receiver index via `IndexTable`
5. Decrypt transport packets in parallel
6. Validate counters and replay windows
7. Deliver plaintext IP packets to the peer’s sequential inbound consumer
8. Snapshot the currently attached TUN for delivery
9. If that TUN requires a larger write offset than the internal transport layout, shift plaintext right before TUN delivery
10. Write plaintext packets back to `tun.Tun` using that attachment's `writeOffset`
11. If a TUN swap raced the write and the old attachment was already closed, rebuild the write buffers once against the new current attachment and retry

## Bind Transition Notes

The current runtime bind transition model is intentionally simple and disruptive:

- swapping or detaching a bind while the device is up stops peers and then starts them again once transport is available
- active keypairs and in-flight sessions are not preserved across bind transitions
- packets sent during a transition, or while detached, may be lost
- peer endpoints are reparsed from `Endpoint.DstToString()` on bind replacement because endpoint values are owned by the bind implementation

This is enough to keep the `Device`, attached TUN, and UAPI server alive across transport changes, but it is not designed to provide seamless session migration.

## Current Limitations

- replacement binds and replacement TUNs still cannot exceed the device's fixed lifetime batch size
- endpoint preservation across bind replacement depends on the new bind successfully parsing the old endpoint's string form
- `ReplaceBind()` is safe but not transactional; if rebinding or reopening fails, the device remains alive but the previous running bind/session state is not restored automatically
- `AttachBind()` does not recreate remote peer knowledge of a new listen port; if the new bind opens on a different port, remote peers may need an endpoint refresh or a new handshake path to reach it

Handshake packets and transport packets are deliberately separated early so the device can scale crypto work while keeping protocol ordering constraints.

## Peer and Routing Model

Peers are keyed by remote static public key and stored in `Device.peers.keyMap`.

Each peer owns:

- handshake state
- current/next/previous keypairs
- endpoint state
- timers and keepalive machinery
- staged outbound queue
- sequential outbound and inbound processing queues

Allowed IP routing is implemented as a prefix trie in `AllowedIPs`. On outbound traffic it chooses the peer for a destination IP. On configuration changes it also acts as the authoritative mapping from peer to announced prefixes.

Receiver indices for inbound transport packets are resolved through `IndexTable`, allowing constant-time lookup from message receiver field to peer/keypair state.

## Concurrency Model

This codebase uses a mixed concurrency strategy:

- coarse locks for configuration/state transitions
- atomics for hot-path state
- channels for work distribution
- per-peer sequential queues to preserve packet ordering
- shared worker pools for crypto-heavy stages

Important patterns:

- `Device.state` serializes `Up`/`Down`/`Close`
- `ipcMutex` prevents configuration operations from racing with lifecycle-sensitive sections
- queue wrappers in [device/channels.go](/home/moth/projects/wgo/device/channels.go) use ref-counted shutdown to avoid closing channels while writers are still active
- memory reuse is handled by pools in `device/pools.go` to reduce allocations on packet hot paths

Message buffers intentionally include a small amount of extra TUN staging headroom beyond the protocol `MaxMessageSize`. This headroom exists only to satisfy oversized TUN read/write offsets without changing the WireGuard transport packet format.

The architecture favors predictable ordering and explicit ownership over fully lock-free operation.

## Platform-Specific Structure

Several packages are split by operating system using Go build tags:

- `ipc/uapi_{linux,unix,bsd,windows,wasm}.go`
- `device/queueconstants_*` and a few mobile-specific files

This keeps the public package surface stable while isolating OS details such as:

- TUN creation and configuration
- route/listener integration inside `device`
- Windows named pipe support

Most socket-control and UDP platform specialization now lives in the external `batchudp` module rather than in this repository.

## UAPI and Embedding Boundary

Although this repo is library-first, it still exposes the WireGuard configuration model used by upstream tooling.

The primary configuration surface for embedders is the typed `Device` API. Common entry points include:

- `Device.SetPrivateKey(NoisePrivateKey)`
- `Device.SetListenPort(uint16)`
- `Device.SetFwmark(uint32)`
- `Device.SetAmneziaWGConfig(AmneziaWGConfig)`
- `Device.NewPeer(NoisePublicKey)`
- `Device.RemovePeer(NoisePublicKey)`
- `Device.RemoveAllPeers()`
- `Device.SetPeerPresharedKey(NoisePublicKey, NoisePresharedKey)`
- `Device.SetPeerEndpoint(NoisePublicKey, string)`
- `Device.SetPeerPersistentKeepaliveInterval(NoisePublicKey, uint16)`
- `Device.SetPeerProtocolVersion(NoisePublicKey, int)`
- `Device.ReplacePeerAllowedIPs(NoisePublicKey, []netip.Prefix)`
- `Device.AddPeerAllowedIP(NoisePublicKey, netip.Prefix)`
- `Device.RemovePeerAllowedIP(NoisePublicKey, netip.Prefix)`
- `Device.AmneziaWGConfig()`
- `Device.Config()`
- `Device.PeerConfig(NoisePublicKey)`

The UAPI compatibility surface remains:

- `Device.IpcGetOperation(io.Writer)`
- `Device.IpcSetOperation(io.Reader)`

This is an important compatibility layer because it separates:

- transport of configuration requests, handled by `ipc`
- interpretation and mutation of device state, handled by `device`

For embedders, this means configuration can be driven by:

- direct Go API usage with typed setters/getters
- an existing WireGuard-compatible UAPI client
- custom application code that speaks the same text protocol

In practice, the examples in this repository prefer the direct `Device` methods and use UAPI only where compatibility with existing tooling matters.

## AmneziaWG Extension

This repository now implements the AmneziaWG 2.0 obfuscation extension described in [amnezia_wg_extension.md](/home/moth/projects/wgo/amnezia_wg_extension.md), using the current `amneziawg-go` behavior as the compatibility target where that differs from public docs.

The implementation is intentionally device-global, matching the original Go daemon:

- `H1..H4` header ranges
- `S1..S4` fixed prefix lengths
- `I1..I5` pre-handshake decoy packet specs
- `Jc`, `Jmin`, `Jmax` pre-handshake junk packet settings

These values are stored on `device.Device` and apply to all peers attached to that device instance. There is no per-peer AmneziaWG profile in this repository yet.

The implementation touches four main areas:

- config and state: [device/amnezia.go](/home/moth/projects/wgo/device/amnezia.go), [device/config.go](/home/moth/projects/wgo/device/config.go), and [device/uapi.go](/home/moth/projects/wgo/device/uapi.go) define the typed config model, UAPI keys, CPS parsing for `I1..I5`, and header-overlap validation
- send path: [device/noise-protocol.go](/home/moth/projects/wgo/device/noise-protocol.go) and [device/send.go](/home/moth/projects/wgo/device/send.go) generate randomized header values, prepend fixed-size random prefixes, emit `I1..I5` and `J*` packets before each initiation, and preserve the keepalive `S4` quirk from `amneziawg-go`
- receive path: [device/receive.go](/home/moth/projects/wgo/device/receive.go) classifies packets by `(configured padding, configured header range, expected size)` before handing the stripped inner message to normal WireGuard processing
- cookie handling: [device/cookie.go](/home/moth/projects/wgo/device/cookie.go) now accepts the configured cookie header value so `H3` applies to cookie replies too

Vanilla WireGuard support is preserved by the default device configuration:

- `H1=1`
- `H2=2`
- `H3=3`
- `H4=4`
- `S1=S2=S3=S4=0`
- `I1..I5` unset
- `Jc=Jmin=Jmax=0`

With those defaults, packet layout and handshake behavior remain standard WireGuard.

## Netstack Mode

Userspace netstack mode is provided directly by `github.com/asciimoth/gonnect-netstack/vtun`.

This is useful when an application wants:

- a userspace network stack instead of a kernel TUN
- embedded client/server behavior without creating a host interface
- easier testing and local integration scenarios

Architecturally, this works because `device` depends only on the `tun.Tun` interface, not on any specific kernel TUN implementation.
