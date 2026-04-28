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
3. A `conn.Bind` implementation from `github.com/asciimoth/batchudp`
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

The host application is expected to configure the device through the WireGuard configuration protocol implemented in `device/uapi.go`, or through direct package-level APIs such as peer creation and key updates.

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

- records the provided bind implementation
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

The device batch size is fixed for the lifetime of the device from the maximum of the initial bind and initial TUN batch sizes. Replacement TUNs may use a smaller batch size, but they may not exceed the device batch size because queue pools are pre-sized once at construction.

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

The main configuration surface is:

- `Device.IpcGetOperation(io.Writer)`
- `Device.IpcSetOperation(io.Reader)`

This is an important compatibility layer because it separates:

- transport of configuration requests, handled by `ipc`
- interpretation and mutation of device state, handled by `device`

For embedders, this means configuration can be driven by:

- an existing WireGuard-compatible UAPI client
- custom application code that speaks the same text protocol
- direct Go API usage where tighter integration is preferred

## Netstack Mode

Userspace netstack mode is provided directly by `github.com/asciimoth/gonnect-netstack/vtun`.

This is useful when an application wants:

- a userspace network stack instead of a kernel TUN
- embedded client/server behavior without creating a host interface
- easier testing and local integration scenarios

Architecturally, this works because `device` depends only on the `tun.Tun` interface, not on any specific kernel TUN implementation.
