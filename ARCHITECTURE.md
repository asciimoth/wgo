# Architecture

## Purpose

`wgo` is a Go library implementation of the WireGuard protocol, derived from `wireguard-go` and adapted to be embedded inside other Go applications.

Unlike the upstream project, this repository is structured as a reusable library rather than an executable tool. The main architectural boundary is:

- `device`: protocol engine and runtime orchestration
- `conn`: UDP transport abstraction
- `tun`: packet I/O abstraction for virtual network devices
- `ipc`: WireGuard UAPI transport helpers
- helper packages: small protocol/runtime utilities used by `device`

## High-Level Model

At runtime, a host application wires together three things:

1. A `tun.Device` implementation from `tun`
2. A `conn.Bind` implementation from `conn`
3. A `device.Device` from `device.NewDevice(...)`

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

### `conn`

`conn` abstracts UDP socket handling behind the `Bind` and `Endpoint` interfaces in [conn/conn.go](/home/moth/projects/wgo/conn/conn.go).

Responsibilities:

- opening and closing IPv4/IPv6 listeners
- batched receive and send
- endpoint parsing and cached source/destination metadata
- OS-specific socket features such as marks, sticky source handling, and UDP offload

`StdNetBind` in [conn/bind_std.go](/home/moth/projects/wgo/conn/bind_std.go) is the cross-platform default implementation. Platform-specific files extend behavior for Linux, Windows, Android, and generic Unix variants.

### `tun`

`tun` defines the virtual interface contract through `tun.Device` in [tun/tun.go](/home/moth/projects/wgo/tun/tun.go).

Responsibilities:

- reading L3 packets from a virtual interface
- writing decrypted packets back to the virtual interface
- surfacing MTU and link events
- OS-specific implementations for Linux, Darwin, FreeBSD, OpenBSD, and Windows

This package also includes:

- checksum/offload helpers
- `tun/netstack`, an in-memory TUN backed by gVisor netstack for embedding/testing
- `tun/tuntest`, test support utilities

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

- records the provided TUN and bind implementations
- reads and stores the current MTU
- initializes peer maps, pools, rate limiter, and key index table
- creates handshake, encryption, and decryption queues
- starts worker goroutines for:
  - handshake processing
  - encryption
  - decryption
  - TUN reads
  - TUN event handling

The device starts in the `down` state. Network sockets are opened later by transitioning the device `up`.

### State transitions

`Device` has three states:

- `down`
- `up`
- `closed`

`Up()` opens the UDP bind and starts per-bind receive routines.

`Down()` closes the bind and stops peer activity without destroying the device object.

`Close()` is terminal. It closes the TUN, tears down the bind, removes peers, drains queues, stops background activity, and closes the `Wait()` channel.

## Data Flow

### Outbound path

The outbound path starts with packets read from the TUN device by `RoutineReadFromTUN` in [device/send.go](/home/moth/projects/wgo/device/send.go).

Flow:

1. Read one or more plaintext IP packets from `tun.Device`
2. Determine IP version and destination address
3. Look up the destination in `AllowedIPs`
4. Stage packets on the selected peer
5. Ensure a valid session exists, initiating handshake if needed
6. Assign nonces sequentially per peer
7. Encrypt transport packets in parallel worker goroutines
8. Send ciphertext through `conn.Bind`

Key design point:

- routing and nonce assignment are serialized where ordering matters
- expensive crypto work is parallelized
- transmission preserves per-peer ordering

### Inbound path

The inbound path starts with UDP datagrams read from `conn.ReceiveFunc` instances created by the active bind.

Flow:

1. Read one or more datagrams from the bind
2. Classify each packet by WireGuard message type
3. Route handshake packets to the handshake queue
4. Route transport packets by receiver index via `IndexTable`
5. Decrypt transport packets in parallel
6. Validate counters and replay windows
7. Deliver plaintext IP packets to the peer’s sequential inbound consumer
8. Write plaintext packets back to `tun.Device`

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

The architecture favors predictable ordering and explicit ownership over fully lock-free operation.

## Platform-Specific Structure

Several packages are split by operating system using Go build tags:

- `tun/*_{linux,darwin,freebsd,openbsd,windows}.go`
- `conn/*_{linux,unix,windows,android}.go`
- `ipc/uapi_{linux,unix,bsd,windows,wasm}.go`
- `device/queueconstants_*` and a few mobile-specific files

This keeps the public package surface stable while isolating OS details such as:

- TUN creation and configuration
- socket control messages
- firewall marks
- route/listener integration
- Windows named pipe support

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

`tun/netstack` provides an alternative in-memory TUN implementation backed by gVisor netstack.

This is useful when an application wants:

- a userspace network stack instead of a kernel TUN
- embedded client/server behavior without creating a host interface
- easier testing and local integration scenarios

Architecturally, this works because `device` depends only on the `tun.Device` interface, not on any specific kernel TUN implementation.

