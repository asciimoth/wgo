# Multi-controller integration guide

This guide is for libraries and applications that want several independent
control-plane clients to share one `wgo` WireGuard device and one TUN.

## Mental model

The host application owns the device-global resources:

- the `device.Device` lifecycle;
- the single local WireGuard private key;
- the TUN;
- the default transport;
- device-global compatibility settings.

A controller owns only its peers and, optionally, one or more named packet
transports. It publishes complete desired `PeerSpec` values and removes those
peers when they leave its control plane.

No `Controller` interface is required by `wgo`:

```go
go serviceA.Run(ctx, dev)
go serviceB.Run(ctx, dev)
```

Both functions use the same thread-safe peer and transport APIs.

## One device means one local key

All peers on one `device.Device` see the same local WireGuard public key. Before
combining controllers, verify that every remote service can be configured to
accept this shared public key.

If two services require different client private keys, use two WireGuard device
instances. Named transports do not create additional WireGuard identities.

## Construct the shared device

The initial bind remains the default transport, so existing applications do
not need a transport registration call for ordinary UDP.

```go
package main

import (
	batchudp "github.com/asciimoth/batchudp"
	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/wgo/device"
	gtun "github.com/asciimoth/gonnect/tun"
)

func newSharedDevice(
	tunDev gtun.Tun,
	privateKey device.NoisePrivateKey,
) (*device.Device, gonnect.Network, error) {
	network := (&gonnect.NativeConfig{}).Build()
	udp := batchudp.NewDefaultBind(network)

	dev := device.NewDevice(
		tunDev,
		udp,
		device.NewLogger(device.LogLevelInfo, "vpn: "),
		nil,
		device.DeviceOptions{
			// This must be at least every transport's BatchSize().
			BatchSize:      128,
			MaxActivePeers: 512,
		},
	)
	if err := dev.SetPrivateKey(privateKey); err != nil {
		dev.Close()
		_ = network.Down()
		return nil, nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		_ = network.Down()
		return nil, nil, err
	}
	return dev, network, nil
}
```

The `MaxActivePeers` field bounds peers that are active at the same time. A
configured on-demand peer can stay inactive until traffic uses it. If the limit
is reached, `Up`, `UpsertPeer`, or `ActivatePeer` can return
`device.ErrActivePeerLimit` when they would start one more peer.

On shutdown, stop controllers before closing the device:

```go
cancelControllers()
controllers.Wait()
dev.Close()       // closes all registered binds
_ = network.Down() // the host still owns the gonnect network
```

## Publish a direct-UDP peer

`UpsertPeer` replaces the complete desired state for one public key. It does
not affect any other peer.

```go
func applyDirectPeer(dev *device.Device, p controlPeer) error {
	return dev.UpsertPeer(device.PeerSpec{
		PublicKey:       p.PublicKey,
		PresharedKey:    p.PresharedKey,
		ProtocolVersion: 1,
		Endpoint: &device.PeerEndpoint{
			Transport: device.DefaultTransportID,
			Address:   p.UDPAddr.String(),
		},
		PersistentKeepaliveInterval: p.KeepaliveSeconds,
		AllowedIPs:                  append([]netip.Prefix(nil), p.AllowedIPs...),
		Activation:                  device.PeerActivationOnDemand,
	})
}
```

The first outbound packet or inbound initiation starts an on-demand peer's
active workers and session state while the device is up. A nonzero persistent
keepalive makes it active while the device is up because keepalive timers
require active state.

When the control plane removes the peer:

```go
_, err := dev.DeletePeer(p.PublicKey)
```

Deletion removes both its desired configuration and any active session. It
does not affect peers belonging to another controller.

## Run independent controllers

Each controller should maintain its own desired peer map and publish complete
specifications. It should never call `RemoveAllPeers`, use
`ApplyConfigOptions.ReplacePeers`, change the device private key, or shut down
the shared device.

```go
type ServiceController struct {
	dev   *device.Device
	peers map[device.NoisePublicKey]device.PeerSpec
}

func (c *ServiceController) ApplyUpdate(update ServiceUpdate) error {
	for _, removedKey := range update.Removed {
		delete(c.peers, removedKey)
		if _, err := c.dev.DeletePeer(removedKey); err != nil {
			return err
		}
	}

	for _, changed := range update.Changed {
		spec := makePeerSpec(changed)
		c.peers[spec.PublicKey] = spec
		if err := c.dev.UpsertPeer(spec); err != nil {
			return err
		}
	}
	return nil
}
```

Calls from different controllers may run concurrently. Operations are
linearized by `wgo`; the last operation to commit wins if two controllers
accidentally use the same public key or exact prefix. Applications should still
prevent those conflicts because no ownership or rollback history is retained.

## Register a controller-provided transport

A transport implements the existing `batchudp.Bind` contract. Despite its UDP
origin, the contract is also suitable for a datagram-preserving tunnel or a
packet-processing wrapper.

```go
const serviceBTLS device.TransportID = "service-b/tls"

func attachServiceBTransport(
	dev *device.Device,
	tlsBind batchudp.Bind,
) error {
	return dev.AddTransport(serviceBTLS, device.TransportConfig{
		Bind: tlsBind,
		// A tunnel may ignore ListenPort and Fwmark. UDP binds use them.
		ListenPort: 0,
		Fwmark:     0,
	})
}
```

Peers select it by ID:

```go
func applyServiceBPeer(dev *device.Device, p serviceBPeer) error {
	return dev.UpsertPeer(device.PeerSpec{
		PublicKey:       p.PublicKey,
		PresharedKey:    p.PresharedKey,
		ProtocolVersion: 1,
		Endpoint: &device.PeerEndpoint{
			Transport: serviceBTLS,
			// The custom bind defines this syntax. It may be a tunnel
			// destination, logical peer ID, or public-key string.
			Address: p.TunnelDestination,
		},
		AllowedIPs: append([]netip.Prefix(nil), p.AllowedIPs...),
		Activation: device.PeerActivationOnDemand,
	})
}
```

`wgo` calls `tlsBind.ParseEndpoint` when it installs or updates the peer
endpoint, and again for peers that select the transport when that transport is
replaced. It sends encrypted WireGuard datagrams through `tlsBind.Send` and
feeds the bind's received datagrams into the normal WireGuard receive path.

Removing a transport does not silently delete its peers:

```go
if err := dev.RemoveTransport(serviceBTLS); err != nil {
	return err
}
```

Those peers remain configured but sends fail fast with
`device.ErrTransportUnavailable`. They recover after the controller adds the
same transport ID again or publishes specs selecting another transport.

Use `ReplaceTransport` for transport recovery or a new tunnel implementation:

```go
err := dev.ReplaceTransport(serviceBTLS, device.TransportConfig{
	Bind: replacement,
})
```

Only endpoints selecting `service-b/tls` are reparsed. Peers on default UDP or
another controller's transport keep running.

## Implementing a custom tunnel bind

The custom bind must satisfy these behavioral requirements:

### `Open`

- Establish or start the receive side and return one or more blocking
  `batchudp.ReceiveFunc` values.
- Return promptly; connection establishment that may take a long time should
  have its own context, timeout, or background reconnect state.
- Treat `Open` as a lifecycle transition and reject an overlapping second open.
- The returned receive functions must remain valid until `Close`.

### `ReceiveFunc`

- Preserve each WireGuard packet as one datagram.
- Fill matching packet, size, and endpoint entries.
- Never return more entries than `BatchSize`.
- Return `net.ErrClosed` after `Close`.
- Enforce maximum frame lengths before copying data from a stream.
- Return an endpoint whose `DstToBytes` is stable enough for WireGuard cookie
  MAC calculations.

### `Send`

- Accept calls concurrent with other sends and with `Close`.
- Preserve datagram boundaries. A stream tunnel normally uses a frame such as
  `length | destination | encrypted-wireguard-datagram`.
- Use a bounded queue and explicit drop/backpressure policy. Do not block a
  peer's sequential sender indefinitely while a TLS connection reconnects.
- Return a useful error when the transport is unavailable.
- Do not inspect or depend on the inner IP packet: `Send` receives encrypted
  WireGuard packets.

### `ParseEndpoint`

- Be fast, deterministic, and local; do not fetch control-plane data.
- Return only endpoint values accepted by that bind's `Send`.
- Make `DstToString` round-trip through `ParseEndpoint`, because transport
  replacement reparses configured endpoints.
- Keep mutable path discovery inside a stable logical endpoint when possible.

### `Close`, `SetMark`, and `BatchSize`

- `Close` must unblock every receive function and be repeatable.
- A non-UDP tunnel may implement `SetMark` as a no-op.
- `BatchSize` must be stable and no larger than the device's construction-time
  `DeviceOptions.BatchSize`.

## Wrap UDP with middleware

Packet transformation does not require changes to `wgo`. Implement a bind that
wraps another bind:

```go
type TransformBind struct {
	inner batchudp.Bind
	// codec transforms only encrypted outer datagrams.
	codec DatagramCodec
}

func (b *TransformBind) Send(bufs [][]byte, ep batchudp.Endpoint) error {
	encoded := make([][]byte, len(bufs))
	for i, packet := range bufs {
		encoded[i] = b.codec.Encode(packet)
	}
	return b.inner.Send(encoded, unwrapEndpoint(ep))
}
```

Its receive functions decode before returning packets to `wgo`. The wrapper
must also wrap endpoints so `ParseEndpoint`, `Send`, roaming, and cookie replies
all preserve the inner bind/endpoint pairing.

Transformations run after WireGuard encryption and before physical output. They
cannot select a transport based on an inner destination or TCP/UDP port. To
route different inner networks through different mechanisms, configure those
prefixes on different peers and assign each peer the appropriate transport.

## Use a different network implementation

Ordinary UDP through another network stack or namespace is just another named
transport:

```go
nsNetwork := buildNamespaceBackedNetwork(...)
nsUDP := batchudp.NewDefaultBind(nsNetwork)

if err := dev.AddTransport("service-c/netns", device.TransportConfig{
	Bind:       nsUDP,
	ListenPort: 0,
}); err != nil {
	return err
}
```

The host/controller owns `nsNetwork`; the device owns the registered bind's
open/close lifecycle.

## Tailscale-style integration

A Tailscale-like adapter can keep all control-plane peer metadata and cheap
logical path objects in its own data structures while publishing lightweight
`PeerSpec` records to `wgo`.

Recommended pattern:

1. Implement a magicsock-like `batchudp.Bind`.
2. Register it under a namespaced transport ID.
3. Make `ParseEndpoint(publicKeyString)` return the existing logical endpoint
   for that peer.
4. Let the logical endpoint choose direct UDP, relay/TLS, or both based on path
   health.
5. Upsert every currently authorized peer as `PeerActivationOnDemand`.
6. Publish its accepted source/destination prefixes in `AllowedIPs`.
7. On a control-plane delta, upsert only changed peers and delete removed peers.

```go
const tailTransport device.TransportID = "example-tailnet/magicsock"

func publishTailPeer(dev *device.Device, n Node) error {
	return dev.UpsertPeer(device.PeerSpec{
		PublicKey:       n.NodeKey,
		ProtocolVersion: 1,
		Endpoint: &device.PeerEndpoint{
			Transport: tailTransport,
			Address:   hex.EncodeToString(n.NodeKey[:]),
		},
		AllowedIPs: n.AllowedIPs,
		Activation: device.PeerActivationOnDemand,
	})
}
```

On first outbound traffic, `wgo` resolves the destination prefix to the
configured peer and starts it if it is inactive. On an inbound initiation, it
decrypts the remote static key, verifies that a configured peer exists, and
starts that peer if needed. The peer specification and logical transport
endpoint remain configured across active session changes.

The adapter must not perform a control-server request from endpoint parsing or
the packet path. Fetch network maps asynchronously and publish local snapshots.

## Inspect state

`PeerSpec` returns desired state only:

```go
spec, configured := dev.PeerSpec(peerKey)
```

`PeerSnapshot` adds runtime information:

```go
snapshot, configured := dev.PeerSnapshot(peerKey)
if configured {
	log.Printf("peer active=%v connected=%v transport=%q revision=%d",
		snapshot.Active,
		snapshot.Connected,
		snapshot.Spec.Endpoint.Transport,
		snapshot.Revision,
	)
}
```

Device-level stats distinguish configured and active peers:

```go
stats := dev.RuntimeStats()
log.Printf("configured=%d active=%d connected=%d transports=%d active_transports=%d",
	stats.PeerCount,
	stats.ActivePeerCount,
	stats.ConnectedPeerCount,
	stats.TransportCount,
	stats.ActiveTransportCount,
)
```

Do not retain or mutate slices returned in snapshots as if they were device
storage; they are copies.

## Failure behavior

Controllers should assume packet loss is possible during endpoint and transport
changes. WireGuard will normally re-handshake or retransmit at higher layers.

Recommended controller behavior:

- retry control-plane reconciliation with backoff;
- replace a failed transport without touching unrelated peers;
- use `errors.Is` with `ErrTransportUnavailable` and other sentinel errors;
- observe transport-specific health from the custom transport itself;
- never respond to a transport failure by calling `Device.Down` or replacing
  the default bind unless the host owns that policy.

When a transport is removed, peers selecting it remain visible in `PeerSpec`
and `Config`. This makes reconciliation deterministic: re-adding the transport
or changing the peer path is enough to recover.

## Controller rules

Third-party controller libraries should follow these rules:

1. Accept an existing `*device.Device`; do not create or close it unless the
   application explicitly delegates ownership.
2. Never change the shared private key.
3. Never use whole-device peer replacement.
4. Namespace transport IDs, for example `module-name/path-name`.
5. Publish complete peer specs and clone control-plane slices.
6. Remove only public keys the controller owns.
7. Keep control-plane I/O outside `wgo` calls and packet callbacks.
8. Use bounded queues in tunnel and middleware transports.
9. Treat endpoint strings as non-secret identifiers; do not place keys or
   credentials in them.
10. Stop controller goroutines before the host closes the device.

Following these rules is sufficient for independent VPN control-plane adapters
to coexist without introducing a controller abstraction into `wgo` itself.
