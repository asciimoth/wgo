# [WireGuard](https://www.wireguard.com/) lib for go 

> [!IMPORTANT]
> This project contains code extracted from the original
> [wireguard-go](https://git.zx2c4.com/wireguard-go) project
> with some modifications.
> All credit goes to the original wireguard-go authors.

## Typed Device Configuration

`Device` can now be configured directly without going through UAPI text.

```go
var localPrivateKey device.NoisePrivateKey
if err := localPrivateKey.FromHex("<local-private-key-hex>"); err != nil {
	log.Fatal(err)
}

var peerKey device.NoisePublicKey
if err := peerKey.FromHex("<peer-public-key-hex>"); err != nil {
	log.Fatal(err)
}

if err := dev.SetPrivateKey(localPrivateKey); err != nil {
	log.Fatal(err)
}
if err := dev.SetListenPort(51820); err != nil {
	log.Fatal(err)
}

peer, err := dev.NewPeer(peerKey)
if err != nil {
	log.Fatal(err)
}
_ = peer

if err := dev.SetPeerProtocolVersion(peerKey, 1); err != nil {
	log.Fatal(err)
}
if err := dev.ReplacePeerAllowedIPs(peerKey, []netip.Prefix{
	netip.MustParsePrefix("10.44.0.2/32"),
}); err != nil {
	log.Fatal(err)
}
if err := dev.SetPeerEndpoint(peerKey, "198.51.100.10:51820"); err != nil {
	log.Fatal(err)
}

cfg := dev.Config()
fmt.Println("listen port:", cfg.ListenPort)
fmt.Println("peer endpoint:", cfg.Peers[0].Endpoint)
```

For complete runnable examples using the typed methods, see:

- [examples/internal/e2e/e2e.go](/home/moth/projects/wgo/examples/internal/e2e/e2e.go)
- [examples/http_request/main.go](/home/moth/projects/wgo/examples/http_request/main.go)
- [examples/web_admin/main.go](/home/moth/projects/wgo/examples/web_admin/main.go) for a localhost web admin panel that starts with no attached TUN or bind and can attach native resources at runtime
