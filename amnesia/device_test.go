package amnezia

import (
	"errors"
	"net/http"
	"net/netip"
	"sync"
	"testing"

	conn "github.com/asciimoth/batchudp"
	"github.com/asciimoth/wgo/device"
)

type deviceTestBind struct{}

func (*deviceTestBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return nil, port, nil
}

func (*deviceTestBind) Close() error { return nil }

func (*deviceTestBind) SetMark(uint32) error { return nil }

func (*deviceTestBind) Send([][]byte, conn.Endpoint) error { return nil }

func (*deviceTestBind) ParseEndpoint(value string) (conn.Endpoint, error) {
	address, err := netip.ParseAddrPort(value)
	if err != nil {
		return nil, err
	}
	return deviceTestEndpoint{address: address}, nil
}

func (*deviceTestBind) BatchSize() int { return 1 }

type deviceTestEndpoint struct {
	address netip.AddrPort
}

func (deviceTestEndpoint) ClearSrc() {}

func (endpoint deviceTestEndpoint) SrcToString() string { return "" }

func (endpoint deviceTestEndpoint) DstToString() string { return endpoint.address.String() }

func (endpoint deviceTestEndpoint) DstToBytes() []byte { return endpoint.address.Addr().AsSlice() }

func (endpoint deviceTestEndpoint) DstIP() netip.Addr { return endpoint.address.Addr() }

func (deviceTestEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

func newDeviceForAmnesiaTest(t *testing.T) *device.Device {
	t.Helper()
	dev := device.NewDevice(
		nil,
		&deviceTestBind{},
		device.NopLogger{},
		nil,
		device.DeviceOptions{WorkerCount: 1},
	)
	t.Cleanup(dev.Close)
	return dev
}

func newClientWithDeviceForTest(t *testing.T, dev device.DeviceAPI) *Client {
	t.Helper()
	client, err := NewClient(ClientOptions{
		HTTPClient:         &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()},
		Device:             dev,
		PrimaryS3URLs:      []string{},
		FallbackS3URLs:     []string{},
		StaticProxyURLs:    []string{},
		DisableS3Discovery: true,
		Metadata: ClientMetadata{
			OSVersion:        "test",
			AppVersion:       "test",
			CLIName:          "test",
			Distribution:     "test",
			Language:         "en",
			InstallationUUID: "00000000-0000-4000-8000-000000000001",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func deviceTestProfile(t *testing.T) *Profile {
	t.Helper()
	privateKey, publicKey := testWireGuardKeypair(t, 0x61)
	_, serverPublicKey := testWireGuardKeypair(t, 0x69)
	return &Profile{
		Interface: WireGuardInterface{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
			Addresses:  []string{"10.0.0.2/32"},
		},
		Peer: WireGuardPeer{
			PublicKey: serverPublicKey,
			Endpoint:  "127.0.0.1:51820",
			AllowedIPs: []string{
				"0.0.0.0/0",
				"::/0",
			},
		},
	}
}

func TestClientDeviceDetachReattachAndReplace(t *testing.T) {
	dev := newDeviceForAmnesiaTest(t)
	first := device.DetachDevice(dev)
	client := newClientWithDeviceForTest(t, first)

	if client.Device() != first {
		t.Fatal("Device did not return the initial implementation")
	}
	if err := client.AttachDevice(dev); !errors.Is(err, ErrDeviceAlreadyAttached) {
		t.Fatalf("AttachDevice while occupied error = %v, want %v", err, ErrDeviceAlreadyAttached)
	}
	var nilWrapper *device.DetachedDevice
	if _, err := client.ReplaceDevice(nilWrapper); !errors.Is(err, ErrDeviceRequired) {
		t.Fatalf("ReplaceDevice with typed nil error = %v, want %v", err, ErrDeviceRequired)
	}

	detached := client.DetachDevice()
	if detached != first || client.Device() != nil {
		t.Fatal("DetachDevice did not return and clear the initial implementation")
	}
	select {
	case <-first.Wait():
		t.Fatal("DetachDevice closed the detached wrapper")
	default:
	}
	if err := client.AttachDevice(detached); err != nil {
		t.Fatalf("reattach same implementation: %v", err)
	}

	second := device.DetachDevice(dev)
	previous, err := client.ReplaceDevice(second)
	if err != nil {
		t.Fatalf("ReplaceDevice: %v", err)
	}
	if previous != first || client.Device() != second {
		t.Fatal("ReplaceDevice returned or installed the wrong implementation")
	}
	first.Close()
	select {
	case <-second.Wait():
		t.Fatal("closing the previous wrapper closed the replacement")
	default:
	}
	select {
	case <-dev.Wait():
		t.Fatal("closing the previous wrapper closed the concrete device")
	default:
	}

	if got := client.DetachDevice(); got != second {
		t.Fatal("DetachDevice did not return the replacement implementation")
	}
	if err := client.AttachDevice(second); err != nil {
		t.Fatalf("reattach replacement implementation: %v", err)
	}
}

func TestClientAttachDeviceAfterStartingWithoutDevice(t *testing.T) {
	client := newClientWithDeviceForTest(t, nil)
	dev := newDeviceForAmnesiaTest(t)
	wrapper := device.DetachDevice(dev)

	if client.Device() != nil {
		t.Fatal("client started with a device API")
	}
	if err := client.AttachDevice(wrapper); err != nil {
		t.Fatalf("AttachDevice after client start: %v", err)
	}
	if client.Device() != wrapper {
		t.Fatal("Device did not return the late attachment")
	}
	if err := client.ApplyProfile(deviceTestProfile(t)); err != nil {
		t.Fatalf("ApplyProfile through late attachment: %v", err)
	}
}

func TestClientAttachDeviceAfterCurrentDeviceCloses(t *testing.T) {
	firstDevice := newDeviceForAmnesiaTest(t)
	first := device.DetachDevice(firstDevice)
	client := newClientWithDeviceForTest(t, first)

	first.Close()
	secondDevice := newDeviceForAmnesiaTest(t)
	second := device.DetachDevice(secondDevice)
	if err := client.AttachDevice(second); err != nil {
		t.Fatalf("AttachDevice after current device closed: %v", err)
	}
	if client.Device() != second {
		t.Fatal("Device did not return the replacement for the closed attachment")
	}
	if err := client.ApplyProfile(deviceTestProfile(t)); err != nil {
		t.Fatalf("ApplyProfile through replacement for closed attachment: %v", err)
	}
}

func TestClientApplyProfileTracksPeerAcrossReplacement(t *testing.T) {
	dev := newDeviceForAmnesiaTest(t)
	first := device.DetachDevice(dev)
	client := newClientWithDeviceForTest(t, first)
	profile := deviceTestProfile(t)
	peerKey, err := device.ParsePublicKey(profile.Peer.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if err := client.ApplyProfile(profile); err != nil {
		t.Fatalf("ApplyProfile through detached wrapper: %v", err)
	}
	if _, ok := dev.PeerSpec(peerKey); !ok {
		t.Fatal("ApplyProfile did not add the tracked peer")
	}

	if got := client.DetachDevice(); got != first {
		t.Fatal("DetachDevice returned the wrong wrapper")
	}
	if _, ok := dev.PeerSpec(peerKey); !ok {
		t.Fatal("DetachDevice removed the tracked peer without closing the wrapper")
	}
	if err := client.AttachDevice(first); err != nil {
		t.Fatalf("reattach same wrapper: %v", err)
	}
	if err := client.ApplyProfile(profile); err != nil {
		t.Fatalf("ApplyProfile after reattach: %v", err)
	}

	second := device.DetachDevice(dev)
	previous, err := client.ReplaceDevice(second)
	if err != nil {
		t.Fatalf("ReplaceDevice: %v", err)
	}
	previous.Close()
	if _, ok := dev.PeerSpec(peerKey); ok {
		t.Fatal("closing the replaced wrapper did not remove its tracked peer")
	}
	if err := client.ApplyProfile(profile); err != nil {
		t.Fatalf("ApplyProfile through replacement wrapper: %v", err)
	}
	if _, ok := dev.PeerSpec(peerKey); !ok {
		t.Fatal("replacement wrapper did not add the tracked peer")
	}

	previous, err = client.ReplaceDevice(dev)
	if err != nil {
		t.Fatalf("replace wrapper with concrete Device: %v", err)
	}
	previous.Close()
	if err := client.ApplyProfile(profile); err != nil {
		t.Fatalf("ApplyProfile through concrete Device: %v", err)
	}
	if got := client.DetachDevice(); got != dev {
		t.Fatal("DetachDevice did not return the concrete Device")
	}
	if _, ok := dev.PeerSpec(peerKey); !ok {
		t.Fatal("detaching concrete Device removed its peer")
	}
}

func TestClientApplyProfileThroughDetachedWrapperChain(t *testing.T) {
	dev := newDeviceForAmnesiaTest(t)
	inner := device.DetachDevice(dev)
	outer := device.DetachDevice(inner)
	client := newClientWithDeviceForTest(t, outer)
	profile := deviceTestProfile(t)
	peerKey, err := device.ParsePublicKey(profile.Peer.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if err := client.ApplyProfile(profile); err != nil {
		t.Fatalf("ApplyProfile through wrapper chain: %v", err)
	}
	if _, ok := dev.PeerSpec(peerKey); !ok {
		t.Fatal("ApplyProfile through wrapper chain did not add the peer")
	}

	outer.Close()
	if _, ok := dev.PeerSpec(peerKey); ok {
		t.Fatal("closing the outer wrapper did not remove its tracked peer")
	}
	select {
	case <-inner.Wait():
		t.Fatal("closing the outer wrapper closed the inner wrapper")
	default:
	}

	previous, err := client.ReplaceDevice(inner)
	if err != nil {
		t.Fatalf("replace closed outer wrapper with inner wrapper: %v", err)
	}
	if previous != outer {
		t.Fatal("ReplaceDevice did not return the closed outer wrapper")
	}
	if err := client.ApplyProfile(profile); err != nil {
		t.Fatalf("ApplyProfile through reattached inner wrapper: %v", err)
	}
	inner.Close()
	if _, ok := dev.PeerSpec(peerKey); ok {
		t.Fatal("closing the inner wrapper did not remove its tracked peer")
	}
	select {
	case <-dev.Wait():
		t.Fatal("closing the wrapper chain closed the concrete device")
	default:
	}
}

func TestApplyProfileUsesAttachedPrivateKeyWithoutExportingIt(t *testing.T) {
	dev := newDeviceForAmnesiaTest(t)
	profile := deviceTestProfile(t)
	privateKey, err := device.ParsePrivateKey(profile.Interface.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := dev.SetPrivateKey(privateKey); err != nil {
		t.Fatal(err)
	}
	profile.Interface.PrivateKey = ""
	wrapper := device.DetachDevice(dev)

	if err := ApplyProfile(wrapper, profile); err != nil {
		t.Fatalf("ApplyProfile with attached private key: %v", err)
	}
	peerKey, err := device.ParsePublicKey(profile.Peer.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := dev.PeerSpec(peerKey); !ok {
		t.Fatal("ApplyProfile did not add the public-only profile peer")
	}
	wrapper.Close()
	if _, ok := dev.PeerSpec(peerKey); ok {
		t.Fatal("closing wrapper did not remove the public-only profile peer")
	}
}

func TestClientRejectsClosedDeviceImplementation(t *testing.T) {
	dev := newDeviceForAmnesiaTest(t)
	closed := device.DetachDevice(dev)
	closed.Close()
	client := newClientWithDeviceForTest(t, nil)

	if err := client.AttachDevice(closed); !errors.Is(err, device.ErrDeviceClosed) {
		t.Fatalf("AttachDevice error = %v, want %v", err, device.ErrDeviceClosed)
	}
	if _, err := client.ReplaceDevice(closed); !errors.Is(err, device.ErrDeviceClosed) {
		t.Fatalf("ReplaceDevice error = %v, want %v", err, device.ErrDeviceClosed)
	}
}

func TestClientUsesAttachedDeviceIdentityForNegotiation(t *testing.T) {
	dev := newDeviceForAmnesiaTest(t)
	privateKey, publicKey := testWireGuardKeypair(t, 0x71)
	parsedPrivateKey, err := device.ParsePrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := dev.SetPrivateKey(parsedPrivateKey); err != nil {
		t.Fatal(err)
	}
	wrapper := device.DetachDevice(dev)
	client := newClientWithDeviceForTest(t, wrapper)

	negotiation, err := client.Start(testActivationKey(t), NegotiationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if negotiation.publicKey != publicKey || negotiation.privateKey != "" {
		t.Fatalf(
			"attached identity = (%q, private=%v), want (%q, private=false)",
			negotiation.publicKey,
			negotiation.privateKey != "",
			publicKey,
		)
	}

	if got := client.DetachDevice(); got != wrapper {
		t.Fatal("DetachDevice returned the wrong wrapper")
	}
	generated, err := client.Start(testActivationKey(t), NegotiationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if generated.privateKey == "" {
		t.Fatal("negotiation without an attached identity did not generate a key")
	}
	if err := client.AttachDevice(wrapper); err != nil {
		t.Fatal(err)
	}
	reused, err := client.Start(testActivationKey(t), NegotiationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if reused.publicKey != publicKey || reused.privateKey != "" {
		t.Fatal("reattached implementation did not restore its identity selection")
	}

	_, explicitPublicKey := testWireGuardKeypair(t, 0x79)
	explicit, err := client.Start(testActivationKey(t), NegotiationOptions{
		WireGuardPublicKey: explicitPublicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if explicit.publicKey != explicitPublicKey || explicit.privateKey != "" {
		t.Fatal("explicit public key did not take priority over the attached identity")
	}

	otherDevice := newDeviceForAmnesiaTest(t)
	otherPrivateKey, otherPublicKey := testWireGuardKeypair(t, 0x21)
	parsedOtherPrivateKey, err := device.ParsePrivateKey(otherPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := otherDevice.SetPrivateKey(parsedOtherPrivateKey); err != nil {
		t.Fatal(err)
	}
	replacement := device.DetachDevice(otherDevice)
	previous, err := client.ReplaceDevice(replacement)
	if err != nil {
		t.Fatal(err)
	}
	if previous != wrapper {
		t.Fatal("ReplaceDevice returned the wrong identity implementation")
	}
	switched, err := client.Start(testActivationKey(t), NegotiationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if switched.publicKey != otherPublicKey || switched.privateKey != "" {
		t.Fatal("replacement implementation did not change the identity for a new negotiation")
	}
}

func TestClientApplyProfileWithoutDevice(t *testing.T) {
	client := newClientWithDeviceForTest(t, nil)
	if err := client.ApplyProfile(deviceTestProfile(t)); !errors.Is(err, ErrDeviceRequired) {
		t.Fatalf("ApplyProfile error = %v, want %v", err, ErrDeviceRequired)
	}
}

func TestNewClientNormalizesTypedNilDevice(t *testing.T) {
	var nilWrapper *device.DetachedDevice
	client := newClientWithDeviceForTest(t, nilWrapper)
	if client.Device() != nil {
		t.Fatal("typed nil Device option was retained as an attachment")
	}
}

func TestClientConcurrentApplyAndReplaceDevice(t *testing.T) {
	firstDevice := newDeviceForAmnesiaTest(t)
	secondDevice := newDeviceForAmnesiaTest(t)
	first := device.DetachDevice(firstDevice)
	second := device.DetachDevice(secondDevice)
	client := newClientWithDeviceForTest(t, first)
	profile := deviceTestProfile(t)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 25 {
				if err := client.ApplyProfile(profile); err != nil {
					t.Errorf("ApplyProfile: %v", err)
					return
				}
			}
		}()
	}
	for i := range 100 {
		next := device.DeviceAPI(first)
		if i%2 == 1 {
			next = second
		}
		if _, err := client.ReplaceDevice(next); err != nil {
			t.Fatalf("ReplaceDevice: %v", err)
		}
	}
	wg.Wait()

	first.Close()
	second.Close()
	if len(firstDevice.Config().Peers) != 0 || len(secondDevice.Config().Peers) != 0 {
		t.Fatal("closing both wrappers left a concurrently applied tracked peer")
	}
}
