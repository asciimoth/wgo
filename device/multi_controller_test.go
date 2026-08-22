/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

func TestUpsertPeerClonesSpecAndDeletePeer(t *testing.T) {
	dev := NewDevice(newChannelTUN().TUN(), &fakeTransitionBind{id: "default", size: 1}, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	peerKey := mustPrivateKey(t, 131).PublicKey()
	allowedIPs := []netip.Prefix{netip.MustParsePrefix("10.131.0.0/24")}
	endpoint := &PeerEndpoint{Transport: DefaultTransportID, Address: "127.0.0.1:13100"}
	spec := PeerSpec{
		PublicKey:       peerKey,
		ProtocolVersion: 1,
		Endpoint:        endpoint,
		AllowedIPs:      allowedIPs,
		Activation:      PeerActivationOnDemand,
	}
	if err := dev.UpsertPeer(spec); err != nil {
		t.Fatalf("UpsertPeer: %v", err)
	}

	allowedIPs[0] = netip.MustParsePrefix("10.132.0.0/24")
	endpoint.Address = "127.0.0.1:13200"

	got, ok := dev.PeerSpec(peerKey)
	if !ok {
		t.Fatal("PeerSpec() reported missing peer")
	}
	if got.Endpoint == nil || got.Endpoint.Address != "127.0.0.1:13100" {
		t.Fatalf("PeerSpec().Endpoint = %+v, want original address", got.Endpoint)
	}
	if !slices.Equal(got.AllowedIPs, []netip.Prefix{netip.MustParsePrefix("10.131.0.0/24")}) {
		t.Fatalf("PeerSpec().AllowedIPs = %v, want original prefix", got.AllowedIPs)
	}

	got.AllowedIPs[0] = netip.MustParsePrefix("10.133.0.0/24")
	got.Endpoint.Address = "127.0.0.1:13300"
	again, ok := dev.PeerSpec(peerKey)
	if !ok {
		t.Fatal("PeerSpec() after returned mutation reported missing peer")
	}
	if again.Endpoint == nil || again.Endpoint.Address != "127.0.0.1:13100" {
		t.Fatalf("PeerSpec() after returned mutation endpoint = %+v, want stored address", again.Endpoint)
	}
	if !slices.Equal(again.AllowedIPs, []netip.Prefix{netip.MustParsePrefix("10.131.0.0/24")}) {
		t.Fatalf("PeerSpec() after returned mutation allowed IPs = %v, want stored prefix", again.AllowedIPs)
	}

	snapshot, ok := dev.PeerSnapshot(peerKey)
	if !ok {
		t.Fatal("PeerSnapshot() reported missing peer")
	}
	if snapshot.Active {
		t.Fatal("PeerSnapshot().Active = true, want false for on-demand peer before traffic")
	}
	if snapshot.Revision != 1 {
		t.Fatalf("PeerSnapshot().Revision = %d, want 1", snapshot.Revision)
	}

	deleted, err := dev.DeletePeer(peerKey)
	if err != nil {
		t.Fatalf("DeletePeer: %v", err)
	}
	if !deleted {
		t.Fatal("DeletePeer() deleted = false, want true")
	}
	deleted, err = dev.DeletePeer(peerKey)
	if err != nil {
		t.Fatalf("DeletePeer second call: %v", err)
	}
	if deleted {
		t.Fatal("DeletePeer() second call deleted = true, want false")
	}
}

func TestNamedTransportPeerSendReplaceAndRemove(t *testing.T) {
	dev := NewDevice(newChannelTUN().TUN(), &fakeTransitionBind{id: "default", size: 1}, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	const transportID TransportID = "test/named"
	bind1 := &fakeTransitionBind{id: "named-1", size: 1}
	if err := dev.AddTransport(transportID, TransportConfig{Bind: bind1, ListenPort: 10001, Fwmark: 7}); err != nil {
		t.Fatalf("AddTransport: %v", err)
	}
	info, ok := dev.TransportInfo(transportID)
	if !ok {
		t.Fatal("TransportInfo() reported missing named transport")
	}
	if !info.Up || info.Generation != 1 || info.ListenPort != 10001 || info.Fwmark != 7 {
		t.Fatalf("TransportInfo() = %+v, want up generation 1 port 10001 fwmark 7", info)
	}

	peerKey := mustPrivateKey(t, 132).PublicKey()
	if err := dev.UpsertPeer(PeerSpec{
		PublicKey:       peerKey,
		ProtocolVersion: 1,
		Endpoint:        &PeerEndpoint{Transport: transportID, Address: "named-peer"},
		Activation:      PeerActivationEager,
	}); err != nil {
		t.Fatalf("UpsertPeer: %v", err)
	}

	peer := dev.LookupPeer(peerKey)
	if peer == nil {
		t.Fatal("LookupPeer() reported missing peer")
	}
	if err := peer.SendBuffers([][]byte{[]byte("hello")}); err != nil {
		t.Fatalf("SendBuffers through named transport: %v", err)
	}
	peer.SetEndpointFromPacket(fakeBindEndpoint{bindID: bind1.id, dst: "learned-peer"}, transportID)
	gotSpec, ok := dev.PeerSpec(peerKey)
	if !ok {
		t.Fatal("PeerSpec() after roaming reported missing peer")
	}
	if gotSpec.Endpoint == nil || gotSpec.Endpoint.Address != "named-peer" {
		t.Fatalf("PeerSpec() endpoint after roaming = %+v, want configured named-peer", gotSpec.Endpoint)
	}

	bind2 := &fakeTransitionBind{id: "named-2", size: 1}
	if err := dev.ReplaceTransport(transportID, TransportConfig{Bind: bind2, ListenPort: 10002}); err != nil {
		t.Fatalf("ReplaceTransport: %v", err)
	}
	info, ok = dev.TransportInfo(transportID)
	if !ok {
		t.Fatal("TransportInfo() after replace reported missing transport")
	}
	if info.Generation != 2 || info.ListenPort != 10002 {
		t.Fatalf("TransportInfo() after replace = %+v, want generation 2 port 10002", info)
	}
	if err := peer.SendBuffers([][]byte{[]byte("hello again")}); err != nil {
		t.Fatalf("SendBuffers through replaced named transport: %v", err)
	}

	if err := dev.RemoveTransport(transportID); err != nil {
		t.Fatalf("RemoveTransport: %v", err)
	}
	if _, ok := dev.TransportInfo(transportID); ok {
		t.Fatal("TransportInfo() after remove reported present transport")
	}
	gotSpec, ok = dev.PeerSpec(peerKey)
	if !ok {
		t.Fatal("PeerSpec() after RemoveTransport reported missing peer")
	}
	if gotSpec.Endpoint == nil || gotSpec.Endpoint.Transport != transportID || gotSpec.Endpoint.Address != "named-peer" {
		t.Fatalf("PeerSpec() after RemoveTransport endpoint = %+v, want named transport endpoint", gotSpec.Endpoint)
	}
	if err := peer.SendBuffers([][]byte{[]byte("after remove")}); !errors.Is(err, ErrTransportUnavailable) {
		t.Fatalf("SendBuffers after RemoveTransport = %v, want ErrTransportUnavailable", err)
	}

	bind3 := &fakeTransitionBind{id: "named-3", size: 1}
	if err := dev.AddTransport(transportID, TransportConfig{Bind: bind3, ListenPort: 10003}); err != nil {
		t.Fatalf("AddTransport after remove: %v", err)
	}
	if err := peer.SendBuffers([][]byte{[]byte("after readd")}); err != nil {
		t.Fatalf("SendBuffers through readded named transport: %v", err)
	}
}

func TestConcurrentNamedTransportSendAndReplace(t *testing.T) {
	dev := NewDevice(newChannelTUN().TUN(), &fakeTransitionBind{id: "default", size: 1}, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	const transportID TransportID = "test/concurrent"
	if err := dev.AddTransport(transportID, TransportConfig{Bind: &fakeTransitionBind{id: "named-0", size: 1}}); err != nil {
		t.Fatalf("AddTransport: %v", err)
	}
	peerKey := mustPrivateKey(t, 138).PublicKey()
	if err := dev.UpsertPeer(PeerSpec{
		PublicKey:       peerKey,
		ProtocolVersion: 1,
		Endpoint:        &PeerEndpoint{Transport: transportID, Address: "named-peer"},
		Activation:      PeerActivationEager,
	}); err != nil {
		t.Fatalf("UpsertPeer: %v", err)
	}
	peer := dev.LookupPeer(peerKey)
	if peer == nil {
		t.Fatal("LookupPeer() reported missing peer")
	}

	var done atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !done.Load() {
			if err := peer.SendBuffers([][]byte{[]byte("packet")}); err != nil {
				t.Errorf("SendBuffers during ReplaceTransport: %v", err)
				return
			}
		}
	}()

	for i := 1; i <= 50; i++ {
		bind := &fakeTransitionBind{id: "named-" + strconv.Itoa(i), size: 1}
		if err := dev.ReplaceTransport(transportID, TransportConfig{Bind: bind}); err != nil {
			done.Store(true)
			wg.Wait()
			t.Fatalf("ReplaceTransport iteration %d: %v", i, err)
		}
	}
	done.Store(true)
	wg.Wait()
}

func TestOnDemandPeerStaysInactiveOnUpAndActiveLimitRollsBack(t *testing.T) {
	dev := NewDevice(newChannelTUN().TUN(), &fakeTransitionBind{id: "default", size: 1}, NewLogger(LogLevelError, ""), nil, DeviceOptions{MaxActivePeers: 1})
	t.Cleanup(dev.Close)

	onDemandKey := mustPrivateKey(t, 133).PublicKey()
	onDemandSpec := PeerSpec{
		PublicKey:       onDemandKey,
		ProtocolVersion: 1,
		Endpoint:        &PeerEndpoint{Address: "127.0.0.1:13300"},
		Activation:      PeerActivationOnDemand,
	}
	if err := dev.UpsertPeer(onDemandSpec); err != nil {
		t.Fatalf("UpsertPeer on-demand while down: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	snapshot, ok := dev.PeerSnapshot(onDemandKey)
	if !ok {
		t.Fatal("PeerSnapshot() reported missing on-demand peer")
	}
	if snapshot.Active {
		t.Fatal("on-demand peer became active during Up")
	}
	if dev.LookupPeer(onDemandKey) == nil {
		t.Fatal("LookupPeer() reported missing configured on-demand peer")
	}
	if active := dev.LookupActivePeer(onDemandKey); active != nil {
		t.Fatalf("LookupActivePeer() = %v, want nil for inactive configured peer", active)
	}

	activeKey := mustPrivateKey(t, 134).PublicKey()
	if err := dev.UpsertPeer(PeerSpec{
		PublicKey:       activeKey,
		ProtocolVersion: 1,
		Endpoint:        &PeerEndpoint{Address: "127.0.0.1:13400"},
		Activation:      PeerActivationEager,
	}); err != nil {
		t.Fatalf("UpsertPeer eager: %v", err)
	}

	changed := onDemandSpec
	changed.Endpoint = &PeerEndpoint{Address: "127.0.0.1:13301"}
	changed.Activation = PeerActivationEager
	if err := dev.UpsertPeer(changed); !errors.Is(err, ErrActivePeerLimit) {
		t.Fatalf("UpsertPeer over active limit = %v, want ErrActivePeerLimit", err)
	}
	got, ok := dev.PeerSpec(onDemandKey)
	if !ok {
		t.Fatal("PeerSpec() after failed eager update reported missing peer")
	}
	if got.Endpoint == nil || got.Endpoint.Address != onDemandSpec.Endpoint.Address || got.Activation != PeerActivationOnDemand {
		t.Fatalf("PeerSpec() after failed eager update = %+v, want original on-demand spec", got)
	}

	newKey := mustPrivateKey(t, 135).PublicKey()
	if err := dev.UpsertPeer(PeerSpec{
		PublicKey:       newKey,
		ProtocolVersion: 1,
		Endpoint:        &PeerEndpoint{Address: "127.0.0.1:13500"},
		Activation:      PeerActivationEager,
	}); !errors.Is(err, ErrActivePeerLimit) {
		t.Fatalf("UpsertPeer new eager over active limit = %v, want ErrActivePeerLimit", err)
	}
	if _, ok := dev.PeerSpec(newKey); ok {
		t.Fatal("failed new eager UpsertPeer left a configured peer behind")
	}
}

func TestUpsertEagerPeerWhileDownStartsOnUp(t *testing.T) {
	dev := NewDevice(nil, &fakeTransitionBind{id: "default", size: 1}, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(dev.Close)

	peerKey := mustPrivateKey(t, 139).PublicKey()
	if err := dev.UpsertPeer(PeerSpec{
		PublicKey:       peerKey,
		ProtocolVersion: 1,
		Endpoint:        &PeerEndpoint{Address: "127.0.0.1:13900"},
		Activation:      PeerActivationEager,
	}); err != nil {
		t.Fatalf("UpsertPeer while down: %v", err)
	}
	snapshot, ok := dev.PeerSnapshot(peerKey)
	if !ok {
		t.Fatal("PeerSnapshot() reported missing peer")
	}
	if snapshot.Active {
		t.Fatal("eager peer became active before device Up")
	}

	if err := dev.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	snapshot, ok = dev.PeerSnapshot(peerKey)
	if !ok {
		t.Fatal("PeerSnapshot() after Up reported missing peer")
	}
	if !snapshot.Active {
		t.Fatal("eager peer stayed inactive after device Up")
	}
}

func TestLookupActivePeerReportsOnlyRunningPeer(t *testing.T) {
	dev := NewDevice(newChannelTUN().TUN(), &fakeTransitionBind{id: "default", size: 1}, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	peerKey := mustPrivateKey(t, 137).PublicKey()
	if err := dev.UpsertPeer(PeerSpec{
		PublicKey:       peerKey,
		ProtocolVersion: 1,
		Endpoint:        &PeerEndpoint{Address: "127.0.0.1:13700"},
		Activation:      PeerActivationOnDemand,
	}); err != nil {
		t.Fatalf("UpsertPeer: %v", err)
	}
	if peer := dev.LookupActivePeer(peerKey); peer != nil {
		t.Fatalf("LookupActivePeer() before activation = %v, want nil", peer)
	}
	if err := dev.ActivatePeer(peerKey); err != nil {
		t.Fatalf("ActivatePeer: %v", err)
	}
	if peer := dev.LookupActivePeer(peerKey); peer == nil {
		t.Fatal("LookupActivePeer() after activation reported missing peer")
	}
	dev.RemovePeer(peerKey)
	if peer := dev.LookupActivePeer(peerKey); peer != nil {
		t.Fatalf("LookupActivePeer() after RemovePeer = %v, want nil", peer)
	}
}

func TestDefaultBindFwmarkSurvivesDetachAttach(t *testing.T) {
	dev := NewDevice(newChannelTUN().TUN(), &fakeTransitionBind{id: "default", size: 1}, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	if err := dev.SetFwmark(42); err != nil {
		t.Fatalf("SetFwmark: %v", err)
	}
	if err := dev.DetachBind(); err != nil {
		t.Fatalf("DetachBind: %v", err)
	}
	if got := dev.Fwmark(); got != 42 {
		t.Fatalf("Fwmark after DetachBind = %d, want 42", got)
	}
	if err := dev.AttachBind(&fakeTransitionBind{id: "reattached", size: 1}); err != nil {
		t.Fatalf("AttachBind: %v", err)
	}
	if got := dev.Fwmark(); got != 42 {
		t.Fatalf("Fwmark after AttachBind = %d, want 42", got)
	}
}

func TestReplaceDefaultTransportAppliesListenPortAndFwmark(t *testing.T) {
	dev := NewDevice(newChannelTUN().TUN(), &fakeTransitionBind{id: "default", size: 1}, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	replacement := &fakeTransitionBind{id: "replacement", size: 1}
	if err := dev.ReplaceTransport(DefaultTransportID, TransportConfig{
		Bind:       replacement,
		ListenPort: 51821,
		Fwmark:     99,
	}); err != nil {
		t.Fatalf("ReplaceTransport(default): %v", err)
	}

	info, ok := dev.TransportInfo(DefaultTransportID)
	if !ok {
		t.Fatal("TransportInfo(default) reported missing transport")
	}
	if info.ListenPort != 51821 || info.Fwmark != 99 {
		t.Fatalf("TransportInfo(default) = %+v, want listen port 51821 fwmark 99", info)
	}
	if got := dev.ListenPort(); got != 51821 {
		t.Fatalf("ListenPort() = %d, want 51821", got)
	}
	if got := dev.Fwmark(); got != 99 {
		t.Fatalf("Fwmark() = %d, want 99", got)
	}
	if got := replacement.mark.Load(); got != 99 {
		t.Fatalf("replacement SetMark got %d, want 99", got)
	}
}

func TestErrPeerNotFoundSupportsErrorsIs(t *testing.T) {
	dev := NewDevice(newChannelTUN().TUN(), nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(dev.Close)

	err := dev.SetPeerProtocolVersion(mustPrivateKey(t, 136).PublicKey(), 1)
	if !errors.Is(err, ErrPeerNotFound) {
		t.Fatalf("SetPeerProtocolVersion missing peer = %v, want ErrPeerNotFound", err)
	}
}

func TestConcurrentUpsertPeerDeletePeerDisjointPeers(t *testing.T) {
	dev := NewDevice(newChannelTUN().TUN(), &fakeTransitionBind{id: "default", size: 1}, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(dev.Close)

	const workers = 4
	const iterations = 40
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			peerKey := mustPrivateKey(t, byte(140+worker)).PublicKey()
			prefix := netip.MustParsePrefix("10." + string(rune('0'+worker)) + ".0.0/24")
			for i := 0; i < iterations; i++ {
				err := dev.UpsertPeer(PeerSpec{
					PublicKey:       peerKey,
					ProtocolVersion: 1,
					Endpoint:        &PeerEndpoint{Address: "127.0.0.1:14000"},
					AllowedIPs:      []netip.Prefix{prefix},
					Activation:      PeerActivationOnDemand,
				})
				if err != nil {
					t.Errorf("UpsertPeer worker %d iteration %d: %v", worker, i, err)
					return
				}
				if _, ok := dev.PeerSnapshot(peerKey); !ok {
					t.Errorf("PeerSnapshot worker %d iteration %d reported missing peer", worker, i)
					return
				}
				if _, err := dev.DeletePeer(peerKey); err != nil {
					t.Errorf("DeletePeer worker %d iteration %d: %v", worker, i, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
