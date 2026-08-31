/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newDeviceAPIForTest(t *testing.T) *Device {
	t.Helper()
	dev := NewDevice(nil, nil, NopLogger{}, nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)
	return dev
}

func detachedTestPeer(seed byte) PeerSpec {
	var key NoisePublicKey
	key[0] = seed
	return PeerSpec{PublicKey: key, ProtocolVersion: 1}
}

func newDetachedTestTUN() *fakeTUNDeviceSized {
	tunDevice := &fakeTUNDeviceSized{size: 1}
	tunDevice.ensureInit()
	return tunDevice
}

func waitForDetachedDeviceClose(t *testing.T, name string, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("%s stayed open", name)
	}
}

func requireDetachedDeviceOpen(t *testing.T, name string, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
		t.Fatalf("%s closed", name)
	default:
	}
}

func TestDetachDeviceDoesNotCloseWrappedDevice(t *testing.T) {
	dev := newDeviceAPIForTest(t)
	detached := DetachDevice(dev)

	detached.Close()

	select {
	case <-dev.Wait():
		t.Fatal("DetachDevice.Close closed the wrapped device")
	default:
	}
	if err := dev.UpsertPeer(detachedTestPeer(1)); err != nil {
		t.Fatalf("wrapped device is not usable after wrapper Close: %v", err)
	}
	if _, ok := dev.PeerSpec(detachedTestPeer(1).PublicKey); !ok {
		t.Fatal("wrapped device did not retain a peer added after wrapper Close")
	}
}

func TestDeviceTrackedMethodsUseDeviceLifetime(t *testing.T) {
	dev := newDeviceAPIForTest(t)
	peer := detachedTestPeer(39)

	if err := dev.UpsertTrackedPeer(peer); err != nil {
		t.Fatalf("UpsertTrackedPeer: %v", err)
	}
	if _, ok := dev.PeerSpec(peer.PublicKey); !ok {
		t.Fatal("UpsertTrackedPeer did not add the peer")
	}
	if deleted, err := dev.DeleteTrackedPeer(peer.PublicKey); err != nil || !deleted {
		t.Fatalf("DeleteTrackedPeer = (%v, %v), want (true, nil)", deleted, err)
	}

	const transportID TransportID = "tracked-device"
	if err := dev.AddTrackedTransport(
		transportID,
		TransportConfig{Bind: &fakeTransitionBind{id: "first", size: 1}},
	); err != nil {
		t.Fatalf("AddTrackedTransport: %v", err)
	}
	if err := dev.ReplaceTrackedTransport(
		transportID,
		TransportConfig{Bind: &fakeTransitionBind{id: "second", size: 1}},
	); err != nil {
		t.Fatalf("ReplaceTrackedTransport: %v", err)
	}
	if info, ok := dev.TransportInfo(transportID); !ok || info.Generation != 2 {
		t.Fatalf("TransportInfo = (%+v, %v), want generation 2", info, ok)
	}
	if err := dev.RemoveTrackedTransport(transportID); err != nil {
		t.Fatalf("RemoveTrackedTransport: %v", err)
	}
}

func TestDetachedDeviceWrappersAreIndependent(t *testing.T) {
	dev := newDeviceAPIForTest(t)
	first := DetachDevice(dev)
	second := DetachDevice(dev)

	first.Close()
	if err := first.UpsertPeer(detachedTestPeer(1)); !errors.Is(err, ErrDeviceClosed) {
		t.Fatalf("first UpsertPeer error = %v, want %v", err, ErrDeviceClosed)
	}
	if err := second.UpsertPeer(detachedTestPeer(2)); err != nil {
		t.Fatalf("second wrapper was affected by first wrapper Close: %v", err)
	}
	if _, ok := second.PeerSpec(detachedTestPeer(2).PublicKey); !ok {
		t.Fatal("second wrapper cannot read its peer")
	}

	second.Close()
	select {
	case <-dev.Wait():
		t.Fatal("closing all wrappers closed the wrapped device")
	default:
	}
}

func TestDetachedDeviceCloseReleasesOnlyTrackedPeersAndTransports(t *testing.T) {
	dev := newDeviceAPIForTest(t)
	detached := DetachDevice(dev)
	plainPeer := detachedTestPeer(40)
	trackedPeer := detachedTestPeer(41)

	if err := detached.UpsertPeer(plainPeer); err != nil {
		t.Fatalf("UpsertPeer: %v", err)
	}
	if err := detached.UpsertTrackedPeer(trackedPeer); err != nil {
		t.Fatalf("UpsertTrackedPeer: %v", err)
	}
	if err := detached.AddTransport(
		"plain",
		TransportConfig{Bind: &fakeTransitionBind{id: "plain", size: 1}},
	); err != nil {
		t.Fatalf("AddTransport: %v", err)
	}
	if err := detached.AddTrackedTransport(
		"tracked",
		TransportConfig{Bind: &fakeTransitionBind{id: "tracked", size: 1}},
	); err != nil {
		t.Fatalf("AddTrackedTransport: %v", err)
	}

	detached.Close()

	if _, ok := dev.PeerSpec(plainPeer.PublicKey); !ok {
		t.Fatal("Close removed a peer added by the untracked method")
	}
	if _, ok := dev.PeerSpec(trackedPeer.PublicKey); ok {
		t.Fatal("Close did not remove the tracked peer")
	}
	if _, ok := dev.TransportInfo("plain"); !ok {
		t.Fatal("Close removed a transport added by the untracked method")
	}
	if _, ok := dev.TransportInfo("tracked"); ok {
		t.Fatal("Close did not remove the tracked transport")
	}
	requireDetachedDeviceOpen(t, "concrete device", dev.Wait())
}

func TestDetachedDeviceCloseDetachesTrackedAttachments(t *testing.T) {
	dev := newDeviceAPIForTest(t)
	detached := DetachDevice(dev)
	tunDevice := newDetachedTestTUN()

	if err := detached.AttachTrackedTUN(tunDevice); err != nil {
		t.Fatalf("AttachTrackedTUN: %v", err)
	}
	if err := detached.AttachTrackedBind(&fakeTransitionBind{id: "tracked-bind", size: 1}); err != nil {
		t.Fatalf("AttachTrackedBind: %v", err)
	}

	detached.Close()

	if dev.currentTUN() != nil {
		t.Fatal("Close did not detach the tracked TUN")
	}
	if _, ok := dev.TransportInfo(DefaultTransportID); ok {
		t.Fatal("Close did not detach the tracked bind")
	}
}

func TestDetachedDeviceTrackedReplacementAssignsResources(t *testing.T) {
	dev := newDeviceAPIForTest(t)
	if err := dev.AddTransport(
		"replace",
		TransportConfig{Bind: &fakeTransitionBind{id: "old", size: 1}},
	); err != nil {
		t.Fatalf("AddTransport: %v", err)
	}
	if err := dev.AttachTUN(newDetachedTestTUN()); err != nil {
		t.Fatalf("AttachTUN: %v", err)
	}
	if err := dev.AttachBind(&fakeTransitionBind{id: "old-bind", size: 1}); err != nil {
		t.Fatalf("AttachBind: %v", err)
	}
	detached := DetachDevice(dev)

	if err := detached.ReplaceTrackedTransport(
		"replace",
		TransportConfig{Bind: &fakeTransitionBind{id: "new", size: 1}},
	); err != nil {
		t.Fatalf("ReplaceTrackedTransport: %v", err)
	}
	if err := detached.ReplaceTrackedTUN(newDetachedTestTUN()); err != nil {
		t.Fatalf("ReplaceTrackedTUN: %v", err)
	}
	if err := detached.ReplaceTrackedBind(&fakeTransitionBind{id: "new-bind", size: 1}); err != nil {
		t.Fatalf("ReplaceTrackedBind: %v", err)
	}

	detached.Close()

	if _, ok := dev.TransportInfo("replace"); ok {
		t.Fatal("Close did not remove the tracked replacement transport")
	}
	if dev.currentTUN() != nil {
		t.Fatal("Close did not detach the tracked replacement TUN")
	}
	if _, ok := dev.TransportInfo(DefaultTransportID); ok {
		t.Fatal("Close did not detach the tracked replacement bind")
	}
}

func TestDetachedDeviceCloseLeavesUntrackedAttachments(t *testing.T) {
	dev := newDeviceAPIForTest(t)
	detached := DetachDevice(dev)
	tunDevice := newDetachedTestTUN()

	if err := detached.AttachTUN(tunDevice); err != nil {
		t.Fatalf("AttachTUN: %v", err)
	}
	if err := detached.AttachBind(&fakeTransitionBind{id: "plain-bind", size: 1}); err != nil {
		t.Fatalf("AttachBind: %v", err)
	}

	detached.Close()

	if dev.currentTUN() == nil {
		t.Fatal("Close detached a TUN attached by the untracked method")
	}
	if _, ok := dev.TransportInfo(DefaultTransportID); !ok {
		t.Fatal("Close detached a bind attached by the untracked method")
	}
}

func TestDetachedDeviceTrackedRemovalReleasesOwnership(t *testing.T) {
	dev := newDeviceAPIForTest(t)
	detached := DetachDevice(dev)
	peer := detachedTestPeer(42)

	if err := detached.UpsertTrackedPeer(peer); err != nil {
		t.Fatalf("UpsertTrackedPeer: %v", err)
	}
	if deleted, err := detached.DeleteTrackedPeer(peer.PublicKey); err != nil || !deleted {
		t.Fatalf("DeleteTrackedPeer = (%v, %v), want (true, nil)", deleted, err)
	}
	if err := dev.UpsertPeer(peer); err != nil {
		t.Fatalf("recreate peer: %v", err)
	}

	const transportID TransportID = "released"
	if err := detached.AddTrackedTransport(
		transportID,
		TransportConfig{Bind: &fakeTransitionBind{id: "tracked", size: 1}},
	); err != nil {
		t.Fatalf("AddTrackedTransport: %v", err)
	}
	if err := detached.RemoveTrackedTransport(transportID); err != nil {
		t.Fatalf("RemoveTrackedTransport: %v", err)
	}
	if err := dev.AddTransport(
		transportID,
		TransportConfig{Bind: &fakeTransitionBind{id: "replacement", size: 1}},
	); err != nil {
		t.Fatalf("recreate transport: %v", err)
	}

	if err := detached.AttachTrackedTUN(newDetachedTestTUN()); err != nil {
		t.Fatalf("AttachTrackedTUN: %v", err)
	}
	if err := detached.DetachTrackedTUN(); err != nil {
		t.Fatalf("DetachTrackedTUN: %v", err)
	}
	if err := dev.AttachTUN(newDetachedTestTUN()); err != nil {
		t.Fatalf("attach replacement TUN: %v", err)
	}

	if err := detached.AttachTrackedBind(&fakeTransitionBind{id: "tracked-bind", size: 1}); err != nil {
		t.Fatalf("AttachTrackedBind: %v", err)
	}
	if err := detached.DetachTrackedBind(); err != nil {
		t.Fatalf("DetachTrackedBind: %v", err)
	}
	if err := dev.AttachBind(&fakeTransitionBind{id: "replacement-bind", size: 1}); err != nil {
		t.Fatalf("attach replacement bind: %v", err)
	}

	detached.Close()

	if _, ok := dev.PeerSpec(peer.PublicKey); !ok {
		t.Fatal("Close removed a peer after DeleteTrackedPeer released ownership")
	}
	if _, ok := dev.TransportInfo(transportID); !ok {
		t.Fatal("Close removed a transport after RemoveTrackedTransport released ownership")
	}
	if dev.currentTUN() == nil {
		t.Fatal("Close removed a TUN after DetachTrackedTUN released ownership")
	}
	if _, ok := dev.TransportInfo(DefaultTransportID); !ok {
		t.Fatal("Close removed a bind after DetachTrackedBind released ownership")
	}
}

func TestDetachedDeviceFailedTrackedChangesDoNotAssignResources(t *testing.T) {
	dev := newDeviceAPIForTest(t)
	detached := DetachDevice(dev)
	peer := detachedTestPeer(43)
	if err := dev.UpsertPeer(peer); err != nil {
		t.Fatalf("UpsertPeer: %v", err)
	}
	invalidPeer := peer
	invalidPeer.ProtocolVersion = 0
	if err := detached.UpsertTrackedPeer(invalidPeer); err == nil {
		t.Fatal("UpsertTrackedPeer with an invalid peer succeeded")
	}
	if err := detached.AddTrackedTransport("failed", TransportConfig{}); err == nil {
		t.Fatal("AddTrackedTransport with a nil bind succeeded")
	}
	if err := dev.AddTransport(
		"failed",
		TransportConfig{Bind: &fakeTransitionBind{id: "replacement", size: 1}},
	); err != nil {
		t.Fatalf("AddTransport after failed tracked add: %v", err)
	}
	if err := dev.AddTransport(
		"failed-replace",
		TransportConfig{Bind: &fakeTransitionBind{id: "original", size: 1}},
	); err != nil {
		t.Fatalf("AddTransport before failed tracked replace: %v", err)
	}
	if err := detached.ReplaceTrackedTransport("failed-replace", TransportConfig{}); err == nil {
		t.Fatal("ReplaceTrackedTransport with a nil bind succeeded")
	}
	if err := dev.AttachTUN(newDetachedTestTUN()); err != nil {
		t.Fatalf("AttachTUN: %v", err)
	}
	if err := detached.AttachTrackedTUN(newDetachedTestTUN()); err == nil {
		t.Fatal("AttachTrackedTUN with an occupied slot succeeded")
	}
	if err := dev.AttachBind(&fakeTransitionBind{id: "original-bind", size: 1}); err != nil {
		t.Fatalf("AttachBind: %v", err)
	}
	if err := detached.AttachTrackedBind(&fakeTransitionBind{id: "failed-bind", size: 1}); err == nil {
		t.Fatal("AttachTrackedBind with an occupied slot succeeded")
	}

	detached.Close()

	if _, ok := dev.PeerSpec(peer.PublicKey); !ok {
		t.Fatal("failed tracked upsert assigned and removed the existing peer")
	}
	if _, ok := dev.TransportInfo("failed"); !ok {
		t.Fatal("failed tracked add assigned and removed the later transport")
	}
	if _, ok := dev.TransportInfo("failed-replace"); !ok {
		t.Fatal("failed tracked replace assigned and removed the existing transport")
	}
	if dev.currentTUN() == nil {
		t.Fatal("failed tracked TUN attach assigned and removed the existing TUN")
	}
	if _, ok := dev.TransportInfo(DefaultTransportID); !ok {
		t.Fatal("failed tracked bind attach assigned and removed the existing bind")
	}
}

func TestDetachedDeviceChainOuterCloseIsLocal(t *testing.T) {
	dev := newDeviceAPIForTest(t)
	inner := DetachDevice(dev)
	outer := DetachDevice(inner)

	if outer.GetWrapped() != inner {
		t.Fatal("outer wrapper does not wrap the inner wrapper")
	}
	outer.Close()

	waitForDetachedDeviceClose(t, "outer wrapper", outer.Wait())
	requireDetachedDeviceOpen(t, "inner wrapper", inner.Wait())
	requireDetachedDeviceOpen(t, "concrete device", dev.Wait())

	peer := detachedTestPeer(10)
	if err := inner.UpsertPeer(peer); err != nil {
		t.Fatalf("inner wrapper is not usable after outer Close: %v", err)
	}
	if _, ok := inner.PeerSpec(peer.PublicKey); !ok {
		t.Fatal("inner wrapper cannot read a peer after outer Close")
	}
	if err := outer.UpsertPeer(detachedTestPeer(11)); !errors.Is(err, ErrDeviceClosed) {
		t.Fatalf("outer UpsertPeer error = %v, want %v", err, ErrDeviceClosed)
	}
}

func TestDetachedDeviceTrackedResourcesFollowOuterChainLifetime(t *testing.T) {
	dev := newDeviceAPIForTest(t)
	inner := DetachDevice(dev)
	outer := DetachDevice(inner)
	innerPeer := detachedTestPeer(50)
	outerPeer := detachedTestPeer(51)

	if err := inner.UpsertTrackedPeer(innerPeer); err != nil {
		t.Fatalf("inner UpsertTrackedPeer: %v", err)
	}
	if err := outer.UpsertTrackedPeer(outerPeer); err != nil {
		t.Fatalf("outer UpsertTrackedPeer: %v", err)
	}
	if err := inner.AddTrackedTransport(
		"inner",
		TransportConfig{Bind: &fakeTransitionBind{id: "inner", size: 1}},
	); err != nil {
		t.Fatalf("inner AddTrackedTransport: %v", err)
	}
	if err := outer.AddTrackedTransport(
		"outer",
		TransportConfig{Bind: &fakeTransitionBind{id: "outer", size: 1}},
	); err != nil {
		t.Fatalf("outer AddTrackedTransport: %v", err)
	}

	outer.Close()

	if _, ok := dev.PeerSpec(outerPeer.PublicKey); ok {
		t.Fatal("outer Close did not remove its tracked peer")
	}
	if _, ok := dev.TransportInfo("outer"); ok {
		t.Fatal("outer Close did not remove its tracked transport")
	}
	if _, ok := dev.PeerSpec(innerPeer.PublicKey); !ok {
		t.Fatal("outer Close removed the inner wrapper's tracked peer")
	}
	if _, ok := dev.TransportInfo("inner"); !ok {
		t.Fatal("outer Close removed the inner wrapper's tracked transport")
	}
	requireDetachedDeviceOpen(t, "inner wrapper", inner.Wait())

	if err := dev.UpsertPeer(outerPeer); err != nil {
		t.Fatalf("recreate outer peer: %v", err)
	}
	if err := dev.AddTransport(
		"outer",
		TransportConfig{Bind: &fakeTransitionBind{id: "outer-replacement", size: 1}},
	); err != nil {
		t.Fatalf("recreate outer transport: %v", err)
	}
	inner.Close()

	if _, ok := dev.PeerSpec(innerPeer.PublicKey); ok {
		t.Fatal("inner Close did not remove its tracked peer")
	}
	if _, ok := dev.TransportInfo("inner"); ok {
		t.Fatal("inner Close did not remove its tracked transport")
	}
	if _, ok := dev.PeerSpec(outerPeer.PublicKey); !ok {
		t.Fatal("inner retained ownership of the outer peer after outer Close")
	}
	if _, ok := dev.TransportInfo("outer"); !ok {
		t.Fatal("inner retained ownership of the outer transport after outer Close")
	}
}

func TestDetachedDeviceTrackedResourcesReleaseWhenInnerChainCloses(t *testing.T) {
	dev := newDeviceAPIForTest(t)
	inner := DetachDevice(dev)
	outer := DetachDevice(inner)
	peer := detachedTestPeer(52)

	if err := outer.UpsertTrackedPeer(peer); err != nil {
		t.Fatalf("UpsertTrackedPeer: %v", err)
	}
	if err := outer.AddTrackedTransport(
		"outer",
		TransportConfig{Bind: &fakeTransitionBind{id: "outer", size: 1}},
	); err != nil {
		t.Fatalf("AddTrackedTransport: %v", err)
	}
	if err := outer.AttachTrackedTUN(newDetachedTestTUN()); err != nil {
		t.Fatalf("AttachTrackedTUN: %v", err)
	}
	if err := outer.AttachTrackedBind(&fakeTransitionBind{id: "outer-bind", size: 1}); err != nil {
		t.Fatalf("AttachTrackedBind: %v", err)
	}

	inner.Close()

	waitForDetachedDeviceClose(t, "outer wrapper", outer.Wait())
	if _, ok := dev.PeerSpec(peer.PublicKey); ok {
		t.Fatal("inner Close did not remove the outer wrapper's tracked peer")
	}
	if _, ok := dev.TransportInfo("outer"); ok {
		t.Fatal("inner Close did not remove the outer wrapper's tracked transport")
	}
	if dev.currentTUN() != nil {
		t.Fatal("inner Close did not detach the outer wrapper's tracked TUN")
	}
	if _, ok := dev.TransportInfo(DefaultTransportID); ok {
		t.Fatal("inner Close did not detach the outer wrapper's tracked bind")
	}
	requireDetachedDeviceOpen(t, "concrete device", dev.Wait())
}

func TestDetachedDeviceChainMiddleClosePropagatesOutward(t *testing.T) {
	dev := newDeviceAPIForTest(t)
	inner := DetachDevice(dev)
	middle := DetachDevice(inner)
	outer := DetachDevice(middle)

	middle.Close()

	waitForDetachedDeviceClose(t, "middle wrapper", middle.Wait())
	waitForDetachedDeviceClose(t, "outer wrapper", outer.Wait())
	requireDetachedDeviceOpen(t, "inner wrapper", inner.Wait())
	requireDetachedDeviceOpen(t, "concrete device", dev.Wait())

	if err := inner.UpsertPeer(detachedTestPeer(12)); err != nil {
		t.Fatalf("inner wrapper is not usable after middle Close: %v", err)
	}
	for name, wrapper := range map[string]*DetachedDevice{
		"middle wrapper": middle,
		"outer wrapper":  outer,
	} {
		if err := wrapper.UpsertPeer(detachedTestPeer(13)); !errors.Is(err, ErrDeviceClosed) {
			t.Errorf("%s UpsertPeer error = %v, want %v", name, err, ErrDeviceClosed)
		}
	}
}

func TestDetachedDeviceChainConcreteClosePropagatesOutward(t *testing.T) {
	dev := newDeviceAPIForTest(t)
	wrappers := make([]*DetachedDevice, 4)
	var wrapped DeviceAPI = dev
	for i := range wrappers {
		wrappers[i] = DetachDevice(wrapped)
		wrapped = wrappers[i]
	}

	dev.Close()

	for i, wrapper := range wrappers {
		waitForDetachedDeviceClose(t, "wrapper "+string(rune('1'+i)), wrapper.Wait())
		if err := wrapper.UpsertPeer(detachedTestPeer(byte(20 + i))); !errors.Is(err, ErrDeviceClosed) {
			t.Errorf("wrapper %d UpsertPeer error = %v, want %v", i+1, err, ErrDeviceClosed)
		}
	}
}

func TestDetachDeviceAroundClosedWrapperIsClosed(t *testing.T) {
	dev := newDeviceAPIForTest(t)
	inner := DetachDevice(dev)
	inner.Close()

	outer := DetachDevice(inner)

	waitForDetachedDeviceClose(t, "outer wrapper", outer.Wait())
	requireDetachedDeviceOpen(t, "concrete device", dev.Wait())
}

func TestDetachedDeviceChainConcurrentClose(t *testing.T) {
	dev := newDeviceAPIForTest(t)
	wrappers := make([]*DetachedDevice, 8)
	var wrapped DeviceAPI = dev
	for i := range wrappers {
		wrappers[i] = DetachDevice(wrapped)
		wrapped = wrappers[i]
	}

	var wg sync.WaitGroup
	for caller := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				wrappers[caller%len(wrappers)].Close()
			}
		}()
	}
	wait := make(chan struct{})
	go func() {
		wg.Wait()
		close(wait)
	}()
	waitForDetachedDeviceClose(t, "concurrent Close calls", wait)

	for i, wrapper := range wrappers {
		waitForDetachedDeviceClose(t, "wrapper "+string(rune('1'+i)), wrapper.Wait())
	}
	requireDetachedDeviceOpen(t, "concrete device", dev.Wait())
	if err := dev.UpsertPeer(detachedTestPeer(30)); err != nil {
		t.Fatalf("concrete device is not usable after chain Close: %v", err)
	}
}

func TestDetachedDeviceConcurrentTrackedChangesAndClose(t *testing.T) {
	dev := newDeviceAPIForTest(t)
	detached := DetachDevice(dev)
	if err := detached.UpsertTrackedPeer(detachedTestPeer(60)); err != nil {
		t.Fatalf("initial UpsertTrackedPeer: %v", err)
	}
	if err := detached.AddTrackedTransport(
		"tracked-0",
		TransportConfig{Bind: &fakeTransitionBind{id: "tracked-0", size: 1}},
	); err != nil {
		t.Fatalf("initial AddTrackedTransport: %v", err)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := detached.UpsertTrackedPeer(detachedTestPeer(byte(61 + i)))
			if err != nil && !errors.Is(err, ErrDeviceClosed) {
				t.Errorf("UpsertTrackedPeer(%d): %v", i, err)
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			id := TransportID("tracked-" + string(rune('a'+i)))
			err := detached.AddTrackedTransport(
				id,
				TransportConfig{Bind: &fakeTransitionBind{id: string(id), size: 1}},
			)
			if err != nil && !errors.Is(err, ErrDeviceClosed) {
				t.Errorf("AddTrackedTransport(%q): %v", id, err)
			}
		}()
	}
	close(start)
	detached.Close()
	wg.Wait()

	if peers := dev.Config().Peers; len(peers) != 0 {
		t.Fatalf("tracked peers after concurrent Close = %d, want 0", len(peers))
	}
	for i := range 16 {
		id := TransportID("tracked-" + string(rune('a'+i)))
		if _, ok := dev.TransportInfo(id); ok {
			t.Errorf("tracked transport %q remains after concurrent Close", id)
		}
	}
	if _, ok := dev.TransportInfo("tracked-0"); ok {
		t.Error("initial tracked transport remains after concurrent Close")
	}
}

func TestDetachedDeviceCloseIsConcurrentAndIdempotent(t *testing.T) {
	dev := newDeviceAPIForTest(t)
	detached := DetachDevice(dev)

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			detached.Close()
		}()
	}
	wg.Wait()

	select {
	case <-detached.Wait():
	default:
		t.Fatal("Wait channel is open after Close")
	}
	select {
	case <-dev.Wait():
		t.Fatal("concurrent wrapper Close calls closed the wrapped device")
	default:
	}
}

func TestDetachedDeviceClosedBehaviorMatchesDevice(t *testing.T) {
	wrapped := newDeviceAPIForTest(t)
	closed := newDeviceAPIForTest(t)

	var privateKey NoisePrivateKey
	privateKey[0] = 7
	for _, dev := range []DeviceAPI{wrapped, closed} {
		if err := dev.SetPrivateKey(privateKey); err != nil {
			t.Fatalf("SetPrivateKey: %v", err)
		}
		if err := dev.SetListenPort(1234); err != nil {
			t.Fatalf("SetListenPort: %v", err)
		}
		if err := dev.SetFwmark(42); err != nil {
			t.Fatalf("SetFwmark: %v", err)
		}
		if err := dev.UpsertPeer(detachedTestPeer(3)); err != nil {
			t.Fatalf("UpsertPeer: %v", err)
		}
	}

	detached := DetachDevice(wrapped)
	detached.Close()
	closed.Close()

	detachedUpErr := detached.Up()
	closedUpErr := closed.Up()
	if detachedUpErr != closedUpErr {
		t.Fatalf("Up error = %v, closed Device returned %v", detachedUpErr, closedUpErr)
	}
	detachedDownErr := detached.Down()
	closedDownErr := closed.Down()
	if detachedDownErr != closedDownErr {
		t.Fatalf("Down error = %v, closed Device returned %v", detachedDownErr, closedDownErr)
	}
	if detached.PrivateKey() != closed.PrivateKey() {
		t.Fatal("PrivateKey differs from a closed Device")
	}
	if detached.ListenPort() != closed.ListenPort() {
		t.Fatal("ListenPort differs from a closed Device")
	}
	if detached.Fwmark() != closed.Fwmark() {
		t.Fatal("Fwmark differs from a closed Device")
	}
	if got, want := detached.Config(), closed.Config(); got.PrivateKey != want.PrivateKey || got.ListenPort != want.ListenPort ||
		got.Fwmark != want.Fwmark || len(got.Peers) != len(want.Peers) {
		t.Fatalf("Config = %+v, closed Device returned %+v", got, want)
	}
	if _, ok := detached.PeerSpec(detachedTestPeer(3).PublicKey); ok {
		t.Fatal("PeerSpec found a peer after wrapper Close")
	}
	if !detached.RuntimeStats().Equal(closed.RuntimeStats()) {
		t.Fatalf(
			"RuntimeStats = %+v, closed Device returned %+v",
			detached.RuntimeStats(),
			closed.RuntimeStats(),
		)
	}

	assertClosed := func(name string, detachedCall, deviceCall func() error) {
		t.Helper()
		detachedErr := detachedCall()
		deviceErr := deviceCall()
		if !errors.Is(detachedErr, ErrDeviceClosed) {
			t.Errorf("detached %s error = %v, want %v", name, detachedErr, ErrDeviceClosed)
		}
		if !errors.Is(deviceErr, ErrDeviceClosed) {
			t.Errorf("closed Device %s error = %v, want %v", name, deviceErr, ErrDeviceClosed)
		}
	}

	assertClosed("SetPrivateKey",
		func() error { return detached.SetPrivateKey(NoisePrivateKey{}) },
		func() error { return closed.SetPrivateKey(NoisePrivateKey{}) },
	)
	assertClosed("SetListenPort",
		func() error { return detached.SetListenPort(4321) },
		func() error { return closed.SetListenPort(4321) },
	)
	assertClosed("SetFwmark",
		func() error { return detached.SetFwmark(24) },
		func() error { return closed.SetFwmark(24) },
	)
	assertClosed("SetAmneziaWGConfig",
		func() error { return detached.SetAmneziaWGConfig(DefaultAmneziaWGConfig()) },
		func() error { return closed.SetAmneziaWGConfig(DefaultAmneziaWGConfig()) },
	)
	assertClosed("SetAmneziaWGConfigPatch",
		func() error { return detached.SetAmneziaWGConfigPatch(AmneziaWGConfigPatch{}) },
		func() error { return closed.SetAmneziaWGConfigPatch(AmneziaWGConfigPatch{}) },
	)
	assertClosed("ApplyConfig",
		func() error {
			return detached.ApplyConfig(
				DeviceConfig{AmneziaWG: DefaultAmneziaWGConfig()},
				ApplyConfigOptions{},
			)
		},
		func() error {
			return closed.ApplyConfig(
				DeviceConfig{AmneziaWG: DefaultAmneziaWGConfig()},
				ApplyConfigOptions{},
			)
		},
	)
	peerKey := detachedTestPeer(3).PublicKey
	assertClosed("SetPeerPresharedKey",
		func() error { return detached.SetPeerPresharedKey(peerKey, NoisePresharedKey{}) },
		func() error { return closed.SetPeerPresharedKey(peerKey, NoisePresharedKey{}) },
	)
	assertClosed("SetPeerEndpoint",
		func() error { return detached.SetPeerEndpoint(peerKey, "127.0.0.1:1") },
		func() error { return closed.SetPeerEndpoint(peerKey, "127.0.0.1:1") },
	)
	assertClosed("SetPeerPersistentKeepaliveInterval",
		func() error { return detached.SetPeerPersistentKeepaliveInterval(peerKey, 1) },
		func() error { return closed.SetPeerPersistentKeepaliveInterval(peerKey, 1) },
	)
	assertClosed("SetPeerPersistentKeepaliveRange",
		func() error { return detached.SetPeerPersistentKeepaliveRange(peerKey, AmneziaWGRange{}) },
		func() error { return closed.SetPeerPersistentKeepaliveRange(peerKey, AmneziaWGRange{}) },
	)
	assertClosed("SetAmneziaWGVersion",
		func() error { return detached.SetAmneziaWGVersion(AmneziaWGVersionAuto) },
		func() error { return closed.SetAmneziaWGVersion(AmneziaWGVersionAuto) },
	)
	assertClosed("SetPeerAmneziaWGVersion",
		func() error { return detached.SetPeerAmneziaWGVersion(peerKey, AmneziaWGVersionAuto) },
		func() error { return closed.SetPeerAmneziaWGVersion(peerKey, AmneziaWGVersionAuto) },
	)
	assertClosed("SetPeerProtocolVersion",
		func() error { return detached.SetPeerProtocolVersion(peerKey, 1) },
		func() error { return closed.SetPeerProtocolVersion(peerKey, 1) },
	)
	assertClosed("SetPeerAmneziaWGConfig",
		func() error { return detached.SetPeerAmneziaWGConfig(peerKey, DefaultAmneziaWGConfig()) },
		func() error { return closed.SetPeerAmneziaWGConfig(peerKey, DefaultAmneziaWGConfig()) },
	)
	assertClosed("SetPeerAmneziaWGConfigPatch",
		func() error { return detached.SetPeerAmneziaWGConfigPatch(peerKey, AmneziaWGConfigPatch{}) },
		func() error { return closed.SetPeerAmneziaWGConfigPatch(peerKey, AmneziaWGConfigPatch{}) },
	)
	assertClosed("ClearPeerAmneziaWGConfig",
		func() error { return detached.ClearPeerAmneziaWGConfig(peerKey) },
		func() error { return closed.ClearPeerAmneziaWGConfig(peerKey) },
	)
	assertClosed("ReplacePeerAllowedIPs",
		func() error { return detached.ReplacePeerAllowedIPs(peerKey, nil) },
		func() error { return closed.ReplacePeerAllowedIPs(peerKey, nil) },
	)
	assertClosed("AddPeerAllowedIP",
		func() error { return detached.AddPeerAllowedIP(peerKey, netip.Prefix{}) },
		func() error { return closed.AddPeerAllowedIP(peerKey, netip.Prefix{}) },
	)
	assertClosed("RemovePeerAllowedIP",
		func() error { return detached.RemovePeerAllowedIP(peerKey, netip.Prefix{}) },
		func() error { return closed.RemovePeerAllowedIP(peerKey, netip.Prefix{}) },
	)
	assertClosed("ActivatePeer",
		func() error { return detached.ActivatePeer(peerKey) },
		func() error { return closed.ActivatePeer(peerKey) },
	)
	assertClosed("UpsertPeer",
		func() error { return detached.UpsertPeer(detachedTestPeer(4)) },
		func() error { return closed.UpsertPeer(detachedTestPeer(4)) },
	)
	assertClosed("UpsertTrackedPeer",
		func() error { return detached.UpsertTrackedPeer(detachedTestPeer(4)) },
		func() error { return closed.UpsertTrackedPeer(detachedTestPeer(4)) },
	)
	assertClosed("AddTransport",
		func() error { return detached.AddTransport("closed", TransportConfig{}) },
		func() error { return closed.AddTransport("closed", TransportConfig{}) },
	)
	assertClosed("ReplaceTransport",
		func() error { return detached.ReplaceTransport("closed", TransportConfig{}) },
		func() error { return closed.ReplaceTransport("closed", TransportConfig{}) },
	)
	assertClosed("RemoveTransport",
		func() error { return detached.RemoveTransport("closed") },
		func() error { return closed.RemoveTransport("closed") },
	)
	assertClosed("AddTrackedTransport",
		func() error { return detached.AddTrackedTransport("closed", TransportConfig{}) },
		func() error { return closed.AddTrackedTransport("closed", TransportConfig{}) },
	)
	assertClosed("ReplaceTrackedTransport",
		func() error { return detached.ReplaceTrackedTransport("closed", TransportConfig{}) },
		func() error { return closed.ReplaceTrackedTransport("closed", TransportConfig{}) },
	)
	assertClosed("RemoveTrackedTransport",
		func() error { return detached.RemoveTrackedTransport("closed") },
		func() error { return closed.RemoveTrackedTransport("closed") },
	)
	assertClosed("ReplaceTUN",
		func() error { return detached.ReplaceTUN(nil) },
		func() error { return closed.ReplaceTUN(nil) },
	)
	assertClosed("AttachTUN",
		func() error { return detached.AttachTUN(nil) },
		func() error { return closed.AttachTUN(nil) },
	)
	assertClosed("DetachTUN", detached.DetachTUN, closed.DetachTUN)
	assertClosed("ReplaceTrackedTUN",
		func() error { return detached.ReplaceTrackedTUN(nil) },
		func() error { return closed.ReplaceTrackedTUN(nil) },
	)
	assertClosed("AttachTrackedTUN",
		func() error { return detached.AttachTrackedTUN(nil) },
		func() error { return closed.AttachTrackedTUN(nil) },
	)
	assertClosed("DetachTrackedTUN", detached.DetachTrackedTUN, closed.DetachTrackedTUN)
	assertClosed("ReplaceBind",
		func() error { return detached.ReplaceBind(nil) },
		func() error { return closed.ReplaceBind(nil) },
	)
	assertClosed("AttachBind",
		func() error { return detached.AttachBind(nil) },
		func() error { return closed.AttachBind(nil) },
	)
	assertClosed("DetachBind", detached.DetachBind, closed.DetachBind)
	assertClosed("ReplaceTrackedBind",
		func() error { return detached.ReplaceTrackedBind(nil) },
		func() error { return closed.ReplaceTrackedBind(nil) },
	)
	assertClosed("AttachTrackedBind",
		func() error { return detached.AttachTrackedBind(nil) },
		func() error { return closed.AttachTrackedBind(nil) },
	)
	assertClosed("DetachTrackedBind", detached.DetachTrackedBind, closed.DetachTrackedBind)

	if deleted, err := detached.DeletePeer(detachedTestPeer(3).PublicKey); deleted || !errors.Is(err, ErrDeviceClosed) {
		t.Fatalf("DeletePeer = (%v, %v), want (false, %v)", deleted, err, ErrDeviceClosed)
	}
	if deleted, err := detached.DeleteTrackedPeer(detachedTestPeer(3).PublicKey); deleted || !errors.Is(err, ErrDeviceClosed) {
		t.Fatalf("DeleteTrackedPeer = (%v, %v), want (false, %v)", deleted, err, ErrDeviceClosed)
	}
}

func TestDetachedDeviceStopsSubscriptionsOnClose(t *testing.T) {
	dev := newDeviceAPIForTest(t)
	detached := DetachDevice(dev)

	var calls atomic.Int32
	initial := make(chan struct{})
	var initialOnce sync.Once
	unsubscribe := detached.SubscribeRuntimeStats(func(RuntimeStats) {
		calls.Add(1)
		initialOnce.Do(func() { close(initial) })
	})
	defer unsubscribe()

	select {
	case <-initial:
	case <-time.After(time.Second):
		t.Fatal("initial runtime stats callback did not run")
	}

	detached.Close()
	wantCalls := calls.Load()
	if err := dev.UpsertPeer(detachedTestPeer(5)); err != nil {
		t.Fatalf("UpsertPeer on wrapped device: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if got := calls.Load(); got != wantCalls {
		t.Fatalf("runtime stats callbacks after Close = %d, want %d", got, wantCalls)
	}
}

func TestDetachedDeviceClosesWhenWrappedDeviceCloses(t *testing.T) {
	dev := newDeviceAPIForTest(t)
	detached := DetachDevice(dev)

	dev.Close()

	select {
	case <-detached.Wait():
	case <-time.After(time.Second):
		t.Fatal("wrapper stayed open after wrapped Device.Close")
	}
	if err := detached.UpsertPeer(detachedTestPeer(6)); !errors.Is(err, ErrDeviceClosed) {
		t.Fatalf("UpsertPeer error = %v, want %v", err, ErrDeviceClosed)
	}
}

func TestDetachedDeviceConcurrentCallsAndClose(t *testing.T) {
	dev := newDeviceAPIForTest(t)
	detached := DetachDevice(dev)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				_ = detached.Config()
				_ = detached.RuntimeStats()
				_ = detached.AmneziaWGReceiveCounters()
			}
		}()
	}
	detached.Close()
	wg.Wait()
}
