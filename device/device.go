/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Modifications Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	conn "github.com/asciimoth/batchudp"
	"github.com/asciimoth/gonnect"
	gtun "github.com/asciimoth/gonnect/tun"
	"github.com/asciimoth/wgo/ratelimiter"
	"github.com/asciimoth/wgo/rwcancel"
)

type Device struct {
	state struct {
		// state holds the device's state. It is accessed atomically.
		// Use the device.deviceState method to read it.
		// device.deviceState does not acquire the mutex, so it captures only a snapshot.
		// During state transitions, the state variable is updated before the device itself.
		// The state is thus either the current state of the device or
		// the intended future state of the device.
		// For example, while executing a call to Up, state will be deviceStateUp.
		// There is no guarantee that that intended future state of the device
		// will become the actual state; Up can fail.
		// The device can also change state multiple times between time of check and time of use.
		// Unsynchronized uses of state must therefore be advisory/best-effort only.
		state atomic.Uint32 // actually a deviceState, but typed uint32 for convenience
		// stopping blocks until all inputs to Device have been closed.
		stopping sync.WaitGroup
		// mu protects state changes.
		sync.Mutex
	}

	net struct {
		stopping sync.WaitGroup
		sync.RWMutex
		bind          conn.Bind // bind interface
		netlinkCancel *rwcancel.RWCancel
		port          uint16 // listening port
		fwmark        uint32 // mark value (0 = disabled)
		brokenRoaming bool
		transports    map[TransportID]*transportState
	}

	staticIdentity struct {
		sync.RWMutex
		privateKey NoisePrivateKey
		publicKey  NoisePublicKey
	}

	peers struct {
		sync.RWMutex // protects keyMap
		keyMap       map[NoisePublicKey]*Peer
	}

	stats struct {
		sync.RWMutex
		subscribers map[uint64]RuntimeStatsCallback
		nextSubID   uint64
		notify      chan struct{}

		rxBytes   atomic.Uint64
		txBytes   atomic.Uint64
		rxPackets atomic.Uint64
		txPackets atomic.Uint64

		byteDelta   atomic.Uint64
		packetDelta atomic.Uint64

		lastNotifyRxBytes   atomic.Uint64
		lastNotifyTxBytes   atomic.Uint64
		lastNotifyRxPackets atomic.Uint64
		lastNotifyTxPackets atomic.Uint64
	}

	receiveErrors struct {
		sync.RWMutex
		subscribers map[uint64]func(ReceiveError)
		nextSubID   uint64
	}

	rate struct {
		underLoadUntil atomic.Int64
		limiter        ratelimiter.Ratelimiter
	}

	allowedips     AllowedIPs
	indexTable     IndexTable
	cookieChecker  CookieChecker
	batchSize      int
	maxActivePeers int

	pool struct {
		inboundElementsContainer  *WaitPool
		outboundElementsContainer *WaitPool
		messageBuffers            *WaitPool
		inboundElements           *WaitPool
		outboundElements          *WaitPool
	}

	queue struct {
		encryption *outboundQueue
		decryption *inboundQueue
		handshake  *handshakeQueue
	}

	tun struct {
		device atomic.Pointer[tunState]
		mtu    atomic.Int32
	}

	ipcMutex sync.RWMutex
	closed   chan struct{}
	log      Logger
	spawner  gonnect.Spawner

	junk struct {
		min   int
		max   int
		count int
	}

	headers struct {
		init      *magicHeader
		response  *magicHeader
		cookie    *magicHeader
		transport *magicHeader
	}

	paddings struct {
		init      int
		response  int
		cookie    int
		transport int
	}

	ipackets [amneziaPacketCount]*obfChain

	amneziaVersion AmneziaWGVersion
	amneziaV3      struct {
		headerProtectionKey  AmneziaWGHeaderProtectionKey
		contentPadding       AmneziaWGRange
		rekeyAfterTime       AmneziaWGRange
		rekeyTimeout         AmneziaWGRange
		rejectAfterTime      AmneziaWGRange
		keepaliveTimeout     AmneziaWGRange
		maxHandshakeAttempts AmneziaWGRange
		randomTrailers       bool
		disableCookies       bool
	}

	amneziaSnapshot          atomic.Pointer[amneziaWGSnapshot]
	amneziaReceiveClassifier atomic.Pointer[amneziaWGReceiveClassifier]
	amneziaReceiveProfileMax int
	forceHandshakeCookies    bool
	amneziaReceiveCounters   struct {
		candidatesTried        atomic.Uint64
		headerDecryptFailures  atomic.Uint64
		profileMismatches      atomic.Uint64
		unknownPackets         atomic.Uint64
		profileLimitRejections atomic.Uint64
	}
}

type AmneziaWGReceiveCounters struct {
	// CandidatesTried counts receive classifier candidates examined before
	// Noise or keypair authentication. It does not include key bytes.
	CandidatesTried uint64

	// HeaderDecryptFailures counts protected-header candidates that could not
	// be decoded, usually because the packet did not contain the 12-byte nonce
	// prefix required by AWG 3.1 header protection.
	HeaderDecryptFailures uint64

	// ProfileMismatches counts decoded packets that authenticated or indexed to
	// a peer with a different effective receive profile.
	ProfileMismatches uint64

	// UnknownPackets counts datagrams that did not match any receive profile.
	UnknownPackets uint64

	// ProfileLimitRejections counts peer receive profiles that were not added
	// to the classifier because DeviceOptions.MaxAmneziaWGReceiveProfiles was
	// reached. Normal configuration paths reject this before publishing state;
	// this counter is for defensive classifier skips in inconsistent state.
	ProfileLimitRejections uint64
}

func (device *Device) AmneziaWGReceiveCounters() AmneziaWGReceiveCounters {
	return AmneziaWGReceiveCounters{
		CandidatesTried:        device.amneziaReceiveCounters.candidatesTried.Load(),
		HeaderDecryptFailures:  device.amneziaReceiveCounters.headerDecryptFailures.Load(),
		ProfileMismatches:      device.amneziaReceiveCounters.profileMismatches.Load(),
		UnknownPackets:         device.amneziaReceiveCounters.unknownPackets.Load(),
		ProfileLimitRejections: device.amneziaReceiveCounters.profileLimitRejections.Load(),
	}
}

const defaultDeviceBatchSize = 256

// DeviceOptions controls construction-time sizing for a Device.
//
// The zero value preserves the high-throughput batch sizing used by previous
// releases while deriving the default worker count from runtime.GOMAXPROCS(0),
// which reflects the scheduler parallelism available to this process.
type DeviceOptions struct {
	// BatchSize controls the number of packet slots allocated for TUN and bind
	// processing batches. Values less than 1 use the historical default. Smaller
	// positive values can reduce retained memory in idle or low-throughput
	// devices, but may reduce peak packet throughput.
	//
	// The effective batch size is always raised to at least the batch size
	// required by the initially attached TUN and bind.
	BatchSize int

	// WorkerCount controls how many encryption, decryption, and handshake
	// workers are started. Values less than 1 use runtime.GOMAXPROCS(0).
	WorkerCount int

	// MaxActivePeers bounds materialized peer sessions. Values less than 1 use
	// MaxPeers. This implementation still stores configured peers as Peer
	// objects, so the limit applies when on-demand peers are activated.
	MaxActivePeers int

	// MaxAmneziaWGReceiveProfiles bounds distinct receive profiles that can be
	// tried before a peer is authenticated. Configuration that exceeds this
	// bound is rejected. Values less than 1 use MaxPeers+1.
	MaxAmneziaWGReceiveProfiles int

	// ForceHandshakeCookies makes the device behave as if it is under handshake
	// load. This is mainly useful for deterministic compatibility tests that
	// must exercise cookie replies without packet-flood timing.
	ForceHandshakeCookies bool
}

type tunState struct {
	device gtun.Tun

	// Transport layout inside device buffers stays fixed at offset 16.
	// These fields describe only the TUN adapter offsets at the boundary.
	readOffset         int
	writeOffset        int
	readNeedsCopy      bool
	writeNeedsCopy     bool
	readUsesLargeBufs  bool
	writeUsesLargeBufs bool
	stop               chan struct{}
	wg                 sync.WaitGroup
}

// deviceState represents the state of a Device.
// There are three states: down, up, closed.
// Transitions:
//
//	down -----+
//	  ↑↓      ↓
//	  up -> closed
type deviceState uint32

//go:generate go run golang.org/x/tools/cmd/stringer -type deviceState -trimprefix=deviceState
const (
	deviceStateDown deviceState = iota
	deviceStateUp
	deviceStateClosed
)

// deviceState returns device.state.state as a deviceState
// See those docs for how to interpret this value.
func (device *Device) deviceState() deviceState {
	return deviceState(device.state.state.Load())
}

// isClosed reports whether the device is closed (or is closing).
// See device.state.state comments for how to interpret this value.
func (device *Device) isClosed() bool {
	return device.deviceState() == deviceStateClosed
}

// isUp reports whether the device is up (or is attempting to come up).
// See device.state.state comments for how to interpret this value.
func (device *Device) isUp() bool {
	return device.deviceState() == deviceStateUp
}

// Must hold device.peers.Lock()
func removePeerLocked(device *Device, peer *Peer, key NoisePublicKey) {
	// stop routing and processing of packets
	device.allowedips.RemoveByPeer(peer)
	peer.Stop()

	// remove from peer map
	delete(device.peers.keyMap, key)
	device.signalRuntimeStats()
}

// changeState attempts to change the device state to match want.
func (device *Device) changeState(want deviceState) (err error) {
	device.state.Lock()
	defer device.state.Unlock()
	old := device.deviceState()
	if old == deviceStateClosed {
		// once closed, always closed
		device.log.Debugf("Interface closed, ignored requested state %s", want)
		return nil
	}
	switch want {
	case old:
		return nil
	case deviceStateUp:
		device.state.state.Store(uint32(deviceStateUp))
		err = device.upLocked()
		if err == nil {
			break
		}
		fallthrough // up failed; bring the device all the way back down
	case deviceStateDown:
		device.state.state.Store(uint32(deviceStateDown))
		errDown := device.downLocked()
		if err == nil {
			err = errDown
		}
	}
	device.log.Debugf("Interface state was %s, requested %s, now %s", old, want, device.deviceState())
	return
}

// upLocked attempts to bring the device up and reports whether it succeeded.
// The caller must hold device.state.mu and is responsible for updating device.state.state.
func (device *Device) upLocked() error {
	if err := device.BindUpdate(); err != nil {
		device.log.Errf("Unable to update bind: %v", err)
		return err
	}
	if err := device.openNonDefaultTransports(); err != nil {
		device.log.Errf("Unable to update transports: %v", err)
		return err
	}
	device.net.RLock()
	hasTransport := device.net.bind != nil || len(device.net.transports) != 0
	device.net.RUnlock()
	if !hasTransport {
		device.log.Debugf("Interface is up without an attached bind")
		return nil
	}

	// The IPC set operation waits for peers to be created before calling Start() on them,
	// so if there's a concurrent IPC set request happening, we should wait for it to complete.
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	device.peers.RLock()
	peers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		peers = append(peers, peer)
	}
	device.peers.RUnlock()

	for _, peer := range peers {
		keepalive := peer.persistentKeepaliveRange.Load() != 0
		if peer.activation != PeerActivationEager && !keepalive {
			continue
		}
		if err := device.checkActivePeerLimitLocked(peer); err != nil {
			return err
		}
		device.activatePeerLocked(peer)
		if keepalive {
			peer.SendKeepalive()
		}
	}
	return nil
}

// downLocked attempts to bring the device down.
// The caller must hold device.state.mu and is responsible for updating device.state.state.
func (device *Device) downLocked() error {
	err := device.BindClose()
	if err != nil {
		device.log.Errf("Bind close failed: %v", err)
	}
	if transportErr := device.closeNonDefaultTransports(); err == nil {
		err = transportErr
	}

	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.Stop()
	}
	device.peers.RUnlock()
	return err
}

func (device *Device) openNonDefaultTransports() error {
	device.net.Lock()
	defer device.net.Unlock()
	for id, st := range device.net.transports {
		if id == DefaultTransportID {
			continue
		}
		recvFns, err := device.openTransportLocked(st)
		if err != nil {
			return fmt.Errorf("transport %q: %w", id, err)
		}
		device.startTransportReceiveRoutinesLocked(st, recvFns)
	}
	return nil
}

func (device *Device) closeNonDefaultTransports() error {
	device.net.Lock()
	var err error
	closed := make([]*transportState, 0, len(device.net.transports))
	for id, st := range device.net.transports {
		if id == DefaultTransportID {
			continue
		}
		if closeErr := device.closeTransportLocked(st); err == nil && closeErr != nil {
			err = fmt.Errorf("transport %q: %w", id, closeErr)
		}
		closed = append(closed, st)
	}
	device.net.Unlock()
	for _, st := range closed {
		st.stopping.Wait()
	}
	return err
}

func (device *Device) Up() error {
	return device.changeState(deviceStateUp)
}

func (device *Device) Down() error {
	return device.changeState(deviceStateDown)
}

func (device *Device) IsUnderLoad() bool {
	if device.isClosed() {
		return false
	}
	if device.forceHandshakeCookies {
		return true
	}

	// check if currently under load
	now := time.Now()
	underLoad := len(device.queue.handshake.c) >= QueueHandshakeSize/8
	if underLoad {
		device.rate.underLoadUntil.Store(now.Add(UnderLoadAfterTime).UnixNano())
		return true
	}
	// check if recently under load
	return device.rate.underLoadUntil.Load() > now.UnixNano()
}

func (device *Device) SetPrivateKey(sk NoisePrivateKey) error {
	if device.isClosed() {
		return ErrDeviceClosed
	}

	// lock required resources

	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()

	if sk.Equals(device.staticIdentity.privateKey) {
		return nil
	}

	device.peers.Lock()
	defer device.peers.Unlock()

	lockedPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		peer.handshake.mutex.RLock()
		lockedPeers = append(lockedPeers, peer)
	}

	// remove peers with matching public keys

	publicKey := sk.publicKey()
	removedPeer := false
	for key, peer := range device.peers.keyMap {
		if peer.handshake.remoteStatic.Equals(publicKey) {
			peer.handshake.mutex.RUnlock()
			removePeerLocked(device, peer, key)
			removedPeer = true
			peer.handshake.mutex.RLock()
		}
	}
	if removedPeer {
		device.storeAmneziaWGReceiveClassifierLocked()
	}

	// update key material

	device.staticIdentity.privateKey = sk
	device.staticIdentity.publicKey = publicKey
	device.cookieChecker.Init(publicKey)

	// do static-static DH pre-computations

	expiredPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		handshake := &peer.handshake
		handshake.precomputedStaticStatic, _ = device.staticIdentity.privateKey.sharedSecret(handshake.remoteStatic)
		expiredPeers = append(expiredPeers, peer)
	}

	for _, peer := range lockedPeers {
		peer.handshake.mutex.RUnlock()
	}
	for _, peer := range expiredPeers {
		peer.ExpireCurrentKeypairs()
	}

	return nil
}

func validateTunOffsets(tunDevice gtun.Tun) error {
	if mwo := tunDevice.MWO(); mwo < 0 {
		return fmt.Errorf("invalid tun minimal write offset %d: must be >= 0", mwo)
	}
	if mro := tunDevice.MRO(); mro < 0 {
		return fmt.Errorf("invalid tun minimal read offset %d: must be >= 0", mro)
	}
	return nil
}

func newTunState(tunDevice gtun.Tun) (*tunState, error) {
	if err := validateTunOffsets(tunDevice); err != nil {
		return nil, err
	}

	state := &tunState{
		device:      tunDevice,
		readOffset:  MessageTransportHeaderSize,
		writeOffset: MessageTransportOffsetContent,
		stop:        make(chan struct{}),
	}
	if mro := tunDevice.MRO(); mro > state.readOffset {
		state.readOffset = mro
		state.readNeedsCopy = true
		if mro > maxTunHeadroom() {
			state.readUsesLargeBufs = true
		}
	}
	if mwo := tunDevice.MWO(); mwo > state.writeOffset {
		state.writeOffset = mwo
		state.writeNeedsCopy = true
		if mwo > maxTunHeadroom() {
			state.writeUsesLargeBufs = true
		}
	}
	return state, nil
}

func effectiveDeviceBatchSize(tunDevice gtun.Tun, bind conn.Bind, options DeviceOptions) int {
	batchSize := options.BatchSize
	if batchSize <= 0 {
		batchSize = defaultDeviceBatchSize
		if batchSize < conn.IdealBatchSize {
			batchSize = conn.IdealBatchSize
		}
	}
	if bind != nil && batchSize < bind.BatchSize() {
		batchSize = bind.BatchSize()
	}
	if tunDevice != nil {
		if tunBatchSize := tunDevice.BatchSize(); batchSize < tunBatchSize {
			batchSize = tunBatchSize
		}
	}
	return batchSize
}

func effectiveDeviceWorkerCount(options DeviceOptions) int {
	workerCount := options.WorkerCount
	if workerCount < 1 {
		workerCount = runtime.GOMAXPROCS(0)
	}
	if workerCount < 1 {
		return 1
	}
	return workerCount
}

// NewDevice creates a WireGuard device and starts its background workers.
//
// Long-lived workers are started with spawner when it is non-nil, allowing the
// caller to observe and manage worker lifecycle through gonnect. Passing nil
// preserves direct goroutine spawning.
func NewDevice(tunDevice gtun.Tun, bind conn.Bind, logger Logger, spawner gonnect.Spawner, options DeviceOptions) *Device {
	var (
		tunState *tunState
		err      error
	)
	if tunDevice != nil {
		tunState, err = newTunState(tunDevice)
		if err != nil {
			panic(fmt.Sprintf("device.NewDevice: %v", err))
		}
	}

	device := new(Device)
	device.state.state.Store(uint32(deviceStateDown))
	device.closed = make(chan struct{})
	device.log = loggerOrNop(logger)
	device.spawner = spawner
	device.net.bind = bind
	device.initTransports(bind)
	device.batchSize = effectiveDeviceBatchSize(tunDevice, bind, options)
	device.maxActivePeers = options.MaxActivePeers
	device.amneziaReceiveProfileMax = options.MaxAmneziaWGReceiveProfiles
	device.forceHandshakeCookies = options.ForceHandshakeCookies
	if device.amneziaReceiveProfileMax < 1 {
		device.amneziaReceiveProfileMax = MaxPeers + 1
	}
	if tunDevice != nil {
		device.tun.device.Store(tunState)
		mtu, err := tunDevice.MTU()
		if err != nil {
			device.log.Errf("Trouble determining MTU, assuming default: %v", err)
			mtu = DefaultMTU
		}
		device.tun.mtu.Store(int32(mtu))
	} else {
		device.tun.mtu.Store(int32(DefaultMTU))
	}
	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
	device.stats.subscribers = make(map[uint64]RuntimeStatsCallback)
	device.stats.notify = make(chan struct{}, 1)
	device.receiveErrors.subscribers = make(map[uint64]func(ReceiveError))
	device.stats.byteDelta.Store(DefaultRuntimeStatsByteDelta)
	device.stats.packetDelta.Store(DefaultRuntimeStatsPacketDelta)
	device.rate.limiter.Init(spawner)
	device.indexTable.Init()
	device.headers.init = &magicHeader{start: MessageInitiationType, end: MessageInitiationType}
	device.headers.response = &magicHeader{start: MessageResponseType, end: MessageResponseType}
	device.headers.cookie = &magicHeader{start: MessageCookieReplyType, end: MessageCookieReplyType}
	device.headers.transport = &magicHeader{start: MessageTransportType, end: MessageTransportType}
	device.storeAmneziaWGSnapshot()
	device.storeAmneziaWGReceiveClassifierLocked()

	device.PopulatePools()

	// create queues

	device.queue.handshake = newHandshakeQueue()
	device.queue.encryption = newOutboundQueue()
	device.queue.decryption = newInboundQueue()

	// start workers

	device.spawnWorker(device.routineRuntimeStatsNotifier, "wgo: runtime stats notifier")

	workers := effectiveDeviceWorkerCount(options)
	device.state.stopping.Wait()
	device.queue.encryption.wg.Add(workers) // One for each RoutineHandshake
	for i := 0; i < workers; i++ {
		id := i + 1
		device.spawnWorker(func() { device.RoutineEncryption(id) }, fmt.Sprintf("wgo: encryption worker %d", id))
		device.spawnWorker(func() { device.RoutineDecryption(id) }, fmt.Sprintf("wgo: decryption worker %d", id))
		device.spawnWorker(func() { device.RoutineHandshake(id) }, fmt.Sprintf("wgo: handshake worker %d", id))
	}

	if tunState != nil {
		device.startTUN(tunState)
	}

	return device
}

// BatchSize returns the BatchSize for the device as a whole which is the max of
// the bind batch size and the tun batch size. The batch size reported by device
// is the size used to construct memory pools, and is the allowed batch size for
// the lifetime of the device.
func (device *Device) BatchSize() int {
	return device.batchSize
}

func (device *Device) LookupPeer(pk NoisePublicKey) *Peer {
	device.peers.RLock()
	defer device.peers.RUnlock()

	return device.peers.keyMap[pk]
}

func (device *Device) LookupActivePeer(pk NoisePublicKey) *Peer {
	peer := device.LookupPeer(pk)
	if peer == nil || !peer.isRunning.Load() {
		return nil
	}
	return peer
}

func (device *Device) RemovePeer(key NoisePublicKey) {
	device.peers.Lock()
	defer device.peers.Unlock()
	// stop peer and remove from routing

	peer, ok := device.peers.keyMap[key]
	if ok {
		removePeerLocked(device, peer, key)
		device.storeAmneziaWGReceiveClassifierLocked()
	}
}

func (device *Device) RemoveAllPeers() {
	device.peers.Lock()
	defer device.peers.Unlock()

	for key, peer := range device.peers.keyMap {
		removePeerLocked(device, peer, key)
	}

	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
	device.storeAmneziaWGReceiveClassifierLocked()
}

func (device *Device) Close() {
	device.state.Lock()
	if device.isClosed() {
		device.state.Unlock()
		return
	}
	device.state.state.Store(uint32(deviceStateClosed))
	device.state.Unlock()

	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	device.log.Debugf("Device closing")

	// Stop TUN workers without holding state.mu. The event reader may already be
	// processing an event and attempt Up/Down, which also takes state.mu.
	device.stopTUN(device.tun.device.Swap(nil))

	device.state.Lock()
	if err := device.downLocked(); err != nil {
		device.log.Errf("Failed to bring device down while closing: %v", err)
	}
	device.state.Unlock()

	// Remove peers before closing queues,
	// because peers assume that queues are active.
	device.RemoveAllPeers()

	// We kept a reference to the encryption and decryption queues,
	// in case we started any new peers that might write to them.
	// No new peers are coming; we are done with these queues.
	device.queue.encryption.wg.Done()
	device.queue.decryption.wg.Done()
	device.queue.handshake.wg.Done()
	device.state.stopping.Wait()

	device.rate.limiter.Close()

	device.log.Debugf("Device closed")
	close(device.closed)
}

func (device *Device) Wait() chan struct{} {
	return device.closed
}

func (device *Device) SendKeepalivesToPeersWithCurrentKeypair() {
	if !device.isUp() {
		return
	}

	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.keypairs.RLock()
		sendKeepalive := peer.keypairs.current != nil && !peer.keypairs.current.created.Add(peer.rejectAfterTimeMax()).Before(time.Now())
		peer.keypairs.RUnlock()
		if sendKeepalive {
			peer.SendKeepalive()
		}
	}
	device.peers.RUnlock()
}

func (device *Device) activatePeerForTraffic(peer *Peer) error {
	if !device.isUp() {
		return nil
	}
	if peer.isRunning.Load() {
		return nil
	}
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	if peer.isRunning.Load() {
		return nil
	}
	if err := device.checkActivePeerLimitLocked(peer); err != nil {
		return err
	}
	device.activatePeerLocked(peer)
	return nil
}

func (device *Device) checkActivePeerLimitLocked(peer *Peer) error {
	limit := MaxPeers
	if device.maxActivePeers > 0 {
		limit = device.maxActivePeers
	}
	if limit <= 0 || peer.isRunning.Load() {
		return nil
	}
	active := 0
	device.peers.RLock()
	for _, existing := range device.peers.keyMap {
		if existing.isRunning.Load() {
			active++
		}
	}
	device.peers.RUnlock()
	if active >= limit {
		return ErrActivePeerLimit
	}
	return nil
}

// closeBindLocked closes the device's net.bind.
// The caller must hold the net mutex.
func closeBindLocked(device *Device) (*transportState, error) {
	st := device.defaultTransportLocked()
	err := device.closeTransportLocked(st)
	device.syncDefaultTransportAliasesLocked(st)
	return st, err
}

func (device *Device) Bind() conn.Bind {
	device.net.Lock()
	defer device.net.Unlock()
	return device.net.bind
}

func (device *Device) BindSetMark(mark uint32) error {
	device.net.Lock()
	defer device.net.Unlock()

	// check if modified
	if device.net.fwmark == mark {
		return nil
	}

	// update fwmark on existing bind
	device.net.fwmark = mark
	st := device.defaultTransportLocked()
	if st != nil {
		st.fwmark = mark
	}
	if device.isUp() && st != nil && st.bind != nil {
		if err := setBindMark(st.bind, mark); err != nil {
			return err
		}
	}

	// clear cached source addresses
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.markEndpointSrcForClearing()
	}
	device.peers.RUnlock()

	return nil
}

func (device *Device) BindUpdate() error {
	device.net.Lock()

	// close existing sockets
	st := device.defaultTransportLocked()
	if err := device.closeTransportLocked(st); err != nil {
		device.syncDefaultTransportAliasesLocked(st)
		device.net.Unlock()
		if st != nil {
			st.stopping.Wait()
		}
		return err
	}
	device.syncDefaultTransportAliasesLocked(st)
	device.net.Unlock()
	if st != nil {
		st.stopping.Wait()
	}

	device.net.Lock()
	defer device.net.Unlock()

	// open new sockets
	if !device.isUp() {
		device.syncDefaultTransportAliasesLocked(st)
		return nil
	}
	if st == nil || st.bind == nil {
		device.syncDefaultTransportAliasesLocked(st)
		device.log.Debugf("Bind update skipped: no bind attached")
		return nil
	}

	recvFns, err := device.openTransportLocked(st)
	if err != nil {
		device.syncDefaultTransportAliasesLocked(st)
		return err
	}
	device.syncDefaultTransportAliasesLocked(st)
	device.startTransportReceiveRoutinesLocked(st, recvFns)

	// clear cached source addresses
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.markEndpointSrcForClearing()
	}
	device.peers.RUnlock()

	device.log.Debugf("UDP bind has been updated")
	return nil
}

func setBindMark(bind conn.Bind, mark uint32) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("set bind mark panic: %v", recovered)
		}
	}()
	return bind.SetMark(mark)
}

func (device *Device) BindClose() error {
	device.net.Lock()
	st, err := closeBindLocked(device)
	device.net.Unlock()
	if st != nil {
		st.stopping.Wait()
	}
	return err
}

func (device *Device) rebindPeerEndpointsLocked(bind conn.Bind) error {
	device.peers.RLock()
	defer device.peers.RUnlock()

	for _, peer := range device.peers.keyMap {
		if err := peer.rebindEndpoint(bind); err != nil {
			return err
		}
	}
	return nil
}

func (device *Device) swapBindLocked(bind conn.Bind) {
	st := device.defaultTransportLocked()
	if bind == nil {
		delete(device.net.transports, DefaultTransportID)
		device.syncDefaultTransportAliasesLocked(nil)
		return
	}
	if st == nil {
		st = &transportState{
			id:         DefaultTransportID,
			port:       device.net.port,
			fwmark:     device.net.fwmark,
			generation: 1,
		}
		device.net.transports[DefaultTransportID] = st
	} else if st.generation == 0 {
		st.generation = 1
	}
	st.bind = bind
	st.fwmark = device.net.fwmark
	device.syncDefaultTransportAliasesLocked(st)
}

func (device *Device) startTUN(tun *tunState) {
	tun.wg.Add(2)
	device.state.stopping.Add(2)      // RoutineReadFromTUN + RoutineTUNEventReader
	device.queue.encryption.wg.Add(1) // RoutineReadFromTUN
	device.spawnWorker(func() { device.RoutineReadFromTUN(tun) }, "wgo: TUN reader")
	device.spawnWorker(func() { device.RoutineTUNEventReader(tun) }, "wgo: TUN event reader")
}

func (device *Device) stopTUN(tun *tunState) {
	if tun == nil {
		return
	}
	close(tun.stop)
	if err := tun.device.Close(); err != nil && !device.isClosed() {
		device.log.Debugf("Failed to close TUN device: %v", err)
	}
	tun.wg.Wait()
}

func (device *Device) currentTUN() *tunState {
	return device.tun.device.Load()
}

// ReplaceTUN atomically swaps the active TUN attachment.
// The new TUN becomes active before the old TUN is closed. This lets inbound
// delivery retry against the new attachment if a write races the swap.
func (device *Device) ReplaceTUN(tunDevice gtun.Tun) error {
	if device.isClosed() {
		if tunDevice != nil {
			_ = tunDevice.Close()
		}
		return ErrDeviceClosed
	}
	tunState, err := newTunState(tunDevice)
	if err != nil {
		return err
	}
	if tunDevice.BatchSize() > device.BatchSize() {
		return fmt.Errorf("replacement tun batch size %d exceeds device batch size %d", tunDevice.BatchSize(), device.BatchSize())
	}
	mtu, err := tunDevice.MTU()
	if err != nil {
		device.log.Errf("Trouble determining MTU, assuming default: %v", err)
		mtu = DefaultMTU
	}

	device.state.Lock()
	if device.isClosed() {
		device.state.Unlock()
		_ = tunDevice.Close()
		return ErrDeviceClosed
	}

	old := device.tun.device.Swap(tunState)
	device.tun.mtu.Store(int32(mtu))
	device.state.Unlock()

	device.startTUN(tunState)
	device.stopTUN(old)
	device.log.Debugf("TUN device replaced")
	return nil
}

// AttachTUN attaches a TUN to a device that is currently detached.
func (device *Device) AttachTUN(tunDevice gtun.Tun) error {
	if device.isClosed() {
		if tunDevice != nil {
			_ = tunDevice.Close()
		}
		return ErrDeviceClosed
	}
	tunState, err := newTunState(tunDevice)
	if err != nil {
		return err
	}
	if tunDevice.BatchSize() > device.BatchSize() {
		return fmt.Errorf("replacement tun batch size %d exceeds device batch size %d", tunDevice.BatchSize(), device.BatchSize())
	}
	mtu, err := tunDevice.MTU()
	if err != nil {
		device.log.Errf("Trouble determining MTU, assuming default: %v", err)
		mtu = DefaultMTU
	}

	device.state.Lock()
	if device.isClosed() {
		device.state.Unlock()
		_ = tunDevice.Close()
		return ErrDeviceClosed
	}
	if device.currentTUN() != nil {
		device.state.Unlock()
		_ = tunDevice.Close()
		return fmt.Errorf("device already has a TUN attached")
	}

	device.tun.device.Store(tunState)
	device.tun.mtu.Store(int32(mtu))
	device.state.Unlock()

	device.startTUN(tunState)
	device.log.Debugf("TUN device attached")
	return nil
}

// DetachTUN closes and removes the currently attached TUN, if any.
func (device *Device) DetachTUN() error {
	device.state.Lock()
	if device.isClosed() {
		device.state.Unlock()
		return ErrDeviceClosed
	}
	old := device.tun.device.Swap(nil)
	if old == nil {
		device.state.Unlock()
		return nil
	}
	device.tun.mtu.Store(int32(DefaultMTU))
	device.state.Unlock()

	device.stopTUN(old)
	device.log.Debugf("TUN device detached")
	return nil
}

// ReplaceTrackedTUN calls ReplaceTUN.
//
// Device owns its TUN for its full lifetime. The tracked distinction is useful
// to middleware with a shorter lifetime.
func (device *Device) ReplaceTrackedTUN(tunDevice gtun.Tun) error {
	return device.ReplaceTUN(tunDevice)
}

// AttachTrackedTUN calls AttachTUN.
//
// Device owns its TUN for its full lifetime. The tracked distinction is useful
// to middleware with a shorter lifetime.
func (device *Device) AttachTrackedTUN(tunDevice gtun.Tun) error {
	return device.AttachTUN(tunDevice)
}

// DetachTrackedTUN calls DetachTUN.
//
// Device owns its TUN for its full lifetime. The tracked distinction is useful
// to middleware with a shorter lifetime.
func (device *Device) DetachTrackedTUN() error {
	return device.DetachTUN()
}

// ReplaceBind atomically swaps the active bind attachment.
// If the device is up, active peer sessions are restarted around the transition.
func (device *Device) ReplaceBind(bind conn.Bind) error {
	if device.isClosed() {
		return ErrDeviceClosed
	}
	if bind == nil {
		return device.DetachBind()
	}
	if bind.BatchSize() > device.BatchSize() {
		return fmt.Errorf("replacement bind batch size %d exceeds device batch size %d", bind.BatchSize(), device.BatchSize())
	}

	device.state.Lock()
	defer device.state.Unlock()
	if device.isClosed() {
		return ErrDeviceClosed
	}

	wasUp := device.isUp()
	if wasUp {
		if err := device.downLocked(); err != nil {
			return err
		}
	}

	device.net.Lock()
	device.swapBindLocked(bind)
	if err := device.rebindPeerEndpointsLocked(bind); err != nil {
		device.net.Unlock()
		return err
	}
	device.net.Unlock()

	if wasUp {
		if err := device.upLocked(); err != nil {
			return err
		}
	}

	device.log.Debugf("Bind replaced")
	return nil
}

// AttachBind attaches a bind to a device that is currently detached.
func (device *Device) AttachBind(bind conn.Bind) error {
	if device.isClosed() {
		return ErrDeviceClosed
	}
	if bind == nil {
		return fmt.Errorf("bind is nil")
	}
	if bind.BatchSize() > device.BatchSize() {
		return fmt.Errorf("replacement bind batch size %d exceeds device batch size %d", bind.BatchSize(), device.BatchSize())
	}

	device.state.Lock()
	defer device.state.Unlock()
	if device.isClosed() {
		return ErrDeviceClosed
	}
	if device.net.bind != nil {
		return fmt.Errorf("device already has a bind attached")
	}

	device.net.Lock()
	device.swapBindLocked(bind)
	if err := device.rebindPeerEndpointsLocked(bind); err != nil {
		device.swapBindLocked(nil)
		device.net.Unlock()
		return err
	}
	device.net.Unlock()

	if device.isUp() {
		if err := device.upLocked(); err != nil {
			device.net.Lock()
			device.swapBindLocked(nil)
			device.net.Unlock()
			return err
		}
	}

	device.log.Debugf("Bind attached")
	return nil
}

// DetachBind closes and removes the currently attached bind, if any.
// If the device is up, active peer sessions are stopped until another bind is attached.
func (device *Device) DetachBind() error {
	device.state.Lock()
	defer device.state.Unlock()
	if device.isClosed() {
		return ErrDeviceClosed
	}

	if device.isUp() {
		if err := device.downLocked(); err != nil {
			return err
		}
	}

	device.net.Lock()
	device.swapBindLocked(nil)
	device.net.Unlock()
	device.log.Debugf("Bind detached")
	return nil
}

// ReplaceTrackedBind calls ReplaceBind.
//
// Device owns its bind for its full lifetime. The tracked distinction is useful
// to middleware with a shorter lifetime.
func (device *Device) ReplaceTrackedBind(bind conn.Bind) error {
	return device.ReplaceBind(bind)
}

// AttachTrackedBind calls AttachBind.
//
// Device owns its bind for its full lifetime. The tracked distinction is useful
// to middleware with a shorter lifetime.
func (device *Device) AttachTrackedBind(bind conn.Bind) error {
	return device.AttachBind(bind)
}

// DetachTrackedBind calls DetachBind.
//
// Device owns its bind for its full lifetime. The tracked distinction is useful
// to middleware with a shorter lifetime.
func (device *Device) DetachTrackedBind() error {
	return device.DetachBind()
}
