/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Modifications Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	conn "github.com/asciimoth/batchudp"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type QueueHandshakeElement struct {
	msgType  uint32
	amnezia  amneziaWGSnapshot
	packet   []byte
	endpoint conn.Endpoint
	buffer   *[MessageBufferSize]byte
}

type QueueInboundElement struct {
	buffer   *[MessageBufferSize]byte
	packet   []byte
	counter  uint64
	keypair  *Keypair
	endpoint conn.Endpoint
}

type QueueInboundElementsContainer struct {
	sync.Mutex
	elems []*QueueInboundElement
}

type ReceiveError struct {
	Name  string
	Err   error
	Fatal bool
}

// SubscribeReceiveErrors registers cb for receive-loop errors and returns an
// unsubscribe function. Callbacks are invoked asynchronously.
func (device *Device) SubscribeReceiveErrors(cb func(ReceiveError)) func() {
	if cb == nil {
		return func() {}
	}

	device.receiveErrors.Lock()
	device.receiveErrors.nextSubID++
	id := device.receiveErrors.nextSubID
	device.receiveErrors.subscribers[id] = cb
	device.receiveErrors.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			device.receiveErrors.Lock()
			delete(device.receiveErrors.subscribers, id)
			device.receiveErrors.Unlock()
		})
	}
}

// ReceiveErrorShouldRecover reports whether an unexpected receive error is a
// candidate for caller-controlled bind recovery.
func ReceiveErrorShouldRecover(err error) bool {
	if err == nil || errors.Is(err, net.ErrClosed) {
		return false
	}
	var neterr net.Error
	if errors.As(err, &neterr) && neterr.Timeout() {
		return false
	}
	type temporary interface {
		Temporary() bool
	}
	var temperr temporary
	if errors.As(err, &temperr) && temperr.Temporary() {
		return false
	}
	return true
}

func (device *Device) reportReceiveError(receiveError ReceiveError) {
	if receiveError.Err == nil || errors.Is(receiveError.Err, net.ErrClosed) {
		return
	}

	device.receiveErrors.RLock()
	callbacks := make([]func(ReceiveError), 0, len(device.receiveErrors.subscribers))
	for _, cb := range device.receiveErrors.subscribers {
		callbacks = append(callbacks, cb)
	}
	device.receiveErrors.RUnlock()

	for _, cb := range callbacks {
		go device.callReceiveErrorCallback(cb, receiveError)
	}
}

func (device *Device) callReceiveErrorCallback(cb func(ReceiveError), receiveError ReceiveError) {
	defer func() {
		if recover() != nil {
			device.log.Debugf("receive error callback panicked")
		}
	}()
	cb(receiveError)
}

func buildTUNWriteBuffers(tun *tunState, elems []*QueueInboundElement, bufs [][]byte) [][]byte {
	bufs = bufs[:0]
	for _, elem := range elems {
		if tun.writeUsesLargeBufs {
			buf := make([]byte, tun.writeOffset+len(elem.packet))
			copy(buf[tun.writeOffset:], elem.packet)
			bufs = append(bufs, buf)
			continue
		}
		if tun.writeNeedsCopy {
			copy(elem.buffer[tun.writeOffset:], elem.packet)
			bufs = append(bufs, elem.buffer[:tun.writeOffset+len(elem.packet)])
			continue
		}
		bufs = append(bufs, elem.buffer[:MessageTransportOffsetContent+len(elem.packet)])
	}
	return bufs
}

func writeTUNBuffers(tun *tunState, bufs [][]byte) error {
	batchSize := tun.device.BatchSize()
	if batchSize < 1 {
		batchSize = len(bufs)
	}
	for len(bufs) > 0 {
		chunkSize := batchSize
		if chunkSize > len(bufs) {
			chunkSize = len(bufs)
		}
		chunk := bufs[:chunkSize]
		written, err := tun.device.Write(chunk, tun.writeOffset)
		if err != nil {
			return err
		}
		if written < 0 || written > len(chunk) {
			return io.ErrShortWrite
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		bufs = bufs[written:]
	}
	return nil
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *QueueInboundElement) clearPointers() {
	elem.buffer = nil
	elem.packet = nil
	elem.keypair = nil
	elem.endpoint = nil
}

/* Called when a new authenticated message has been received
 *
 * NOTE: Not thread safe, but called by sequential receiver!
 */
func (peer *Peer) keepKeyFreshReceiving() {
	if peer.timers.sentLastMinuteHandshake.Load() {
		return
	}
	keypair := peer.keypairs.Current()
	if keypair != nil && keypair.isInitiator && time.Since(keypair.created) > (RejectAfterTime-KeepaliveTimeout-RekeyTimeout) {
		peer.timers.sentLastMinuteHandshake.Store(true)
		if err := peer.SendHandshakeInitiation(false); err != nil {
			peer.device.log.Debugf("%v - Failed to send handshake initiation: %v", peer, err)
		}
	}
}

/* Receives incoming datagrams for the device
 *
 * Every time the bind is updated a new routine is started for
 * IPv4 and IPv6 (separately)
 */
func (device *Device) RoutineReceiveIncoming(maxBatchSize int, recv conn.ReceiveFunc) {
	recvName := recv.PrettyName()
	defer func() {
		device.logWorkerLifecyclef("Routine: receive incoming %s - stopped", recvName)
		device.queue.decryption.wg.Done()
		device.queue.handshake.wg.Done()
		device.net.stopping.Done()
	}()

	device.logWorkerLifecyclef("Routine: receive incoming %s - started", recvName)

	// receive datagrams until conn is closed

	var (
		bufsArrs    = make([]*[MessageBufferSize]byte, maxBatchSize)
		bufs        = make([][]byte, maxBatchSize)
		err         error
		sizes       = make([]int, maxBatchSize)
		count       int
		endpoints   = make([]conn.Endpoint, maxBatchSize)
		deathSpiral int
		elemsByPeer = make(map[*Peer]*QueueInboundElementsContainer, maxBatchSize)
	)

	for i := range bufsArrs {
		bufsArrs[i] = device.GetMessageBuffer()
		bufs[i] = bufsArrs[i][:]
	}

	defer func() {
		for i := 0; i < maxBatchSize; i++ {
			if bufsArrs[i] != nil {
				device.PutMessageBuffer(bufsArrs[i])
			}
		}
	}()

	for {
		count, err = recv(bufs, sizes, endpoints)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			device.log.Debugf("Failed to receive %s packet: %v", recvName, err)
			if ReceiveErrorShouldRecover(err) {
				device.reportReceiveError(ReceiveError{Name: recvName, Err: err, Fatal: true})
				return
			}
			if deathSpiral < 10 {
				deathSpiral++
				device.reportReceiveError(ReceiveError{Name: recvName, Err: err, Fatal: false})
				time.Sleep(time.Second / 3)
				continue
			}
			device.reportReceiveError(ReceiveError{Name: recvName, Err: err, Fatal: true})
			return
		}
		deathSpiral = 0
		if err := validateReceiveBatch(count, maxBatchSize, sizes, endpoints, bufs); err != nil {
			device.log.Debugf("Invalid receive %s batch: %v", recvName, err)
			device.reportReceiveError(ReceiveError{Name: recvName, Err: err, Fatal: true})
			return
		}

		// handle each packet in the batch
		for i, size := range sizes[:count] {
			if size < MinMessageSize {
				continue
			}

			packet := bufsArrs[i][:size]
			msgType, padding, amnezia := device.determinePacketTypeAndPadding(packet, MessageUnknownType)
			if padding > 0 {
				copy(packet, packet[padding:])
				packet = packet[:len(packet)-padding]
			}

			switch msgType {

			// check if transport

			case MessageTransportType:

				// check size

				if len(packet) < MessageTransportSize {
					continue
				}

				// lookup key pair

				receiver := binary.LittleEndian.Uint32(
					packet[MessageTransportOffsetReceiver:MessageTransportOffsetCounter],
				)
				value := device.indexTable.Lookup(receiver)
				keypair := value.keypair
				if keypair == nil {
					continue
				}

				// check keypair expiry

				if keypair.created.Add(RejectAfterTime).Before(time.Now()) {
					continue
				}

				// create work element
				peer := value.peer
				elem := device.GetInboundElement()
				elem.packet = packet
				elem.buffer = bufsArrs[i]
				elem.keypair = keypair
				elem.endpoint = endpoints[i]
				elem.counter = 0

				elemsForPeer, ok := elemsByPeer[peer]
				if !ok {
					elemsForPeer = device.GetInboundElementsContainer()
					elemsForPeer.Lock()
					elemsByPeer[peer] = elemsForPeer
				}
				elemsForPeer.elems = append(elemsForPeer.elems, elem)
				bufsArrs[i] = device.GetMessageBuffer()
				bufs[i] = bufsArrs[i][:]
				continue

			// otherwise it is a fixed size & handshake related packet

			case MessageInitiationType:
				if len(packet) != MessageInitiationSize {
					continue
				}

			case MessageResponseType:
				if len(packet) != MessageResponseSize {
					continue
				}

			case MessageCookieReplyType:
				if len(packet) != MessageCookieReplySize {
					continue
				}

			default:
				device.log.Debugf("Received message with unknown type")
				continue
			}

			select {
			case device.queue.handshake.c <- QueueHandshakeElement{
				msgType:  msgType,
				amnezia:  amnezia,
				buffer:   bufsArrs[i],
				packet:   packet,
				endpoint: endpoints[i],
			}:
				bufsArrs[i] = device.GetMessageBuffer()
				bufs[i] = bufsArrs[i][:]
			default:
			}
		}
		for peer, elemsContainer := range elemsByPeer {
			if peer.isRunning.Load() {
				peer.queue.inbound.c <- elemsContainer
				device.queue.decryption.c <- elemsContainer
			} else {
				for _, elem := range elemsContainer.elems {
					device.PutMessageBuffer(elem.buffer)
					device.PutInboundElement(elem)
				}
				device.PutInboundElementsContainer(elemsContainer)
			}
			delete(elemsByPeer, peer)
		}
	}
}

func validateReceiveBatch(count, maxBatchSize int, sizes []int, endpoints []conn.Endpoint, bufs [][]byte) error {
	// ReceiveFunc is provided by conn.Bind implementations. Validate its batch
	// contract before slicing buffers so a bad library embedder cannot panic the
	// receive routine.
	if count < 0 || count > maxBatchSize {
		return fmt.Errorf("invalid packet count %d", count)
	}
	for i := 0; i < count; i++ {
		if sizes[i] < 0 || sizes[i] > len(bufs[i]) {
			return fmt.Errorf("invalid packet size %d at index %d", sizes[i], i)
		}
		if sizes[i] >= MinMessageSize && endpoints[i] == nil {
			return fmt.Errorf("missing endpoint at index %d", i)
		}
	}
	return nil
}

func (device *Device) RoutineDecryption(id int) {
	var nonce [chacha20poly1305.NonceSize]byte

	defer device.logWorkerLifecyclef("Routine: decryption worker %d - stopped", id)
	device.logWorkerLifecyclef("Routine: decryption worker %d - started", id)

	for elemsContainer := range device.queue.decryption.c {
		for _, elem := range elemsContainer.elems {
			// split message into fields
			counter := elem.packet[MessageTransportOffsetCounter:MessageTransportOffsetContent]
			content := elem.packet[MessageTransportOffsetContent:]

			// decrypt and release to consumer
			var err error
			elem.counter = binary.LittleEndian.Uint64(counter)
			// copy counter to nonce
			binary.LittleEndian.PutUint64(nonce[0x4:0xc], elem.counter)
			elem.packet, err = elem.keypair.receive.Open(
				content[:0],
				nonce[:],
				content,
				nil,
			)
			if err != nil {
				elem.packet = nil
			}
		}
		elemsContainer.Unlock()
	}
}

/* Handles incoming packets related to handshake
 */
func (device *Device) RoutineHandshake(id int) {
	defer func() {
		device.logWorkerLifecyclef("Routine: handshake worker %d - stopped", id)
		device.queue.encryption.wg.Done()
	}()
	device.logWorkerLifecyclef("Routine: handshake worker %d - started", id)

	for elem := range device.queue.handshake.c {

		// handle cookie fields and ratelimiting

		switch elem.msgType {

		case MessageCookieReplyType:

			// unmarshal packet

			var reply MessageCookieReply
			err := reply.unmarshal(elem.packet)
			if err != nil {
				device.log.Debugf("Failed to decode cookie reply")
				goto skip
			}

			// lookup peer from index

			entry := device.indexTable.Lookup(reply.Receiver)

			if entry.peer == nil {
				goto skip
			}

			// consume reply

			if peer := entry.peer; peer.isRunning.Load() {
				device.log.Debugf("Receiving cookie response from %s", elem.endpoint.DstToString())
				if !peer.cookieGenerator.ConsumeReply(&reply) {
					device.log.Debugf("Could not decrypt invalid cookie response")
				}
			}

			goto skip

		case MessageInitiationType, MessageResponseType:

			// check mac fields and maybe ratelimit

			if !device.cookieChecker.CheckMAC1(elem.packet) {
				device.log.Debugf("Received packet with invalid mac1")
				goto skip
			}

			// endpoints destination address is the source of the datagram

			if device.IsUnderLoad() {

				// verify MAC2 field

				if !device.cookieChecker.CheckMAC2(elem.packet, elem.endpoint.DstToBytes()) {
					if err := device.SendHandshakeCookie(&elem); err != nil {
						device.log.Debugf("Failed to send handshake cookie: %v", err)
					}
					goto skip
				}

				// check ratelimiter

				if !device.rate.limiter.Allow(elem.endpoint.DstIP()) {
					goto skip
				}
			}

		default:
			device.log.Errf("Invalid packet ended up in the handshake queue")
			goto skip
		}

		// handle handshake initiation/response content

		switch elem.msgType {
		case MessageInitiationType:

			// unmarshal

			var msg MessageInitiation
			err := msg.unmarshal(elem.packet)
			if err != nil {
				device.log.Errf("Failed to decode initiation message")
				goto skip
			}
			msg.Type = elem.msgType

			// consume initiation

			peer := device.ConsumeMessageInitiation(&msg)
			if peer == nil {
				device.log.Debugf("Received invalid initiation message from %s", elem.endpoint.DstToString())
				goto skip
			}

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// update endpoint
			peer.SetEndpointFromPacket(elem.endpoint)

			device.log.Debugf("%v - Received handshake initiation", peer)
			peer.rxBytes.Add(uint64(len(elem.packet)))
			peer.device.accountRuntimeStatsRx(uint64(len(elem.packet)), 1)

			if err := peer.SendHandshakeResponse(); err != nil {
				device.log.Debugf("%v - Failed to send handshake response: %v", peer, err)
			}

		case MessageResponseType:

			// unmarshal

			var msg MessageResponse
			err := msg.unmarshal(elem.packet)
			if err != nil {
				device.log.Errf("Failed to decode response message")
				goto skip
			}
			msg.Type = elem.msgType

			// consume response

			peer := device.ConsumeMessageResponse(&msg)
			if peer == nil {
				device.log.Debugf("Received invalid response message from %s", elem.endpoint.DstToString())
				goto skip
			}

			// update endpoint
			peer.SetEndpointFromPacket(elem.endpoint)

			device.log.Debugf("%v - Received handshake response", peer)
			peer.rxBytes.Add(uint64(len(elem.packet)))
			peer.device.accountRuntimeStatsRx(uint64(len(elem.packet)), 1)

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// derive keypair

			err = peer.BeginSymmetricSession()

			if err != nil {
				device.log.Errf("%v - Failed to derive keypair: %v", peer, err)
				goto skip
			}

			peer.timersSessionDerived()
			peer.timersHandshakeComplete()
			peer.SendKeepalive()
		}
	skip:
		device.PutMessageBuffer(elem.buffer)
	}
}

func (peer *Peer) RoutineSequentialReceiver(maxBatchSize int) {
	device := peer.device
	defer func() {
		device.logWorkerLifecyclef("%v - Routine: sequential receiver - stopped", peer)
		peer.stopping.Done()
	}()
	device.logWorkerLifecyclef("%v - Routine: sequential receiver - started", peer)

	bufs := make([][]byte, 0, maxBatchSize)
	packets := make([]*QueueInboundElement, 0, maxBatchSize)

	for elemsContainer := range peer.queue.inbound.c {
		if elemsContainer == nil {
			return
		}
		elemsContainer.Lock()
		validTailPacket := -1
		dataPacketReceived := false
		rxBytesLen := uint64(0)
		rxPackets := uint64(0)
		for i, elem := range elemsContainer.elems {
			if elem.packet == nil {
				// decryption failed
				continue
			}

			if !elem.keypair.replayFilter.ValidateCounter(elem.counter, RejectAfterMessages) {
				continue
			}

			validTailPacket = i
			if peer.ReceivedWithKeypair(elem.keypair) {
				peer.SetEndpointFromPacket(elem.endpoint)
				peer.timersHandshakeComplete()
				peer.SendStagedPackets()
			}
			rxBytesLen += uint64(len(elem.packet) + MinMessageSize)
			rxPackets++

			if len(elem.packet) == 0 {
				device.log.Debugf("%v - Receiving keepalive packet", peer)
				continue
			}
			dataPacketReceived = true

			switch elem.packet[0] >> 4 {
			case 4:
				if len(elem.packet) < ipv4.HeaderLen {
					continue
				}
				field := elem.packet[IPv4offsetTotalLength : IPv4offsetTotalLength+2]
				length := binary.BigEndian.Uint16(field)
				if int(length) > len(elem.packet) || int(length) < ipv4.HeaderLen {
					continue
				}
				elem.packet = elem.packet[:length]
				src := elem.packet[IPv4offsetSrc : IPv4offsetSrc+net.IPv4len]
				if device.allowedips.Lookup(src) != peer {
					device.log.Debugf("IPv4 packet with disallowed source address from %v", peer)
					continue
				}

			case 6:
				if len(elem.packet) < ipv6.HeaderLen {
					continue
				}
				field := elem.packet[IPv6offsetPayloadLength : IPv6offsetPayloadLength+2]
				length := binary.BigEndian.Uint16(field)
				length += ipv6.HeaderLen
				if int(length) > len(elem.packet) {
					continue
				}
				elem.packet = elem.packet[:length]
				src := elem.packet[IPv6offsetSrc : IPv6offsetSrc+net.IPv6len]
				if device.allowedips.Lookup(src) != peer {
					device.log.Debugf("IPv6 packet with disallowed source address from %v", peer)
					continue
				}

			default:
				device.log.Debugf("Packet with invalid IP version from %v", peer)
				continue
			}

			packets = append(packets, elem)
		}

		peer.rxBytes.Add(rxBytesLen)
		peer.device.accountRuntimeStatsRx(rxBytesLen, rxPackets)
		if validTailPacket >= 0 {
			peer.SetEndpointFromPacket(elemsContainer.elems[validTailPacket].endpoint)
			peer.keepKeyFreshReceiving()
			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()
		}
		if dataPacketReceived {
			peer.timersDataReceived()
		}
		if len(packets) > 0 {
			tun := device.currentTUN()
			var err error
			if tun != nil {
				bufs = buildTUNWriteBuffers(tun, packets, bufs)
				err = writeTUNBuffers(tun, bufs)
				if err != nil && !device.isClosed() {
					if nextTun := device.currentTUN(); nextTun != nil && nextTun != tun {
						bufs = buildTUNWriteBuffers(nextTun, packets, bufs)
						err = writeTUNBuffers(nextTun, bufs)
					}
				}
			}
			if err != nil && !device.isClosed() {
				device.log.Errf("Failed to write packets to TUN device: %v", err)
			}
		}
		for _, elem := range elemsContainer.elems {
			device.PutMessageBuffer(elem.buffer)
			device.PutInboundElement(elem)
		}
		bufs = bufs[:0]
		packets = packets[:0]
		device.PutInboundElementsContainer(elemsContainer)
	}
}

func (device *Device) DeterminePacketTypeAndPadding(packet []byte, expectedType uint32) (uint32, int) {
	msgType, padding, _ := device.determinePacketTypeAndPadding(packet, expectedType)
	return msgType, padding
}

func (device *Device) determinePacketTypeAndPadding(packet []byte, expectedType uint32) (uint32, int, amneziaWGSnapshot) {
	size := len(packet)
	classifier := device.amneziaReceiveClassifier.Load()
	if classifier == nil {
		amnezia := device.amneziaWGSnapshot()
		if msgType, padding, ok := classifyAmneziaWGPacket(packet, size, expectedType, amnezia); ok {
			return msgType, padding, amnezia
		}
		return MessageUnknownType, 0, amneziaWGSnapshot{}
	}

	if candidate, ok := classifier.classify(packet, expectedType); ok {
		return candidate.msgType, candidate.padding, candidate.amnezia
	}
	return MessageUnknownType, 0, amneziaWGSnapshot{}
}

// classify checks only candidates that can match the packet size and header
// value. The work per unauthenticated datagram stays bounded by the number of
// valid header offsets, not by the number of configured peer profiles.
func (classifier *amneziaWGReceiveClassifier) classify(packet []byte, expectedType uint32) (amneziaWGReceiveCandidate, bool) {
	size := len(packet)
	var best amneziaWGReceiveCandidate
	found := false

	if expectedType == MessageUnknownType ||
		expectedType == MessageInitiationType ||
		expectedType == MessageResponseType ||
		expectedType == MessageCookieReplyType {
		for padding, index := range classifier.fixedBySize[size] {
			if padding+4 > size {
				continue
			}
			header := binary.LittleEndian.Uint32(packet[padding:])
			candidate, ok := index.lookup(header, expectedType)
			if ok && (!found || candidate.order < best.order) {
				best = candidate
				found = true
			}
		}
	}

	if expectedType == MessageUnknownType || expectedType == MessageTransportType {
		maxPadding := size - MessageTransportHeaderSize
		if maxPadding > maxAmneziaWGTransportPaddingSize {
			maxPadding = maxAmneziaWGTransportPaddingSize
		}
		for padding := 0; padding <= maxPadding; padding++ {
			index := &classifier.transportByPadding[padding]
			if index.empty() {
				continue
			}
			header := binary.LittleEndian.Uint32(packet[padding:])
			candidate, ok := index.lookup(header, expectedType)
			if ok && (!found || candidate.order < best.order) {
				best = candidate
				found = true
			}
		}
	}

	return best, found
}

func classifyAmneziaWGPacket(packet []byte, size int, expectedType uint32, amnezia amneziaWGSnapshot) (uint32, int, bool) {
	if expectedType == MessageUnknownType || expectedType == MessageInitiationType {
		padding := amnezia.paddings.init
		if amnezia.headers.init != nil && size == padding+MessageInitiationSize && size >= padding+4 && amnezia.headers.init.Validate(binary.LittleEndian.Uint32(packet[padding:])) {
			return MessageInitiationType, padding, true
		}
	}
	if expectedType == MessageUnknownType || expectedType == MessageResponseType {
		padding := amnezia.paddings.response
		if amnezia.headers.response != nil && size == padding+MessageResponseSize && size >= padding+4 && amnezia.headers.response.Validate(binary.LittleEndian.Uint32(packet[padding:])) {
			return MessageResponseType, padding, true
		}
	}
	if expectedType == MessageUnknownType || expectedType == MessageCookieReplyType {
		padding := amnezia.paddings.cookie
		if amnezia.headers.cookie != nil && size == padding+MessageCookieReplySize && size >= padding+4 && amnezia.headers.cookie.Validate(binary.LittleEndian.Uint32(packet[padding:])) {
			return MessageCookieReplyType, padding, true
		}
	}
	if expectedType == MessageUnknownType || expectedType == MessageTransportType {
		padding := amnezia.paddings.transport
		if amnezia.headers.transport != nil && size >= padding+MessageTransportHeaderSize && size >= padding+4 && amnezia.headers.transport.Validate(binary.LittleEndian.Uint32(packet[padding:])) {
			return MessageTransportType, padding, true
		}
		if padding > 0 && amnezia.headers.transport != nil && size >= MessageTransportHeaderSize && amnezia.headers.transport.Validate(binary.LittleEndian.Uint32(packet)) {
			return MessageTransportType, 0, true
		}
	}
	return MessageUnknownType, 0, false
}
