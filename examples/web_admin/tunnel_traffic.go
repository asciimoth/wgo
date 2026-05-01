// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 AsciiMoth

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultTunnelEchoPort = 18080

type tunnelTrafficState struct {
	mu              sync.Mutex
	echoListener    net.Listener
	echoListenAddr  string
	lastProbeResult string
}

type tunnelTrafficSummary struct {
	EchoListenAddr  string `json:"echo_listen_addr,omitempty"`
	LastProbeResult string `json:"last_probe_result,omitempty"`
}

type tunnelEchoRequest struct {
	Port *uint16 `json:"port"`
}

type tunnelProbeRequest struct {
	RemoteIP *string `json:"remote_ip"`
	Port     *uint16 `json:"port"`
	Message  *string `json:"message"`
}

func newTunnelTrafficSummary(state *tunnelTrafficState) *tunnelTrafficSummary {
	state.mu.Lock()
	defer state.mu.Unlock()

	if state.echoListenAddr == "" && state.lastProbeResult == "" {
		return nil
	}
	return &tunnelTrafficSummary{
		EchoListenAddr:  state.echoListenAddr,
		LastProbeResult: state.lastProbeResult,
	}
}

func (s *tunnelTrafficState) startEchoOn(listener net.Listener) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.echoListener != nil {
		return fmt.Errorf("tunnel echo is already running on %s", s.echoListenAddr)
	}

	s.echoListener = listener
	s.echoListenAddr = listener.Addr().String()
	log.Printf("[web_admin tunnel] echo listening on %s", s.echoListenAddr)

	go s.serveEcho(listener)
	return nil
}

func (s *tunnelTrafficState) serveEcho(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[web_admin tunnel] echo accept on %s stopped: %v", listener.Addr(), err)
			return
		}
		go s.handleEchoConn(conn)
	}
}

func (s *tunnelTrafficState) handleEchoConn(conn net.Conn) {
	defer conn.Close()

	log.Printf("[web_admin tunnel] echo accepted local=%s remote=%s", conn.LocalAddr(), conn.RemoteAddr())
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		log.Printf("[web_admin tunnel] echo set deadline error: %v", err)
		return
	}

	payload, err := io.ReadAll(io.LimitReader(conn, 4096))
	if err != nil {
		log.Printf("[web_admin tunnel] echo read error: %v", err)
		return
	}
	msg := strings.TrimSpace(string(payload))
	reply := "echo:" + msg
	if _, err := io.WriteString(conn, reply); err != nil {
		log.Printf("[web_admin tunnel] echo write error: %v", err)
		return
	}
	log.Printf("[web_admin tunnel] echo replied local=%s remote=%s msg=%q reply=%q", conn.LocalAddr(), conn.RemoteAddr(), msg, reply)
}

func (s *tunnelTrafficState) stopEcho() error {
	s.mu.Lock()
	listener := s.echoListener
	addr := s.echoListenAddr
	s.echoListener = nil
	s.echoListenAddr = ""
	s.mu.Unlock()

	if listener == nil {
		return nil
	}
	log.Printf("[web_admin tunnel] stopping echo on %s", addr)
	return listener.Close()
}

func (s *tunnelTrafficState) setLastProbeResult(result string) {
	s.mu.Lock()
	s.lastProbeResult = result
	s.mu.Unlock()
}

func (a *adminApp) tunnelLocalPeerIPs() (localIP, peerIP netip.Addr, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.tun == nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("attach TUN first")
	}
	return a.tun.localIP, a.tun.peerIP, nil
}

func (a *adminApp) startTunnelEcho(req tunnelEchoRequest) error {
	localIP, _, err := a.tunnelLocalPeerIPs()
	if err != nil {
		return err
	}
	stack, err := a.tunnelNetwork()
	if err != nil {
		return err
	}

	port := uint16(defaultTunnelEchoPort)
	if req.Port != nil && *req.Port != 0 {
		port = *req.Port
	}

	listener, err := stack.ListenTCP(context.Background(), "tcp4", net.JoinHostPort(localIP.String(), strconv.Itoa(int(port))))
	if err != nil {
		return fmt.Errorf("listen on userspace tunnel %s:%d: %w", localIP, port, err)
	}
	return a.traffic.startEchoOn(listener)
}

func (a *adminApp) stopTunnelEcho() error {
	return a.traffic.stopEcho()
}

func (a *adminApp) probeTunnel(req tunnelProbeRequest) (string, error) {
	localIP, defaultPeerIP, err := a.tunnelLocalPeerIPs()
	if err != nil {
		return "", err
	}
	stack, err := a.tunnelNetwork()
	if err != nil {
		return "", err
	}

	remoteIP := defaultPeerIP
	if req.RemoteIP != nil && strings.TrimSpace(*req.RemoteIP) != "" {
		remoteIP, err = netip.ParseAddr(strings.TrimSpace(*req.RemoteIP))
		if err != nil {
			return "", fmt.Errorf("parse remote_ip: %w", err)
		}
	}

	port := uint16(defaultTunnelEchoPort)
	if req.Port != nil && *req.Port != 0 {
		port = *req.Port
	}

	message := fmt.Sprintf("probe from %s to %s at %s", localIP, remoteIP, time.Now().UTC().Format(time.RFC3339Nano))
	if req.Message != nil && strings.TrimSpace(*req.Message) != "" {
		message = strings.TrimSpace(*req.Message)
	}

	remoteAddr := net.JoinHostPort(remoteIP.String(), strconv.Itoa(int(port)))
	log.Printf("[web_admin tunnel] probe dialing local=%s remote=%s", localIP, remoteAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()

	conn, err := stack.DialTCP(ctx, "tcp4", net.JoinHostPort(localIP.String(), "0"), remoteAddr)
	if err != nil {
		return "", fmt.Errorf("dial %s from %s: %w", remoteAddr, localIP, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return "", err
	}
	if _, err := io.WriteString(conn, message); err != nil {
		return "", fmt.Errorf("write probe: %w", err)
	}
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}

	reply, err := io.ReadAll(io.LimitReader(conn, 4096))
	if err != nil {
		return "", fmt.Errorf("read reply: %w", err)
	}

	result := fmt.Sprintf("local=%s remote=%s reply=%q", conn.LocalAddr(), conn.RemoteAddr(), string(reply))
	log.Printf("[web_admin tunnel] probe success %s", result)
	a.traffic.setLastProbeResult(result)
	return result, nil
}
