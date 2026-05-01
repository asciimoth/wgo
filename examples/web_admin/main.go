// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 AsciiMoth

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	conn "github.com/asciimoth/batchudp"
	"github.com/asciimoth/gonnect-netstack/vtun"
	gtun "github.com/asciimoth/gonnect/tun"
	"github.com/asciimoth/tuntap"
	"github.com/asciimoth/wgo/device"
	"golang.org/x/crypto/curve25519"
)

const defaultMTU = 1420

func main() {
	app, err := newAdminApp()
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := app.Close(); err != nil {
			log.Printf("cleanup error: %v", err)
		}
	}()

	if err := app.Run(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

type adminApp struct {
	dev     *device.Device
	server  *http.Server
	plan    pairingPlan
	traffic tunnelTrafficState

	mu   sync.Mutex
	tun  *tunAttachment
	bind *bindAttachment
}

type tunAttachment struct {
	kind    string
	name    string
	localIP netip.Addr
	peerIP  netip.Addr
	mtu     int
	stack   *vtun.VTun
	cleanup func() error
}

type bindAttachment struct {
	network       *recordingNetwork
	requestedPort uint16
}

type appState struct {
	Device  deviceStateSummary    `json:"device"`
	TUN     *tunStateSummary      `json:"tun,omitempty"`
	Bind    *bindStateSummary     `json:"bind,omitempty"`
	Traffic *tunnelTrafficSummary `json:"traffic,omitempty"`
}

type deviceStateSummary struct {
	PrivateKey string              `json:"private_key"`
	ListenPort uint16              `json:"listen_port"`
	Fwmark     uint32              `json:"fwmark"`
	AmneziaWG  amneziaStateSummary `json:"amneziawg"`
	Peers      []peerStateSummary  `json:"peers"`
}

type peerStateSummary struct {
	PublicKey                   string               `json:"public_key"`
	PresharedKey                string               `json:"preshared_key"`
	ProtocolVersion             int                  `json:"protocol_version"`
	Endpoint                    string               `json:"endpoint"`
	LastHandshakeTime           string               `json:"last_handshake_time"`
	TxBytes                     uint64               `json:"tx_bytes"`
	RxBytes                     uint64               `json:"rx_bytes"`
	PersistentKeepaliveInterval uint16               `json:"persistent_keepalive_interval"`
	AllowedIPs                  []string             `json:"allowed_ips"`
	AmneziaWG                   *amneziaStateSummary `json:"amneziawg,omitempty"`
}

type amneziaStateSummary struct {
	JunkCount         int      `json:"junk_count"`
	JunkMin           int      `json:"junk_min"`
	JunkMax           int      `json:"junk_max"`
	InitHeader        string   `json:"init_header"`
	ResponseHeader    string   `json:"response_header"`
	CookieHeader      string   `json:"cookie_header"`
	TransportHeader   string   `json:"transport_header"`
	InitPadding       int      `json:"init_padding"`
	ResponsePadding   int      `json:"response_padding"`
	CookiePadding     int      `json:"cookie_padding"`
	TransportPadding  int      `json:"transport_padding"`
	InitiationPackets []string `json:"initiation_packets"`
}

type tunStateSummary struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	LocalIP string `json:"local_ip"`
	PeerIP  string `json:"peer_ip"`
	MTU     int    `json:"mtu"`
}

type bindStateSummary struct {
	Type          string   `json:"type"`
	RequestedPort uint16   `json:"requested_port"`
	ListenPort    uint16   `json:"listen_port"`
	ListenAddrs   []string `json:"listen_addrs,omitempty"`
}

type deviceUpdateRequest struct {
	PrivateKey *string `json:"private_key"`
	ListenPort *uint16 `json:"listen_port"`
	Fwmark     *uint32 `json:"fwmark"`
}

type amneziaApplyRequest struct {
	JunkCount         int      `json:"junk_count"`
	JunkMin           int      `json:"junk_min"`
	JunkMax           int      `json:"junk_max"`
	InitHeader        string   `json:"init_header"`
	ResponseHeader    string   `json:"response_header"`
	CookieHeader      string   `json:"cookie_header"`
	TransportHeader   string   `json:"transport_header"`
	InitPadding       int      `json:"init_padding"`
	ResponsePadding   int      `json:"response_padding"`
	CookiePadding     int      `json:"cookie_padding"`
	TransportPadding  int      `json:"transport_padding"`
	InitiationPackets []string `json:"initiation_packets"`
}

type peerApplyRequest struct {
	PublicKey                   string   `json:"public_key"`
	PresharedKey                *string  `json:"preshared_key"`
	Endpoint                    *string  `json:"endpoint"`
	ProtocolVersion             *int     `json:"protocol_version"`
	PersistentKeepaliveInterval *uint16  `json:"persistent_keepalive_interval"`
	AllowedIPs                  []string `json:"allowed_ips"`
	ReplaceAllowedIPs           bool     `json:"replace_allowed_ips"`
}

type peerDeleteRequest struct {
	PublicKey string `json:"public_key"`
}

type attachTUNRequest struct {
	Name    string `json:"name"`
	LocalIP string `json:"local_ip"`
	PeerIP  string `json:"peer_ip"`
	MTU     int    `json:"mtu"`
}

type attachBindRequest struct {
	ListenPort *uint16 `json:"listen_port"`
}

type pairingPlan struct {
	Local  peerPlan
	Remote peerPlan
}

type peerPlan struct {
	Label        string
	PrivateKey   string
	PublicKey    string
	TunName      string
	LocalIP      netip.Addr
	PeerIP       netip.Addr
	AllowedIP    netip.Prefix
	ListenPort   uint16
	PingTargetIP netip.Addr
	AmneziaWG    device.AmneziaWGConfig
}

type indexPageData struct {
	SuggestedRole        string
	SuggestedAmneziaJSON template.JS
	DefaultAmneziaJSON   template.JS
}

func newAdminApp() (*adminApp, error) {
	plan, err := newPairingPlan()
	if err != nil {
		return nil, err
	}

	dev := device.NewDevice(nil, nil, device.NewLogger(device.LogLevelError, "example/web-admin: "))
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("bring device up: %w", err)
	}

	app := &adminApp{dev: dev, plan: plan}

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleIndex)
	mux.HandleFunc("/api/state", app.handleState)
	mux.HandleFunc("/api/device", app.handleDeviceUpdate)
	mux.HandleFunc("/api/device/amnezia", app.handleAmneziaUpdate)
	mux.HandleFunc("/api/peers/apply", app.handlePeerApply)
	mux.HandleFunc("/api/peers/delete", app.handlePeerDelete)
	mux.HandleFunc("/api/peers/delete_all", app.handlePeerDeleteAll)
	mux.HandleFunc("/api/tun/attach", app.handleAttachTUN)
	mux.HandleFunc("/api/tun/detach", app.handleDetachTUN)
	mux.HandleFunc("/api/vtun/attach", app.handleAttachVTun)
	mux.HandleFunc("/api/bind/attach", app.handleAttachBind)
	mux.HandleFunc("/api/bind/detach", app.handleDetachBind)
	mux.HandleFunc("/api/tunnel/echo/start", app.handleTunnelEchoStart)
	mux.HandleFunc("/api/tunnel/echo/stop", app.handleTunnelEchoStop)
	mux.HandleFunc("/api/tunnel/probe", app.handleTunnelProbe)

	app.server = &http.Server{
		Addr:              "127.0.0.1:0",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return app, nil
}

func (a *adminApp) Run() error {
	listener, err := net.Listen("tcp4", a.server.Addr)
	if err != nil {
		return fmt.Errorf("listen on admin panel address: %w", err)
	}

	fmt.Println()
	fmt.Println("wgo web admin")
	fmt.Println()
	fmt.Printf("panel:   http://%s\n", listener.Addr())
	fmt.Println("device:  started without TUN or bind")
	fmt.Println("notice:  native TUN attach requires root/administrator privileges")
	fmt.Println()
	a.printPairingGuide()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- a.server.Serve(listener)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case err := <-serverErr:
		return err
	case sig := <-sigCh:
		log.Printf("received %s, shutting down", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return a.server.Shutdown(ctx)
	}
}

func (a *adminApp) Close() error {
	a.mu.Lock()
	bind := a.bind
	tun := a.tun
	a.bind = nil
	a.tun = nil
	a.mu.Unlock()

	if a.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = a.server.Shutdown(ctx)
		cancel()
	}

	if bind != nil && bind.network != nil {
		_ = bind.network.Down()
	}
	_ = a.traffic.stopEcho()

	a.dev.Close()

	var err error
	if tun != nil && tun.cleanup != nil {
		err = tun.cleanup()
	}
	return err
}

func (a *adminApp) handleIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	page, err := newIndexPageData(a.plan.Local)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := indexTemplate.Execute(w, page); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *adminApp) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, a.snapshot())
}

func (a *adminApp) logPanelAction(action, format string, args ...any) {
	msg := format
	if msg == "" {
		msg = "ok"
	} else {
		msg = fmt.Sprintf(format, args...)
	}
	log.Printf("[web_admin panel] %s %s", action, msg)
}

func shortHex(src string) string {
	src = strings.TrimSpace(src)
	if len(src) <= 12 {
		return src
	}
	return src[:8] + "..." + src[len(src)-4:]
}

func displayPort(port *uint16) any {
	if port == nil {
		return "unchanged"
	}
	return *port
}

func displayUint32(v *uint32) any {
	if v == nil {
		return "unchanged"
	}
	return *v
}

func displayInt(v *int) any {
	if v == nil {
		return "unchanged"
	}
	return *v
}

func displayString(v *string) any {
	if v == nil {
		return "unchanged"
	}
	if strings.TrimSpace(*v) == "" {
		return `""`
	}
	return strings.TrimSpace(*v)
}

func displayStringSlice(v []string) any {
	if len(v) == 0 {
		return "[]"
	}
	return strings.Join(v, ",")
}

func summarizeAmneziaConfig(cfg device.AmneziaWGConfig) amneziaStateSummary {
	packets := make([]string, len(cfg.InitiationPackets))
	copy(packets, cfg.InitiationPackets[:])
	return amneziaStateSummary{
		JunkCount:         cfg.JunkCount,
		JunkMin:           cfg.JunkMin,
		JunkMax:           cfg.JunkMax,
		InitHeader:        cfg.InitHeader.Spec(),
		ResponseHeader:    cfg.ResponseHeader.Spec(),
		CookieHeader:      cfg.CookieHeader.Spec(),
		TransportHeader:   cfg.TransportHeader.Spec(),
		InitPadding:       cfg.InitPadding,
		ResponsePadding:   cfg.ResponsePadding,
		CookiePadding:     cfg.CookiePadding,
		TransportPadding:  cfg.TransportPadding,
		InitiationPackets: packets,
	}
}

func amneziaApplyRequestFromConfig(cfg device.AmneziaWGConfig) amneziaApplyRequest {
	packets := make([]string, len(cfg.InitiationPackets))
	copy(packets, cfg.InitiationPackets[:])
	return amneziaApplyRequest{
		JunkCount:         cfg.JunkCount,
		JunkMin:           cfg.JunkMin,
		JunkMax:           cfg.JunkMax,
		InitHeader:        cfg.InitHeader.Spec(),
		ResponseHeader:    cfg.ResponseHeader.Spec(),
		CookieHeader:      cfg.CookieHeader.Spec(),
		TransportHeader:   cfg.TransportHeader.Spec(),
		InitPadding:       cfg.InitPadding,
		ResponsePadding:   cfg.ResponsePadding,
		CookiePadding:     cfg.CookiePadding,
		TransportPadding:  cfg.TransportPadding,
		InitiationPackets: packets,
	}
}

func (req amneziaApplyRequest) toConfig() (device.AmneziaWGConfig, error) {
	cfg := device.DefaultAmneziaWGConfig()
	cfg.JunkCount = req.JunkCount
	cfg.JunkMin = req.JunkMin
	cfg.JunkMax = req.JunkMax
	cfg.InitPadding = req.InitPadding
	cfg.ResponsePadding = req.ResponsePadding
	cfg.CookiePadding = req.CookiePadding
	cfg.TransportPadding = req.TransportPadding

	var err error
	if cfg.InitHeader, err = parseAmneziaHeader(req.InitHeader, device.DefaultAmneziaWGHeaderRange(device.MessageInitiationType)); err != nil {
		return device.AmneziaWGConfig{}, fmt.Errorf("parse init_header: %w", err)
	}
	if cfg.ResponseHeader, err = parseAmneziaHeader(req.ResponseHeader, device.DefaultAmneziaWGHeaderRange(device.MessageResponseType)); err != nil {
		return device.AmneziaWGConfig{}, fmt.Errorf("parse response_header: %w", err)
	}
	if cfg.CookieHeader, err = parseAmneziaHeader(req.CookieHeader, device.DefaultAmneziaWGHeaderRange(device.MessageCookieReplyType)); err != nil {
		return device.AmneziaWGConfig{}, fmt.Errorf("parse cookie_header: %w", err)
	}
	if cfg.TransportHeader, err = parseAmneziaHeader(req.TransportHeader, device.DefaultAmneziaWGHeaderRange(device.MessageTransportType)); err != nil {
		return device.AmneziaWGConfig{}, fmt.Errorf("parse transport_header: %w", err)
	}

	for i := range cfg.InitiationPackets {
		if i < len(req.InitiationPackets) {
			cfg.InitiationPackets[i] = strings.TrimSpace(req.InitiationPackets[i])
		}
	}
	return cfg, nil
}

func parseAmneziaHeader(spec string, fallback device.AmneziaWGHeaderRange) (device.AmneziaWGHeaderRange, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return fallback, nil
	}
	return device.ParseAmneziaWGHeaderRange(spec)
}

func newIndexPageData(local peerPlan) (indexPageData, error) {
	suggestedJSON, err := json.Marshal(amneziaApplyRequestFromConfig(local.AmneziaWG))
	if err != nil {
		return indexPageData{}, fmt.Errorf("marshal suggested amnezia profile: %w", err)
	}
	defaultJSON, err := json.Marshal(amneziaApplyRequestFromConfig(device.DefaultAmneziaWGConfig()))
	if err != nil {
		return indexPageData{}, fmt.Errorf("marshal default amnezia profile: %w", err)
	}
	return indexPageData{
		SuggestedRole:        local.Label,
		SuggestedAmneziaJSON: template.JS(suggestedJSON),
		DefaultAmneziaJSON:   template.JS(defaultJSON),
	}, nil
}

func (a *adminApp) handleDeviceUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req deviceUpdateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if req.PrivateKey != nil {
		key, err := parsePrivateKey(*req.PrivateKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := a.dev.SetPrivateKey(key); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	if req.ListenPort != nil {
		if err := a.dev.SetListenPort(*req.ListenPort); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	if req.Fwmark != nil {
		if err := a.dev.SetFwmark(*req.Fwmark); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	a.logPanelAction(
		"device.update",
		"private_key=%t listen_port=%v fwmark=%v",
		req.PrivateKey != nil,
		displayPort(req.ListenPort),
		displayUint32(req.Fwmark),
	)

	writeJSON(w, http.StatusOK, a.snapshot())
}

func (a *adminApp) handleAmneziaUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req amneziaApplyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	cfg, err := req.toConfig()
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := a.dev.SetAmneziaWGConfig(cfg); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	a.logPanelAction(
		"device.amnezia",
		"junk=%d/%d/%d headers=%s,%s,%s,%s paddings=%d/%d/%d/%d",
		cfg.JunkCount,
		cfg.JunkMin,
		cfg.JunkMax,
		cfg.InitHeader.Spec(),
		cfg.ResponseHeader.Spec(),
		cfg.CookieHeader.Spec(),
		cfg.TransportHeader.Spec(),
		cfg.InitPadding,
		cfg.ResponsePadding,
		cfg.CookiePadding,
		cfg.TransportPadding,
	)
	writeJSON(w, http.StatusOK, a.snapshot())
}

func (a *adminApp) handlePeerApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req peerApplyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	publicKey, err := parsePublicKey(req.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if a.dev.LookupPeer(publicKey) == nil {
		if _, err := a.dev.NewPeer(publicKey); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	if req.PresharedKey != nil {
		psk, err := parsePresharedKey(*req.PresharedKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := a.dev.SetPeerPresharedKey(publicKey, psk); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	if req.ProtocolVersion != nil {
		if err := a.dev.SetPeerProtocolVersion(publicKey, *req.ProtocolVersion); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	if req.Endpoint != nil && strings.TrimSpace(*req.Endpoint) != "" {
		if err := a.dev.SetPeerEndpoint(publicKey, strings.TrimSpace(*req.Endpoint)); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	if req.PersistentKeepaliveInterval != nil {
		if err := a.dev.SetPeerPersistentKeepaliveInterval(publicKey, *req.PersistentKeepaliveInterval); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	if req.ReplaceAllowedIPs {
		prefixes, err := parsePrefixes(req.AllowedIPs)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := a.dev.ReplacePeerAllowedIPs(publicKey, prefixes); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	if err := a.dev.ActivatePeer(publicKey); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	a.logPanelAction(
		"peer.apply",
		"public_key=%s preshared_key=%t endpoint=%v protocol=%v keepalive=%v replace_allowed_ips=%t allowed_ips=%v",
		shortHex(req.PublicKey),
		req.PresharedKey != nil,
		displayString(req.Endpoint),
		displayInt(req.ProtocolVersion),
		displayPort(req.PersistentKeepaliveInterval),
		req.ReplaceAllowedIPs,
		displayStringSlice(req.AllowedIPs),
	)

	writeJSON(w, http.StatusOK, a.snapshot())
}

func (a *adminApp) handlePeerDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req peerDeleteRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	publicKey, err := parsePublicKey(req.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	a.dev.RemovePeer(publicKey)
	a.logPanelAction("peer.delete", "public_key=%s", shortHex(req.PublicKey))
	writeJSON(w, http.StatusOK, a.snapshot())
}

func (a *adminApp) handlePeerDeleteAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.dev.RemoveAllPeers()
	a.logPanelAction("peer.delete_all", "")
	writeJSON(w, http.StatusOK, a.snapshot())
}

func (a *adminApp) handleAttachTUN(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req attachTUNRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if err := a.attachTUN(req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	a.logPanelAction(
		"tun.attach_native",
		"name=%s local_ip=%s peer_ip=%s mtu=%d",
		strings.TrimSpace(req.Name),
		strings.TrimSpace(req.LocalIP),
		strings.TrimSpace(req.PeerIP),
		req.MTU,
	)
	writeJSON(w, http.StatusOK, a.snapshot())
}

func (a *adminApp) handleAttachVTun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req attachTUNRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if err := a.attachVTun(req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	a.logPanelAction(
		"tun.attach_vtun",
		"name=%s local_ip=%s peer_ip=%s",
		strings.TrimSpace(req.Name),
		strings.TrimSpace(req.LocalIP),
		strings.TrimSpace(req.PeerIP),
	)
	writeJSON(w, http.StatusOK, a.snapshot())
}

func (a *adminApp) handleDetachTUN(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := a.detachTUN(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	a.logPanelAction("tun.detach", "")
	writeJSON(w, http.StatusOK, a.snapshot())
}

func (a *adminApp) handleAttachBind(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req attachBindRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := a.attachBind(req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	a.logPanelAction("bind.attach", "listen_port=%v", displayPort(req.ListenPort))
	writeJSON(w, http.StatusOK, a.snapshot())
}

func (a *adminApp) handleDetachBind(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := a.detachBind(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	a.logPanelAction("bind.detach", "")
	writeJSON(w, http.StatusOK, a.snapshot())
}

func (a *adminApp) handleTunnelEchoStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req tunnelEchoRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := a.startTunnelEcho(req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	a.logPanelAction("tunnel.echo_start", "port=%v", displayPort(req.Port))
	writeJSON(w, http.StatusOK, a.snapshot())
}

func (a *adminApp) handleTunnelEchoStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := a.stopTunnelEcho(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	a.logPanelAction("tunnel.echo_stop", "")
	writeJSON(w, http.StatusOK, a.snapshot())
}

func (a *adminApp) handleTunnelProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req tunnelProbeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result, err := a.probeTunnel(req)
	if err != nil {
		a.traffic.setLastProbeResult("error: " + err.Error())
		writeError(w, http.StatusBadRequest, err)
		return
	}
	a.logPanelAction(
		"tunnel.probe",
		"remote_ip=%v port=%v message=%v result=%s",
		displayString(req.RemoteIP),
		displayPort(req.Port),
		displayString(req.Message),
		result,
	)
	writeJSON(w, http.StatusOK, map[string]any{
		"result": result,
		"state":  a.snapshot(),
	})
}

func (a *adminApp) attachTUN(req attachTUNRequest) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.tun != nil {
		return fmt.Errorf("a native TUN is already attached")
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		return fmt.Errorf("name is required")
	}

	localIP, err := netip.ParseAddr(strings.TrimSpace(req.LocalIP))
	if err != nil {
		return fmt.Errorf("parse local_ip: %w", err)
	}
	peerIP, err := netip.ParseAddr(strings.TrimSpace(req.PeerIP))
	if err != nil {
		return fmt.Errorf("parse peer_ip: %w", err)
	}

	mtu := req.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	if mtu < 576 {
		return fmt.Errorf("mtu must be at least 576")
	}

	tunDev, ifName, cleanup, err := createConfiguredTUN(name, localIP, peerIP, mtu)
	if err != nil {
		return err
	}
	tunDev = newLoggingTUN(ifName, tunDev)
	if err := a.dev.AttachTUN(tunDev); err != nil {
		_ = tunDev.Close()
		if cleanup != nil {
			_ = cleanup()
		}
		return err
	}

	a.tun = &tunAttachment{
		kind:    "native",
		name:    ifName,
		localIP: localIP,
		peerIP:  peerIP,
		mtu:     mtu,
		cleanup: cleanup,
	}
	return nil
}

func (a *adminApp) attachVTun(req attachTUNRequest) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.tun != nil {
		return fmt.Errorf("a TUN is already attached")
	}

	localIP, err := netip.ParseAddr(strings.TrimSpace(req.LocalIP))
	if err != nil {
		return fmt.Errorf("parse local_ip: %w", err)
	}
	peerIP, err := netip.ParseAddr(strings.TrimSpace(req.PeerIP))
	if err != nil {
		return fmt.Errorf("parse peer_ip: %w", err)
	}

	tunDev, err := (&vtun.Opts{
		Name:           strings.TrimSpace(req.Name),
		LocalAddrs:     []netip.Addr{localIP},
		NoLoopbackAddr: true,
	}).Build()
	if err != nil {
		return fmt.Errorf("build vtun: %w", err)
	}
	select {
	case <-tunDev.Events():
	case <-time.After(5 * time.Second):
		_ = tunDev.Close()
		return fmt.Errorf("timed out waiting for vtun event")
	}

	mtu, err := tunDev.MTU()
	if err != nil {
		_ = tunDev.Close()
		return fmt.Errorf("read vtun mtu: %w", err)
	}

	var tun gtun.Tun = tunDev
	tun = newLoggingTUN(req.Name, tun)
	if err := a.dev.AttachTUN(tun); err != nil {
		_ = tunDev.Close()
		return err
	}

	a.tun = &tunAttachment{
		kind:    "vtun",
		name:    req.Name,
		localIP: localIP,
		peerIP:  peerIP,
		mtu:     mtu,
		stack:   tunDev,
	}
	return nil
}

func (a *adminApp) detachTUN() error {
	a.mu.Lock()
	if a.tun == nil {
		a.mu.Unlock()
		return nil
	}
	tun := a.tun
	a.tun = nil
	a.mu.Unlock()

	if err := a.dev.DetachTUN(); err != nil {
		a.mu.Lock()
		a.tun = tun
		a.mu.Unlock()
		return err
	}
	_ = a.traffic.stopEcho()
	if tun.cleanup != nil {
		return tun.cleanup()
	}
	return nil
}

func (a *adminApp) attachBind(req attachBindRequest) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.bind != nil {
		return fmt.Errorf("a bind is already attached")
	}

	var port uint16
	if req.ListenPort != nil {
		port = *req.ListenPort
	}
	if err := a.dev.SetListenPort(port); err != nil {
		return err
	}

	network := newRecordingNetwork()
	bind := newLoggingBind("native-default", conn.NewDefaultBind(network))
	if err := a.dev.AttachBind(bind); err != nil {
		_ = network.Down()
		return err
	}
	log.Printf("web_admin bind listening on %s", strings.Join(network.ListenAddrs(), ", "))

	a.bind = &bindAttachment{
		network:       network,
		requestedPort: port,
	}
	return nil
}

func (a *adminApp) detachBind() error {
	a.mu.Lock()
	if a.bind == nil {
		a.mu.Unlock()
		return nil
	}
	bind := a.bind
	a.bind = nil
	a.mu.Unlock()

	if err := a.dev.DetachBind(); err != nil {
		a.mu.Lock()
		a.bind = bind
		a.mu.Unlock()
		return err
	}
	if bind.network != nil {
		return bind.network.Down()
	}
	return nil
}

func (a *adminApp) snapshot() appState {
	cfg := a.dev.Config()

	state := appState{
		Device: deviceStateSummary{
			PrivateKey: encodePrivateKey(cfg.PrivateKey),
			ListenPort: cfg.ListenPort,
			Fwmark:     cfg.Fwmark,
			AmneziaWG:  summarizeAmneziaConfig(cfg.AmneziaWG),
			Peers:      make([]peerStateSummary, 0, len(cfg.Peers)),
		},
	}

	for _, peer := range cfg.Peers {
		allowedIPs := make([]string, 0, len(peer.AllowedIPs))
		for _, prefix := range peer.AllowedIPs {
			allowedIPs = append(allowedIPs, prefix.String())
		}
		summary := peerStateSummary{
			PublicKey:                   hex.EncodeToString(peer.PublicKey[:]),
			PresharedKey:                hex.EncodeToString(peer.PresharedKey[:]),
			ProtocolVersion:             peer.ProtocolVersion,
			Endpoint:                    peer.Endpoint,
			LastHandshakeTime:           peer.LastHandshakeTime.UTC().Format(time.RFC3339Nano),
			TxBytes:                     peer.TxBytes,
			RxBytes:                     peer.RxBytes,
			PersistentKeepaliveInterval: peer.PersistentKeepaliveInterval,
			AllowedIPs:                  allowedIPs,
		}
		if peer.AmneziaWG != nil {
			amnezia := summarizeAmneziaConfig(*peer.AmneziaWG)
			summary.AmneziaWG = &amnezia
		}
		state.Device.Peers = append(state.Device.Peers, summary)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.tun != nil {
		state.TUN = &tunStateSummary{
			Kind:    a.tun.kind,
			Name:    a.tun.name,
			LocalIP: a.tun.localIP.String(),
			PeerIP:  a.tun.peerIP.String(),
			MTU:     a.tun.mtu,
		}
	}
	if a.bind != nil {
		state.Bind = &bindStateSummary{
			Type:          "native-default",
			RequestedPort: a.bind.requestedPort,
			ListenPort:    a.dev.ListenPort(),
			ListenAddrs:   a.bind.network.ListenAddrs(),
		}
	}
	state.Traffic = newTunnelTrafficSummary(&a.traffic)

	return state
}

func (a *adminApp) tunnelNetwork() (*vtun.VTun, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.tun == nil {
		return nil, fmt.Errorf("attach TUN first")
	}
	if a.tun.stack == nil {
		return nil, fmt.Errorf("explicit tunnel traffic requires a userspace VTun attachment, not a native OS TUN")
	}
	return a.tun.stack, nil
}

func (a *adminApp) printPairingGuide() {
	local := a.plan.Local
	remote := a.plan.Remote

	fmt.Println("Pairing Guide")
	fmt.Printf("Use this instance as %s.\n", local.Label)
	fmt.Printf("Use another instance as %s.\n", remote.Label)
	fmt.Println()

	printPeerPlan(local, remote)
	fmt.Println()
	printPeerPlan(remote, local)
	fmt.Println()

	fmt.Println("Endpoints")
	fmt.Println("  Same machine:")
	fmt.Printf("    %s peer endpoint: 127.0.0.1:%d\n", local.Label, remote.ListenPort)
	fmt.Printf("    %s peer endpoint: 127.0.0.1:%d\n", remote.Label, local.ListenPort)
	fmt.Println("  Different machines:")
	fmt.Printf("    %s peer endpoint: <remote-host>:%d\n", local.Label, remote.ListenPort)
	fmt.Printf("    %s peer endpoint: <remote-host>:%d\n", remote.Label, local.ListenPort)
	fmt.Println()

	fmt.Println("Steps")
	fmt.Println("  1. Open this panel and the other instance panel.")
	fmt.Printf("  2. In this panel, configure %s.\n", local.Label)
	fmt.Printf("  3. In the other panel, configure %s.\n", remote.Label)
	fmt.Println("  4. On each side: attach TUN, attach bind, create peer.")
	fmt.Printf("  5. On one side, start tunnel echo on %s:%d.\n", local.LocalIP, defaultTunnelEchoPort)
	fmt.Printf("  6. On the other side, probe %s:%d through the tunnel.\n", local.LocalIP, defaultTunnelEchoPort)
	fmt.Println("  7. If one side is behind NAT, set persistent keepalive there and use a reachable endpoint/port mapping.")
	fmt.Println()
}

func printPeerPlan(self, peer peerPlan) {
	fmt.Printf("%s\n", strings.ToUpper(self.Label))
	fmt.Printf("  private key: %s\n", self.PrivateKey)
	fmt.Printf("  peer pubkey: %s\n", peer.PublicKey)
	fmt.Printf("  tun name:    %s\n", self.TunName)
	fmt.Printf("  tun local:   %s\n", self.LocalIP)
	fmt.Printf("  tun peer:    %s\n", self.PeerIP)
	fmt.Printf("  allowed ip:  %s\n", self.AllowedIP)
	fmt.Printf("  listen port: %d\n", self.ListenPort)
	fmt.Println("  protocol:    1")
	fmt.Println("  amneziawg:")
	for _, line := range amneziaConfigLines(self.AmneziaWG) {
		fmt.Printf("    %s\n", line)
	}
}

func createConfiguredTUN(name string, localIP, peerIP netip.Addr, mtu int) (gtun.Tun, string, func() error, error) {
	tunDev, err := tuntap.CreateTUN(name, mtu)
	if err != nil {
		return nil, "", nil, fmt.Errorf("create native tun: %w", err)
	}

	ifName, err := tunDev.Name()
	if err != nil {
		_ = tunDev.Close()
		return nil, "", nil, fmt.Errorf("load tun name: %w", err)
	}

	cleanup, err := configurePlatformTUN(ifName, localIP, peerIP, mtu)
	if err != nil {
		_ = tunDev.Close()
		return nil, "", nil, err
	}

	return tunDev, ifName, cleanup, nil
}

func parsePrivateKey(src string) (device.NoisePrivateKey, error) {
	var key device.NoisePrivateKey
	if err := key.FromHex(strings.TrimSpace(src)); err != nil {
		return device.NoisePrivateKey{}, fmt.Errorf("parse private_key: %w", err)
	}
	return key, nil
}

func parsePublicKey(src string) (device.NoisePublicKey, error) {
	var key device.NoisePublicKey
	if err := key.FromHex(strings.TrimSpace(src)); err != nil {
		return device.NoisePublicKey{}, fmt.Errorf("parse public_key: %w", err)
	}
	return key, nil
}

func parsePresharedKey(src string) (device.NoisePresharedKey, error) {
	var key device.NoisePresharedKey
	if err := key.FromHex(strings.TrimSpace(src)); err != nil {
		return device.NoisePresharedKey{}, fmt.Errorf("parse preshared_key: %w", err)
	}
	return key, nil
}

func parsePrefixes(src []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(src))
	for _, item := range src {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, fmt.Errorf("parse allowed_ip %q: %w", item, err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func encodePrivateKey(key device.NoisePrivateKey) string {
	if key.IsZero() {
		return ""
	}
	return hex.EncodeToString(key[:])
}

func newPairingPlan() (pairingPlan, error) {
	localPrivate, localPublic, err := generateKeyPair()
	if err != nil {
		return pairingPlan{}, fmt.Errorf("generate local keypair: %w", err)
	}
	remotePrivate, remotePublic, err := generateKeyPair()
	if err != nil {
		return pairingPlan{}, fmt.Errorf("generate remote keypair: %w", err)
	}

	portBase, err := randomPortBase()
	if err != nil {
		return pairingPlan{}, fmt.Errorf("select suggested listen ports: %w", err)
	}

	localIP := netip.MustParseAddr("10.88.0.1")
	remoteIP := netip.MustParseAddr("10.88.0.2")

	return pairingPlan{
		Local: peerPlan{
			Label:        "node-a",
			PrivateKey:   hex.EncodeToString(localPrivate[:]),
			PublicKey:    hex.EncodeToString(localPublic[:]),
			TunName:      "wgoadm-a",
			LocalIP:      localIP,
			PeerIP:       remoteIP,
			AllowedIP:    netip.PrefixFrom(remoteIP, remoteIP.BitLen()),
			ListenPort:   portBase,
			PingTargetIP: remoteIP,
			AmneziaWG:    suggestedAmneziaConfigA(),
		},
		Remote: peerPlan{
			Label:        "node-b",
			PrivateKey:   hex.EncodeToString(remotePrivate[:]),
			PublicKey:    hex.EncodeToString(remotePublic[:]),
			TunName:      "wgoadm-b",
			LocalIP:      remoteIP,
			PeerIP:       localIP,
			AllowedIP:    netip.PrefixFrom(localIP, localIP.BitLen()),
			ListenPort:   portBase + 1,
			PingTargetIP: localIP,
			AmneziaWG:    suggestedAmneziaConfigB(),
		},
	}, nil
}

func suggestedAmneziaConfigA() device.AmneziaWGConfig {
	cfg := device.DefaultAmneziaWGConfig()
	cfg.JunkCount = 2
	cfg.JunkMin = 11
	cfg.JunkMax = 23
	cfg.InitPadding = 13
	cfg.ResponsePadding = 17
	cfg.CookiePadding = 19
	cfg.TransportPadding = 29
	cfg.InitHeader = mustAmneziaHeader("1111-1113")
	cfg.ResponseHeader = mustAmneziaHeader("2222-2225")
	cfg.CookieHeader = mustAmneziaHeader("3333")
	cfg.TransportHeader = mustAmneziaHeader("4444-4449")
	cfg.InitiationPackets[0] = "<b 0xaa55><rc 3><rd 2><t>"
	cfg.InitiationPackets[1] = "<r 5>"
	cfg.InitiationPackets[2] = "<rd 4>"
	cfg.InitiationPackets[3] = "<rc 6>"
	cfg.InitiationPackets[4] = "<b 0x01020304>"
	return cfg
}

func suggestedAmneziaConfigB() device.AmneziaWGConfig {
	cfg := device.DefaultAmneziaWGConfig()
	cfg.JunkCount = 3
	cfg.JunkMin = 7
	cfg.JunkMax = 14
	cfg.InitPadding = 5
	cfg.ResponsePadding = 9
	cfg.CookiePadding = 11
	cfg.TransportPadding = 15
	cfg.InitHeader = mustAmneziaHeader("5111-5114")
	cfg.ResponseHeader = mustAmneziaHeader("5222-5224")
	cfg.CookieHeader = mustAmneziaHeader("5333")
	cfg.TransportHeader = mustAmneziaHeader("5444-5446")
	cfg.InitiationPackets[0] = "<b 0xdead><r 4>"
	cfg.InitiationPackets[1] = "<rc 2><t>"
	cfg.InitiationPackets[3] = "<rd 3>"
	cfg.InitiationPackets[4] = "<b 0x99>"
	return cfg
}

func mustAmneziaHeader(spec string) device.AmneziaWGHeaderRange {
	header, err := device.ParseAmneziaWGHeaderRange(spec)
	if err != nil {
		panic(err)
	}
	return header
}

func amneziaConfigLines(cfg device.AmneziaWGConfig) []string {
	lines := []string{
		fmt.Sprintf("jc=%d", cfg.JunkCount),
		fmt.Sprintf("jmin=%d", cfg.JunkMin),
		fmt.Sprintf("jmax=%d", cfg.JunkMax),
		fmt.Sprintf("s1=%d", cfg.InitPadding),
		fmt.Sprintf("s2=%d", cfg.ResponsePadding),
		fmt.Sprintf("s3=%d", cfg.CookiePadding),
		fmt.Sprintf("s4=%d", cfg.TransportPadding),
		fmt.Sprintf("h1=%s", cfg.InitHeader.Spec()),
		fmt.Sprintf("h2=%s", cfg.ResponseHeader.Spec()),
		fmt.Sprintf("h3=%s", cfg.CookieHeader.Spec()),
		fmt.Sprintf("h4=%s", cfg.TransportHeader.Spec()),
	}
	for i, spec := range cfg.InitiationPackets {
		if spec == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("i%d=%s", i+1, spec))
	}
	return lines
}

func generateKeyPair() (device.NoisePrivateKey, device.NoisePublicKey, error) {
	var privateKey device.NoisePrivateKey
	if _, err := rand.Read(privateKey[:]); err != nil {
		return device.NoisePrivateKey{}, device.NoisePublicKey{}, err
	}
	privateKey[0] &= 248
	privateKey[31] = (privateKey[31] & 127) | 64

	publicBytes, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return device.NoisePrivateKey{}, device.NoisePublicKey{}, err
	}

	var publicKey device.NoisePublicKey
	copy(publicKey[:], publicBytes)
	return privateKey, publicKey, nil
}

func randomPortBase() (uint16, error) {
	var raw [2]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, err
	}

	base := 20000 + int(raw[0])<<8 + int(raw[1])
	base = 20000 + (base % 20000)
	if base == 65535 {
		base--
	}
	return uint16(base), nil
}

func decodeJSON(r *http.Request, dst any) error {
	defer func() {
		_ = r.Body.Close()
	}()
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wgo web admin</title>
<style>
:root {
  color-scheme: light;
  --bg: #f4efe6;
  --panel: rgba(255,255,255,0.88);
  --ink: #16211f;
  --accent: #0d6b57;
  --accent-2: #c76b39;
  --line: rgba(22,33,31,0.12);
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: "Iosevka Aile", "IBM Plex Sans", sans-serif;
  background:
    radial-gradient(circle at top left, rgba(199,107,57,0.18), transparent 30%),
    radial-gradient(circle at top right, rgba(13,107,87,0.18), transparent 34%),
    linear-gradient(180deg, #f8f5ef, var(--bg));
  color: var(--ink);
}
main {
  width: min(1280px, calc(100vw - 32px));
  margin: 24px auto 48px;
}
h1, h2 { font-family: "IBM Plex Mono", monospace; }
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 16px;
}
.panel {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 18px;
  padding: 18px;
  backdrop-filter: blur(10px);
  box-shadow: 0 18px 40px rgba(22,33,31,0.08);
}
label, button, input, textarea {
  display: block;
  width: 100%;
}
.field-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
  gap: 12px;
}
label {
  font-size: 13px;
  margin-top: 12px;
}
input, textarea {
  margin-top: 6px;
  padding: 10px 12px;
  border-radius: 10px;
  border: 1px solid var(--line);
  background: rgba(255,255,255,0.9);
  font: inherit;
}
textarea { min-height: 110px; resize: vertical; }
button {
  margin-top: 14px;
  border: 0;
  border-radius: 999px;
  padding: 11px 14px;
  background: var(--accent);
  color: white;
  font: inherit;
  cursor: pointer;
}
button.alt { background: var(--accent-2); }
button.ghost {
  background: transparent;
  color: var(--ink);
  border: 1px solid var(--line);
}
pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: "IBM Plex Mono", monospace;
  font-size: 12px;
}
#message {
  min-height: 24px;
  margin: 10px 0 20px;
  font-family: "IBM Plex Mono", monospace;
}
</style>
</head>
<body>
<main>
  <h1>wgo localhost admin</h1>
  <p>This panel uses typed <code>Device</code> methods directly. Native TUN actions require root or administrator privileges.</p>
  <div id="message"></div>
  <div class="grid">
    <section class="panel">
      <h2>Device</h2>
      <label>Private key
        <input id="private_key" placeholder="64 hex chars">
      </label>
      <label>Listen port
        <input id="listen_port" type="number" min="0" max="65535" placeholder="0 for random">
      </label>
      <label>Fwmark
        <input id="fwmark" type="number" min="0" placeholder="0">
      </label>
      <button onclick="saveDevice()">Apply device settings</button>
    </section>

    <section class="panel">
      <h2>AmneziaWG</h2>
      <p>Suggested {{.SuggestedRole}} profile is preloaded into this form.</p>
      <div class="field-grid">
        <label>Jc
          <input id="amnezia_junk_count" type="number" min="0" value="0">
        </label>
        <label>Jmin
          <input id="amnezia_junk_min" type="number" min="0" value="0">
        </label>
        <label>Jmax
          <input id="amnezia_junk_max" type="number" min="0" value="0">
        </label>
      </div>
      <div class="field-grid">
        <label>S1
          <input id="amnezia_init_padding" type="number" min="0" value="0">
        </label>
        <label>S2
          <input id="amnezia_response_padding" type="number" min="0" value="0">
        </label>
        <label>S3
          <input id="amnezia_cookie_padding" type="number" min="0" value="0">
        </label>
        <label>S4
          <input id="amnezia_transport_padding" type="number" min="0" value="0">
        </label>
      </div>
      <div class="field-grid">
        <label>H1
          <input id="amnezia_init_header" placeholder="1 or 1000-1004">
        </label>
        <label>H2
          <input id="amnezia_response_header" placeholder="2 or 2000-2004">
        </label>
        <label>H3
          <input id="amnezia_cookie_header" placeholder="3 or 3000-3004">
        </label>
        <label>H4
          <input id="amnezia_transport_header" placeholder="4 or 4000-4004">
        </label>
      </div>
      <label>I1
        <input id="amnezia_i1" placeholder="<b 0xaa55><rc 3><rd 2><t>">
      </label>
      <label>I2
        <input id="amnezia_i2" placeholder="<r 5>">
      </label>
      <label>I3
        <input id="amnezia_i3" placeholder="<rd 4>">
      </label>
      <label>I4
        <input id="amnezia_i4" placeholder="<rc 6>">
      </label>
      <label>I5
        <input id="amnezia_i5" placeholder="<b 0x01020304>">
      </label>
      <button onclick="applyAmnezia()">Apply AmneziaWG settings</button>
      <button class="ghost" onclick="loadSuggestedAmnezia()">Reload suggested profile</button>
      <button class="alt" onclick="resetAmnezia()">Reset to plain WireGuard defaults</button>
    </section>

    <section class="panel">
      <h2>Peer</h2>
      <label>Public key
        <input id="peer_public_key" placeholder="64 hex chars">
      </label>
      <label>Preshared key
        <input id="peer_preshared_key" placeholder="optional 64 hex chars">
      </label>
      <label>Endpoint
        <input id="peer_endpoint" placeholder="127.0.0.1:51820">
      </label>
      <label>Protocol version
        <input id="peer_protocol_version" type="number" min="1" value="1">
      </label>
      <label>Persistent keepalive interval
        <input id="peer_keepalive" type="number" min="0" placeholder="seconds">
      </label>
      <label>Allowed IPs
        <textarea id="peer_allowed_ips" placeholder="10.0.0.2/32&#10;fd00::2/128"></textarea>
      </label>
      <button onclick="applyPeer()">Create or update peer</button>
      <button class="alt" onclick="deletePeer()">Delete peer</button>
      <button class="ghost" onclick="deleteAllPeers()">Delete all peers</button>
    </section>

    <section class="panel">
      <h2>TUN</h2>
      <label>Name
        <input id="tun_name" value="wgoadm0">
      </label>
      <label>Local IP
        <input id="tun_local_ip" value="10.77.0.1">
      </label>
      <label>Peer IP
        <input id="tun_peer_ip" value="10.77.0.2">
      </label>
      <label>MTU
        <input id="tun_mtu" type="number" min="576" value="1420">
      </label>
      <button onclick="attachTun()">Create and attach native TUN</button>
      <button class="ghost" onclick="attachVTun()">Attach userspace VTun</button>
      <button class="alt" onclick="detachTun()">Detach and destroy TUN</button>
    </section>

    <section class="panel">
      <h2>Bind</h2>
      <label>Listen port
        <input id="bind_port" type="number" min="0" max="65535" placeholder="empty or 0 for random">
      </label>
      <button onclick="attachBind()">Attach native bind</button>
      <button class="alt" onclick="detachBind()">Detach bind</button>
    </section>

    <section class="panel">
      <h2>Forced Tunnel Traffic</h2>
      <p>This uses the attached <code>VTun</code> userspace stack so traffic must pass through WireGuard. It is not available with a native OS TUN.</p>
      <label>Echo port
        <input id="echo_port" type="number" min="1" max="65535" value="18080">
      </label>
      <button onclick="startTunnelEcho()">Start TCP echo on local VTun IP</button>
      <button class="alt" onclick="stopTunnelEcho()">Stop echo</button>
      <label>Probe peer IP
        <input id="probe_remote_ip" placeholder="empty uses attached peer IP">
      </label>
      <label>Probe port
        <input id="probe_port" type="number" min="1" max="65535" value="18080">
      </label>
      <label>Probe message
        <input id="probe_message" placeholder="optional custom payload">
      </label>
      <button class="ghost" onclick="probeTunnel()">Probe peer through tunnel</button>
    </section>

    <section class="panel" style="grid-column: 1 / -1;">
      <h2>State</h2>
      <pre id="state"></pre>
    </section>
  </div>
</main>
<script>
const stateEl = document.getElementById('state');
const messageEl = document.getElementById('message');
const suggestedAmnezia = {{.SuggestedAmneziaJSON}};
const defaultAmnezia = {{.DefaultAmneziaJSON}};

function lines(text) {
  return text.split(/\n|,/).map(v => v.trim()).filter(Boolean);
}

function numValue(id) {
  const raw = document.getElementById(id).value.trim();
  if (raw === '') return null;
  return Number(raw);
}

async function post(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body || {})
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'request failed');
  }
  return data;
}

async function refresh() {
  const res = await fetch('/api/state');
  const data = await res.json();
  stateEl.textContent = JSON.stringify(data, null, 2);
}

function showMessage(text, isError) {
  messageEl.textContent = text;
  messageEl.style.color = isError ? '#9f1d35' : '#0d6b57';
}

async function run(action) {
  try {
    await action();
    showMessage('ok', false);
    await refresh();
  } catch (err) {
    showMessage(err.message, true);
  }
}

function saveDevice() {
  run(() => post('/api/device', {
    private_key: document.getElementById('private_key').value.trim() || null,
    listen_port: numValue('listen_port'),
    fwmark: numValue('fwmark')
  }));
}

function setAmneziaForm(profile) {
  document.getElementById('amnezia_junk_count').value = profile.junk_count;
  document.getElementById('amnezia_junk_min').value = profile.junk_min;
  document.getElementById('amnezia_junk_max').value = profile.junk_max;
  document.getElementById('amnezia_init_padding').value = profile.init_padding;
  document.getElementById('amnezia_response_padding').value = profile.response_padding;
  document.getElementById('amnezia_cookie_padding').value = profile.cookie_padding;
  document.getElementById('amnezia_transport_padding').value = profile.transport_padding;
  document.getElementById('amnezia_init_header').value = profile.init_header;
  document.getElementById('amnezia_response_header').value = profile.response_header;
  document.getElementById('amnezia_cookie_header').value = profile.cookie_header;
  document.getElementById('amnezia_transport_header').value = profile.transport_header;
  const packets = profile.initiation_packets || [];
  for (let i = 0; i < 5; i++) {
    document.getElementById('amnezia_i' + (i + 1)).value = packets[i] || '';
  }
}

function readAmneziaForm() {
  return {
    junk_count: Number(document.getElementById('amnezia_junk_count').value || 0),
    junk_min: Number(document.getElementById('amnezia_junk_min').value || 0),
    junk_max: Number(document.getElementById('amnezia_junk_max').value || 0),
    init_padding: Number(document.getElementById('amnezia_init_padding').value || 0),
    response_padding: Number(document.getElementById('amnezia_response_padding').value || 0),
    cookie_padding: Number(document.getElementById('amnezia_cookie_padding').value || 0),
    transport_padding: Number(document.getElementById('amnezia_transport_padding').value || 0),
    init_header: document.getElementById('amnezia_init_header').value.trim(),
    response_header: document.getElementById('amnezia_response_header').value.trim(),
    cookie_header: document.getElementById('amnezia_cookie_header').value.trim(),
    transport_header: document.getElementById('amnezia_transport_header').value.trim(),
    initiation_packets: [1, 2, 3, 4, 5].map(i => document.getElementById('amnezia_i' + i).value.trim())
  };
}

function applyAmnezia() {
  run(() => post('/api/device/amnezia', readAmneziaForm()));
}

function loadSuggestedAmnezia() {
  setAmneziaForm(suggestedAmnezia);
  showMessage('suggested profile loaded into form', false);
}

function resetAmnezia() {
  setAmneziaForm(defaultAmnezia);
  showMessage('plain WireGuard defaults loaded into form', false);
}

function applyPeer() {
  run(() => post('/api/peers/apply', {
    public_key: document.getElementById('peer_public_key').value.trim(),
    preshared_key: document.getElementById('peer_preshared_key').value.trim() || null,
    endpoint: document.getElementById('peer_endpoint').value.trim() || null,
    protocol_version: numValue('peer_protocol_version'),
    persistent_keepalive_interval: numValue('peer_keepalive'),
    allowed_ips: lines(document.getElementById('peer_allowed_ips').value),
    replace_allowed_ips: true
  }));
}

function deletePeer() {
  run(() => post('/api/peers/delete', {
    public_key: document.getElementById('peer_public_key').value.trim()
  }));
}

function deleteAllPeers() {
  run(() => post('/api/peers/delete_all', {}));
}

function attachTun() {
  run(() => post('/api/tun/attach', {
    name: document.getElementById('tun_name').value.trim(),
    local_ip: document.getElementById('tun_local_ip').value.trim(),
    peer_ip: document.getElementById('tun_peer_ip').value.trim(),
    mtu: numValue('tun_mtu') || 1420
  }));
}

function attachVTun() {
  run(() => post('/api/vtun/attach', {
    name: document.getElementById('tun_name').value.trim(),
    local_ip: document.getElementById('tun_local_ip').value.trim(),
    peer_ip: document.getElementById('tun_peer_ip').value.trim(),
    mtu: numValue('tun_mtu') || 1420
  }));
}

function detachTun() {
  run(() => post('/api/tun/detach', {}));
}

function attachBind() {
  run(() => post('/api/bind/attach', {
    listen_port: numValue('bind_port')
  }));
}

function detachBind() {
  run(() => post('/api/bind/detach', {}));
}

function startTunnelEcho() {
  run(() => post('/api/tunnel/echo/start', {
    port: numValue('echo_port')
  }));
}

function stopTunnelEcho() {
  run(() => post('/api/tunnel/echo/stop', {}));
}

function probeTunnel() {
  (async () => {
    try {
      const data = await post('/api/tunnel/probe', {
        remote_ip: document.getElementById('probe_remote_ip').value.trim() || null,
        port: numValue('probe_port'),
        message: document.getElementById('probe_message').value.trim() || null
      });
      showMessage(data.result, false);
      await refresh();
    } catch (err) {
      showMessage(err.message, true);
      await refresh();
    }
  })();
}

setAmneziaForm(suggestedAmnezia);
refresh();
</script>
</body>
</html>`

var indexTemplate = template.Must(template.New("index").Parse(indexHTML))

func init() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
}
