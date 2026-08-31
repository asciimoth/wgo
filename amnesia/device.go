package amnezia

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"

	"github.com/asciimoth/wgo/device"
)

// Device returns the currently attached WireGuard control implementation.
// It returns nil if no implementation is attached. The caller must not infer
// ownership from this method; Client never closes an attached implementation.
func (c *Client) Device() device.DeviceAPI {
	c.deviceMu.RLock()
	defer c.deviceMu.RUnlock()
	return c.deviceAPI
}

// AttachDevice attaches dev if the client has no current usable device API.
//
// AttachDevice does not configure, start, or take ownership of dev. It returns
// ErrDeviceAlreadyAttached if another open implementation is attached. A
// closed implementation does not occupy the attachment slot. Use ReplaceDevice
// to change an existing open attachment.
func (c *Client) AttachDevice(dev device.DeviceAPI) error {
	if err := validateDeviceAPI(dev); err != nil {
		return err
	}
	c.deviceMu.Lock()
	defer c.deviceMu.Unlock()
	if !nilDeviceAPI(c.deviceAPI) && !closedDeviceAPI(c.deviceAPI) {
		return ErrDeviceAlreadyAttached
	}
	c.deviceAPI = dev
	return nil
}

// DetachDevice removes and returns the current device API without closing it.
// It returns nil if no implementation is attached. The returned implementation
// can be attached again, or the caller can close it explicitly.
func (c *Client) DetachDevice() device.DeviceAPI {
	c.deviceMu.Lock()
	defer c.deviceMu.Unlock()
	previous := c.deviceAPI
	c.deviceAPI = nil
	return previous
}

// ReplaceDevice atomically attaches dev and returns the previous device API.
//
// ReplaceDevice does not close either implementation. It waits for a current
// ApplyProfile call to finish before it replaces the attachment. The caller can
// attach the returned implementation again later or close it explicitly.
func (c *Client) ReplaceDevice(dev device.DeviceAPI) (device.DeviceAPI, error) {
	if err := validateDeviceAPI(dev); err != nil {
		return nil, err
	}
	c.deviceMu.Lock()
	defer c.deviceMu.Unlock()
	previous := c.deviceAPI
	c.deviceAPI = dev
	return previous, nil
}

// ApplyProfile applies profile to the currently attached device API.
//
// The call holds the client attachment stable until application finishes. It
// uses tracked peer ownership, so closing an attached DetachedDevice removes
// the applied peer. Device-global settings remain part of the wrapped device.
func (c *Client) ApplyProfile(profile *Profile) error {
	c.deviceMu.RLock()
	defer c.deviceMu.RUnlock()
	if nilDeviceAPI(c.deviceAPI) {
		return ErrDeviceRequired
	}
	return ApplyProfile(c.deviceAPI, profile)
}

// ApplyProfile validates and applies profile through dev.
//
// dev can be a concrete Device, a DetachedDevice, or any other DeviceAPI
// implementation. The profile peer is added with UpsertTrackedPeer. A
// middleware must therefore release that peer when its lifetime ends.
// ApplyProfile does not call Up or Close.
func ApplyProfile(dev device.DeviceAPI, profile *Profile) error {
	if err := validateDeviceAPI(dev); err != nil {
		return err
	}
	if profile == nil {
		return errors.New("amnezia: profile is nil")
	}
	if err := validateProfile(profile); err != nil {
		return fmt.Errorf("amnezia: invalid profile: %w", err)
	}

	privateKey, err := profilePrivateKey(dev, profile)
	if err != nil {
		return err
	}
	peerPublicKey, err := device.ParsePublicKey(strings.TrimSpace(profile.Peer.PublicKey))
	if err != nil {
		return fmt.Errorf("amnezia: parse peer public key: %w", err)
	}
	presharedKey, err := device.ParsePresharedKey(strings.TrimSpace(profile.Peer.PresharedKey))
	if err != nil {
		return fmt.Errorf("amnezia: parse peer preshared key: %w", err)
	}
	allowedIPs, err := profileAllowedIPs(profile.Peer.AllowedIPs)
	if err != nil {
		return err
	}
	awg, err := profileDeviceAmneziaWGConfig(profile.AmneziaWG)
	if err != nil {
		return err
	}
	listenPort, err := profileUint16("listen port", profile.Interface.ListenPort)
	if err != nil {
		return err
	}

	peer := device.PeerSpec{
		PublicKey:       peerPublicKey,
		PresharedKey:    presharedKey,
		ProtocolVersion: 1,
		Endpoint: &device.PeerEndpoint{
			Transport: device.DefaultTransportID,
			Address:   strings.TrimSpace(profile.Peer.Endpoint),
		},
		AllowedIPs: allowedIPs,
		Activation: device.PeerActivationEager,
	}
	if profile.Peer.PersistentKeepalive.Set {
		if profile.Peer.PersistentKeepalive.Min == profile.Peer.PersistentKeepalive.Max {
			keepalive, err := profileUint16(
				"persistent keepalive",
				int(profile.Peer.PersistentKeepalive.Min),
			)
			if err != nil {
				return err
			}
			peer.PersistentKeepaliveInterval = keepalive
		} else {
			keepalive := profileDeviceRange(profile.Peer.PersistentKeepalive)
			peer.PersistentKeepaliveRange = &keepalive
		}
	}

	if err := dev.ApplyConfig(device.DeviceConfig{
		PrivateKey: privateKey,
		ListenPort: listenPort,
		Fwmark:     profile.Interface.FirewallMark,
		AmneziaWG:  awg,
	}, device.ApplyConfigOptions{}); err != nil {
		return fmt.Errorf("amnezia: apply device configuration: %w", err)
	}
	if err := dev.UpsertTrackedPeer(peer); err != nil {
		return fmt.Errorf("amnezia: apply tracked peer: %w", err)
	}
	return nil
}

func validateDeviceAPI(dev device.DeviceAPI) error {
	if nilDeviceAPI(dev) {
		return ErrDeviceRequired
	}
	if closedDeviceAPI(dev) {
		return device.ErrDeviceClosed
	}
	return nil
}

func closedDeviceAPI(dev device.DeviceAPI) bool {
	select {
	case <-dev.Wait():
		return true
	default:
		return false
	}
}

func nilDeviceAPI(dev device.DeviceAPI) bool {
	if dev == nil {
		return true
	}
	value := reflect.ValueOf(dev)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (c *Client) attachedDevicePublicKey() (string, bool, error) {
	c.deviceMu.RLock()
	defer c.deviceMu.RUnlock()
	if nilDeviceAPI(c.deviceAPI) {
		return "", false, nil
	}
	if err := validateDeviceAPI(c.deviceAPI); err != nil {
		return "", false, err
	}
	privateKey := c.deviceAPI.PrivateKey()
	if privateKey.IsZero() {
		return "", false, nil
	}
	return privateKey.PublicKey().Base64(), true, nil
}

func profilePrivateKey(dev device.DeviceAPI, profile *Profile) (device.NoisePrivateKey, error) {
	encodedPrivateKey := strings.TrimSpace(profile.Interface.PrivateKey)
	if encodedPrivateKey == "" {
		privateKey := dev.PrivateKey()
		if privateKey.IsZero() {
			return device.NoisePrivateKey{}, ErrWireGuardPrivateKeyRequired
		}
		if publicKey := strings.TrimSpace(profile.Interface.PublicKey); publicKey != "" &&
			privateKey.PublicKey().Base64() != publicKey {
			return device.NoisePrivateKey{}, errors.New("amnezia: attached device private key does not match profile public key")
		}
		return privateKey, nil
	}
	privateKey, err := device.ParsePrivateKey(encodedPrivateKey)
	if err != nil {
		return device.NoisePrivateKey{}, fmt.Errorf("amnezia: parse interface private key: %w", err)
	}
	if privateKey.IsZero() {
		return device.NoisePrivateKey{}, ErrWireGuardPrivateKeyRequired
	}
	if publicKey := strings.TrimSpace(profile.Interface.PublicKey); publicKey != "" &&
		privateKey.PublicKey().Base64() != publicKey {
		return device.NoisePrivateKey{}, errors.New("amnezia: interface private key does not match profile public key")
	}
	return privateKey, nil
}

func profileAllowedIPs(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("amnezia: parse allowed IP %q: %w", value, err)
		}
		prefixes = append(prefixes, prefix)
	}
	if len(prefixes) == 0 {
		return nil, errors.New("amnezia: profile has no peer allowed IPs")
	}
	return prefixes, nil
}

func profileDeviceAmneziaWGConfig(src AmneziaWGConfig) (device.AmneziaWGConfig, error) {
	cfg := device.DefaultAmneziaWGConfig()
	version, err := profileDeviceAmneziaWGVersion(src.ProtocolVersion)
	if err != nil {
		return device.AmneziaWGConfig{}, err
	}
	cfg.Version = version
	cfg.JunkCount = src.JunkPacketCount
	cfg.JunkMin = src.JunkPacketMinSize
	cfg.JunkMax = src.JunkPacketMaxSize
	if !profileFitsInt(src.InitPadding) || !profileFitsInt(src.ResponsePadding) ||
		!profileFitsInt(src.CookiePadding) || !profileFitsInt(src.TransportPadding) {
		return device.AmneziaWGConfig{}, errors.New("amnezia: AmneziaWG padding exceeds int range")
	}
	cfg.InitPadding = int(src.InitPadding)
	cfg.ResponsePadding = int(src.ResponsePadding)
	cfg.CookiePadding = int(src.CookiePadding)
	cfg.TransportPadding = int(src.TransportPadding)
	if src.InitHeader.Set {
		cfg.InitHeader = device.AmneziaWGHeaderRange{Start: src.InitHeader.Min, End: src.InitHeader.Max}
	}
	if src.ResponseHeader.Set {
		cfg.ResponseHeader = device.AmneziaWGHeaderRange{Start: src.ResponseHeader.Min, End: src.ResponseHeader.Max}
	}
	if src.CookieHeader.Set {
		cfg.CookieHeader = device.AmneziaWGHeaderRange{Start: src.CookieHeader.Min, End: src.CookieHeader.Max}
	}
	if src.TransportHeader.Set {
		cfg.TransportHeader = device.AmneziaWGHeaderRange{Start: src.TransportHeader.Min, End: src.TransportHeader.Max}
	}
	cfg.InitiationPackets = src.InitiationPackets
	if strings.TrimSpace(src.HeaderProtectionKey) != "" {
		key, err := profileHeaderProtectionKey(src.HeaderProtectionKey)
		if err != nil {
			return device.AmneziaWGConfig{}, fmt.Errorf("amnezia: parse header protection key: %w", err)
		}
		cfg.HeaderProtectionKey = key
	}
	cfg.ContentPadding = profileDeviceRange(src.ContentPaddingAddition)
	cfg.RekeyAfterTime = profileDeviceRange(src.RekeyAfterTime)
	cfg.RekeyTimeout = profileDeviceRange(src.RekeyTimeout)
	cfg.RejectAfterTime = profileDeviceRange(src.RejectAfterTime)
	cfg.KeepaliveTimeout = profileDeviceRange(src.KeepaliveTimeout)
	cfg.MaxHandshakeAttempts = profileDeviceRange(src.MaxHandshakeAttempts)
	if src.RandomTrailers.Set {
		cfg.RandomTrailers = src.RandomTrailers.Enabled
	}
	if src.DisableCookies.Set {
		cfg.DisableCookies = src.DisableCookies.Enabled
	}
	return cfg, nil
}

func profileDeviceAmneziaWGVersion(value string) (device.AmneziaWGVersion, error) {
	switch strings.TrimSpace(value) {
	case "":
		return device.AmneziaWGVersionAuto, nil
	case "1.5":
		return device.AmneziaWGV1_5, nil
	case "2":
		return device.AmneziaWGV2, nil
	case "3.1":
		return device.AmneziaWGV3_1, nil
	default:
		return device.AmneziaWGVersionAuto, fmt.Errorf("amnezia: unsupported AmneziaWG protocol version %q", value)
	}
}

func profileDeviceRange(src Uint32Range) device.AmneziaWGRange {
	return device.AmneziaWGRange{Min: src.Min, Max: src.Max, Set: src.Set}
}

func profileFitsInt(value uint32) bool {
	return uint64(value) <= uint64(int(^uint(0)>>1))
}

func profileHeaderProtectionKey(value string) (device.AmneziaWGHeaderProtectionKey, error) {
	var key device.AmneziaWGHeaderProtectionKey
	value = strings.TrimSpace(value)
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil && len(decoded) == len(key) {
		copy(key[:], decoded)
		return key, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(value); err == nil && len(decoded) == len(key) {
		copy(key[:], decoded)
		return key, nil
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(key) {
		return key, errors.New("key must encode exactly 32 bytes")
	}
	copy(key[:], decoded)
	return key, nil
}

func profileUint16(name string, value int) (uint16, error) {
	if value < 0 || value > int(^uint16(0)) {
		return 0, fmt.Errorf("amnezia: %s must be in range 0-65535", name)
	}
	return uint16(value), nil
}
