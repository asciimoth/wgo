package amnezia

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// ProfileAPI records service metadata associated with a profile. ServiceInfo
// is opaque gateway data and should be treated as potentially sensitive.
type ProfileAPI struct {
	ServiceType       string
	ServiceProtocol   string
	UserCountryCode   string
	ServerCountryCode string
	ServiceInfo       json.RawMessage
}

// WireGuardInterface is backend-neutral interface input. PrivateKey is secret
// and is empty when service negotiation used a caller-owned public key.
type WireGuardInterface struct {
	PrivateKey   string
	PublicKey    string
	Addresses    []string
	DNS          []string
	MTU          int
	ListenPort   int
	FirewallMark uint32
}

// WireGuardPeer is backend-neutral peer input.
type WireGuardPeer struct {
	PublicKey           string
	PresharedKey        string
	Endpoint            string
	AllowedIPs          []string
	PersistentKeepalive Uint32Range
}

// AmneziaWGConfig contains all v1.5/v2/v3.1 fields currently recognized by
// the official app and amneziawg-go. Zero/Set=false means omitted.
// HeaderProtectionKey is shared obfuscation key material and is secret.
type AmneziaWGConfig struct {
	ProtocolVersion string

	JunkPacketCount   int
	JunkPacketMinSize int
	JunkPacketMaxSize int

	InitPadding      uint32
	ResponsePadding  uint32
	CookiePadding    uint32
	TransportPadding uint32

	InitHeader      Uint32Range
	ResponseHeader  Uint32Range
	CookieHeader    Uint32Range
	TransportHeader Uint32Range

	InitiationPackets [5]string

	HeaderProtectionKey    string
	ContentPaddingAddition Uint32Range
	RekeyAfterTime         Uint32Range
	RekeyTimeout           Uint32Range
	RejectAfterTime        Uint32Range
	KeepaliveTimeout       Uint32Range
	MaxHandshakeAttempts   Uint32Range
	RandomTrailers         Toggle
	DisableCookies         Toggle

	paddingSet [4]bool
}

// PreConnectAction is a server-supplied UDP/TCP preamble action. The library
// exposes it but never performs it implicitly; the embedding application owns
// networking policy and timing.
type PreConnectAction struct {
	Endpoint             string
	Protocol             string
	Timeout              time.Duration
	PayloadSpec          string
	ExpectedResponseSpec string
}

// Profile is the completed result. NativeConfig is untrusted imported/server
// text and may contain directives outside the safe structured model.
// NativeConfig and RawConfig can contain a WireGuard private key or an
// unresolved private-key placeholder and must be treated as secrets.
type Profile struct {
	Name          string
	Description   string
	ConfigVersion int
	HostName      string
	Interface     WireGuardInterface
	Peer          WireGuardPeer
	AmneziaWG     AmneziaWGConfig
	PreConnect    []PreConnectAction
	API           ProfileAPI
	NativeConfig  string
	RawConfig     json.RawMessage
}

// String is deliberately redacted.
func (p Profile) String() string {
	return fmt.Sprintf("Profile{name:%q, endpoint:<redacted>, protocol:%q, private_key:<redacted>}", p.Name, p.AmneziaWG.ProtocolVersion)
}

// ParseGatewayProfile decodes a successful gateway config for a locally held
// private key, substitutes the private-key placeholder, and projects it into
// Profile. Use ParseGatewayProfileWithPublicKey when the caller keeps the
// private key outside this package.
func ParseGatewayProfile(configText, clientPrivateKey string, api ProfileAPI) (*Profile, error) {
	clientPrivateKey = strings.TrimSpace(clientPrivateKey)
	localPublicKey, err := wireGuardPublicFromPrivate(clientPrivateKey)
	if err != nil {
		return nil, &ProtocolError{Op: "validate local WireGuard private key", Err: err}
	}
	return parseGatewayProfile(configText, localPublicKey, clientPrivateKey, api)
}

// ParseGatewayProfileWithPublicKey decodes a successful gateway config for a
// caller-owned WireGuard identity. The returned Profile has an empty
// Interface.PrivateKey; the caller must configure its backend with the private
// key matching clientPublicKey. ConfigText and RenderConfig return
// ErrWireGuardPrivateKeyRequired until that private key is supplied.
func ParseGatewayProfileWithPublicKey(configText, clientPublicKey string, api ProfileAPI) (*Profile, error) {
	clientPublicKey = strings.TrimSpace(clientPublicKey)
	if err := validateWireGuardKey("client public key", clientPublicKey); err != nil {
		return nil, &ProtocolError{Op: "validate local WireGuard public key", Err: err}
	}
	return parseGatewayProfile(configText, clientPublicKey, "", api)
}

func parseGatewayProfile(configText, clientPublicKey, clientPrivateKey string, api ProfileAPI) (*Profile, error) {
	plain, err := DecodeVPNPayload(configText)
	if err != nil {
		return nil, &ProtocolError{Op: "decode gateway profile", Err: err}
	}
	if clientPrivateKey != "" {
		plain = bytes.ReplaceAll(plain, []byte("$WIREGUARD_CLIENT_PRIVATE_KEY"), []byte(clientPrivateKey))
	}
	var root map[string]any
	if err := json.Unmarshal(plain, &root); err != nil {
		return nil, &ProtocolError{Op: "parse gateway profile JSON", Err: err}
	}
	profile := &Profile{
		Name:          anyString(root["name"]),
		Description:   anyString(root["description"]),
		ConfigVersion: anyInt(root["config_version"]),
		HostName:      anyString(root["hostName"]),
		API:           cloneProfileAPI(api),
		RawConfig:     append(json.RawMessage(nil), plain...),
	}
	profile.Interface.DNS = nonEmptyStrings(anyString(root["dns1"]), anyString(root["dns2"]))
	profile.PreConnect = parsePreConnect(root["send_payload"])
	if apiConfig, ok := root["api_config"].(map[string]any); ok {
		profile.API.ServerCountryCode = anyString(apiConfig["server_country_code"])
	}

	protocol, client, err := findWireGuardClient(root)
	if err != nil {
		return nil, &ProtocolError{Op: "find WireGuard/AmneziaWG client profile", Err: err}
	}
	for _, key := range awgFieldNames {
		if anyString(client[key]) == "" && protocol[key] != nil {
			client[key] = protocol[key]
		}
	}
	profile.NativeConfig = anyString(client["config"])
	if profile.NativeConfig != "" && clientPrivateKey != "" {
		profile.NativeConfig = strings.ReplaceAll(profile.NativeConfig, "$WIREGUARD_CLIENT_PRIVATE_KEY", clientPrivateKey)
		profile.NativeConfig, err = forceNativeInterfacePrivateKey(profile.NativeConfig, clientPrivateKey)
		if err != nil {
			return nil, &ProtocolError{Op: "sanitize native config", Err: err}
		}
	}
	profile.HostName = firstString(anyString(client["hostName"]), profile.HostName)
	port := anyInt(client["port"])
	profile.Interface.PrivateKey = clientPrivateKey
	profile.Interface.PublicKey = clientPublicKey
	if reportedPublicKey := anyString(client["client_pub_key"]); reportedPublicKey != "" && !sameWireGuardKey(reportedPublicKey, clientPublicKey) {
		return nil, &ProtocolError{Op: "validate gateway profile", Err: errors.New("returned client public key does not match requested public key")}
	}
	profile.Interface.Addresses = anyStringSlice(client["client_ip"])
	profile.Interface.MTU = parseLooseInt(client["mtu"])
	profile.Peer.PublicKey = anyString(client["server_pub_key"])
	profile.Peer.PresharedKey = anyString(client["psk_key"])
	profile.Peer.AllowedIPs = anyStringSlice(client["allowed_ips"])
	if keepalive := anyString(client["persistent_keep_alive"]); keepalive != "" {
		profile.Peer.PersistentKeepalive, err = ParseUint32Range(keepalive)
		if err != nil {
			return nil, &ProtocolError{Op: "parse PersistentKeepalive", Err: err}
		}
	}
	profile.AmneziaWG, err = parseAmneziaWG(client)
	if err != nil {
		return nil, err
	}

	if profile.NativeConfig != "" {
		if err := applyNativeFallback(profile, profile.NativeConfig); err != nil {
			return nil, &ProtocolError{Op: "parse native config", Err: err}
		}
	}
	if profile.Peer.Endpoint == "" && profile.HostName != "" && port > 0 {
		profile.Peer.Endpoint = net.JoinHostPort(strings.Trim(profile.HostName, "[]"), strconv.Itoa(port))
	}
	profile.Interface.Addresses = normalizeInterfaceAddresses(profile.Interface.Addresses)
	if err := validateProfile(profile); err != nil {
		return nil, &ProtocolError{Op: "validate gateway profile", Err: err}
	}
	return profile, nil
}

func cloneProfileAPI(api ProfileAPI) ProfileAPI {
	api.ServiceInfo = append(json.RawMessage(nil), api.ServiceInfo...)
	return api
}

var errWireGuardClientProfileNotFound = errors.New("missing WireGuard/AmneziaWG client profile")

func findWireGuardClient(root map[string]any) (map[string]any, map[string]any, error) {
	containers, _ := root["containers"].([]any)
	for _, value := range containers {
		container, ok := value.(map[string]any)
		if !ok {
			continue
		}
		var protocol map[string]any
		for _, key := range []string{"awg", "amnezia-awg", "amnezia-awg2", "wireguard"} {
			if candidate, candidateOK := container[key].(map[string]any); candidateOK {
				protocol = candidate
				break
			}
		}
		if protocol == nil {
			continue
		}
		client := make(map[string]any)
		switch last := protocol["last_config"].(type) {
		case string:
			if err := json.Unmarshal([]byte(last), &client); err != nil {
				return nil, nil, fmt.Errorf("last_config JSON: %w", err)
			}
		case map[string]any:
			for key, entry := range last {
				client[key] = entry
			}
		case nil:
			// Some compatible gateways flatten client fields into the protocol
			// object. The merge below handles that form.
		default:
			return nil, nil, errors.New("last_config must be a JSON string or object")
		}
		for _, key := range clientFieldNames {
			if client[key] == nil && protocol[key] != nil {
				client[key] = protocol[key]
			}
		}
		return protocol, client, nil
	}
	// A custom gateway may return the AWG client object directly.
	if anyString(root["client_priv_key"]) != "" || anyString(root["config"]) != "" {
		return root, root, nil
	}
	return nil, nil, errWireGuardClientProfileNotFound
}

var clientFieldNames = []string{
	"config", "hostName", "port", "client_ip", "client_priv_key", "client_pub_key",
	"server_pub_key", "psk_key", "allowed_ips", "persistent_keep_alive", "mtu",
}

var awgFieldNames = []string{
	"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
	"I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey", "ContentPaddingAddition",
	"RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout",
	"MaxHandshakeAttempts", "RandomTrailers", "DisableCookies", "protocol_version",
}

func parseAmneziaWG(values map[string]any) (AmneziaWGConfig, error) {
	var config AmneziaWGConfig
	config.ProtocolVersion = anyString(values["protocol_version"])
	config.JunkPacketCount = parseLooseInt(values["Jc"])
	config.JunkPacketMinSize = parseLooseInt(values["Jmin"])
	config.JunkPacketMaxSize = parseLooseInt(values["Jmax"])
	paddings := []*uint32{&config.InitPadding, &config.ResponsePadding, &config.CookiePadding, &config.TransportPadding}
	for i, key := range []string{"S1", "S2", "S3", "S4"} {
		text := anyString(values[key])
		if text == "" {
			continue
		}
		parsed, err := strconv.ParseUint(text, 10, 32)
		if err != nil {
			return config, &ProtocolError{Op: "parse " + key, Err: err}
		}
		*paddings[i] = uint32(parsed)
		config.paddingSet[i] = true
	}
	headers := []*Uint32Range{&config.InitHeader, &config.ResponseHeader, &config.CookieHeader, &config.TransportHeader}
	for i, key := range []string{"H1", "H2", "H3", "H4"} {
		text := anyString(values[key])
		if text == "" {
			continue
		}
		parsed, err := ParseUint32Range(text)
		if err != nil {
			return config, &ProtocolError{Op: "parse " + key, Err: err}
		}
		*headers[i] = parsed
	}
	for i := range config.InitiationPackets {
		config.InitiationPackets[i] = anyString(values[fmt.Sprintf("I%d", i+1)])
	}
	config.HeaderProtectionKey = anyString(values["HeaderProtectionKey"])
	var err error
	ranges := []struct {
		key    string
		target *Uint32Range
	}{
		{"ContentPaddingAddition", &config.ContentPaddingAddition},
		{"RekeyAfterTime", &config.RekeyAfterTime},
		{"RekeyTimeout", &config.RekeyTimeout},
		{"RejectAfterTime", &config.RejectAfterTime},
		{"KeepaliveTimeout", &config.KeepaliveTimeout},
		{"MaxHandshakeAttempts", &config.MaxHandshakeAttempts},
	}
	for _, entry := range ranges {
		if text := anyString(values[entry.key]); text != "" {
			*entry.target, err = ParseUint32Range(text)
			if err != nil {
				return config, &ProtocolError{Op: "parse " + entry.key, Err: err}
			}
		}
	}
	config.RandomTrailers = parseToggle(anyString(values["RandomTrailers"]))
	config.DisableCookies = parseToggle(anyString(values["DisableCookies"]))
	if config.ProtocolVersion == "" {
		config.ProtocolVersion = inferAWGVersion(config)
	}
	return config, nil
}

func inferAWGVersion(config AmneziaWGConfig) string {
	if config.HeaderProtectionKey != "" || config.ContentPaddingAddition.Set || config.RekeyAfterTime.Set ||
		config.RekeyTimeout.Set || config.RejectAfterTime.Set || config.KeepaliveTimeout.Set ||
		config.MaxHandshakeAttempts.Set || config.RandomTrailers.Enabled || config.DisableCookies.Enabled {
		return "3.1"
	}
	if config.paddingSet[2] || config.paddingSet[3] ||
		(config.InitHeader.Set && config.InitHeader.Min != config.InitHeader.Max) ||
		(config.ResponseHeader.Set && config.ResponseHeader.Min != config.ResponseHeader.Max) ||
		(config.CookieHeader.Set && config.CookieHeader.Min != config.CookieHeader.Max) ||
		(config.TransportHeader.Set && config.TransportHeader.Min != config.TransportHeader.Max) {
		return "2"
	}
	for _, packet := range config.InitiationPackets {
		if packet != "" {
			return "1.5"
		}
	}
	return ""
}

func applyNativeFallback(profile *Profile, native string) error {
	section := ""
	nativeAWG := make(map[string]any)
	interfaceSections := 0
	peerSections := 0
	scanner := bufio.NewScanner(strings.NewReader(native))
	scanner.Buffer(make([]byte, 64*1024), maxVPNPayloadBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch section {
			case "interface":
				interfaceSections++
			case "peer":
				peerSections++
			}
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		switch section {
		case "interface":
			switch strings.ToLower(key) {
			case "privatekey":
				if profile.Interface.PrivateKey == "" && profile.Interface.PublicKey == "" {
					profile.Interface.PrivateKey = value
				}
			case "address":
				if len(profile.Interface.Addresses) == 0 {
					profile.Interface.Addresses = splitComma(value)
				}
			case "dns":
				if len(profile.Interface.DNS) == 0 {
					profile.Interface.DNS = splitComma(value)
				}
			case "mtu":
				if profile.Interface.MTU == 0 {
					parsed, err := strconv.Atoi(value)
					if err != nil {
						return fmt.Errorf("MTU: %w", err)
					}
					profile.Interface.MTU = parsed
				}
			case "listenport":
				if profile.Interface.ListenPort == 0 {
					parsed, err := strconv.ParseUint(value, 10, 16)
					if err != nil {
						return fmt.Errorf("ListenPort: %w", err)
					}
					profile.Interface.ListenPort = int(parsed)
				}
			case "fwmark":
				if profile.Interface.FirewallMark == 0 && !strings.EqualFold(value, "off") {
					parsed, err := strconv.ParseUint(value, 0, 32)
					if err != nil {
						return fmt.Errorf("FwMark: %w", err)
					}
					profile.Interface.FirewallMark = uint32(parsed)
				}
			default:
				if canonical, ok := nativeAWGFieldName(key); ok {
					nativeAWG[canonical] = value
				}
			}
		case "peer":
			switch strings.ToLower(key) {
			case "publickey":
				if profile.Peer.PublicKey == "" {
					profile.Peer.PublicKey = value
				}
			case "presharedkey":
				if profile.Peer.PresharedKey == "" {
					profile.Peer.PresharedKey = value
				}
			case "endpoint":
				profile.Peer.Endpoint = value
			case "allowedips":
				if len(profile.Peer.AllowedIPs) == 0 {
					profile.Peer.AllowedIPs = splitComma(value)
				}
			case "persistentkeepalive":
				if !profile.Peer.PersistentKeepalive.Set {
					parsed, err := ParseUint32Range(value)
					if err != nil {
						return fmt.Errorf("PersistentKeepalive: %w", err)
					}
					profile.Peer.PersistentKeepalive = parsed
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if interfaceSections != 1 || peerSections > 1 {
		return errors.New("native config must contain one [Interface] and at most one [Peer]")
	}
	if len(nativeAWG) > 0 {
		fallback, err := parseAmneziaWG(nativeAWG)
		if err != nil {
			return err
		}
		mergeAmneziaWGFallback(&profile.AmneziaWG, fallback)
	}
	return nil
}

func nativeAWGFieldName(value string) (string, bool) {
	for _, candidate := range awgFieldNames {
		if strings.EqualFold(value, candidate) {
			return candidate, true
		}
	}
	return "", false
}

func mergeAmneziaWGFallback(target *AmneziaWGConfig, fallback AmneziaWGConfig) {
	if target.ProtocolVersion == "" {
		target.ProtocolVersion = fallback.ProtocolVersion
	}
	if target.JunkPacketCount == 0 {
		target.JunkPacketCount = fallback.JunkPacketCount
	}
	if target.JunkPacketMinSize == 0 {
		target.JunkPacketMinSize = fallback.JunkPacketMinSize
	}
	if target.JunkPacketMaxSize == 0 {
		target.JunkPacketMaxSize = fallback.JunkPacketMaxSize
	}
	targetPaddings := []*uint32{&target.InitPadding, &target.ResponsePadding, &target.CookiePadding, &target.TransportPadding}
	fallbackPaddings := []uint32{fallback.InitPadding, fallback.ResponsePadding, fallback.CookiePadding, fallback.TransportPadding}
	for index := range targetPaddings {
		if !target.paddingSet[index] && fallback.paddingSet[index] {
			*targetPaddings[index] = fallbackPaddings[index]
			target.paddingSet[index] = true
		}
	}
	targetHeaders := []*Uint32Range{&target.InitHeader, &target.ResponseHeader, &target.CookieHeader, &target.TransportHeader}
	fallbackHeaders := []Uint32Range{fallback.InitHeader, fallback.ResponseHeader, fallback.CookieHeader, fallback.TransportHeader}
	for index := range targetHeaders {
		if !targetHeaders[index].Set && fallbackHeaders[index].Set {
			*targetHeaders[index] = fallbackHeaders[index]
		}
	}
	for index := range target.InitiationPackets {
		if target.InitiationPackets[index] == "" {
			target.InitiationPackets[index] = fallback.InitiationPackets[index]
		}
	}
	if target.HeaderProtectionKey == "" {
		target.HeaderProtectionKey = fallback.HeaderProtectionKey
	}
	targetRanges := []*Uint32Range{
		&target.ContentPaddingAddition, &target.RekeyAfterTime, &target.RekeyTimeout,
		&target.RejectAfterTime, &target.KeepaliveTimeout, &target.MaxHandshakeAttempts,
	}
	fallbackRanges := []Uint32Range{
		fallback.ContentPaddingAddition, fallback.RekeyAfterTime, fallback.RekeyTimeout,
		fallback.RejectAfterTime, fallback.KeepaliveTimeout, fallback.MaxHandshakeAttempts,
	}
	for index := range targetRanges {
		if !targetRanges[index].Set && fallbackRanges[index].Set {
			*targetRanges[index] = fallbackRanges[index]
		}
	}
	if !target.RandomTrailers.Set && fallback.RandomTrailers.Set {
		target.RandomTrailers = fallback.RandomTrailers
	}
	if !target.DisableCookies.Set && fallback.DisableCookies.Set {
		target.DisableCookies = fallback.DisableCookies
	}
}

func validateProfile(profile *Profile) error {
	if profile.Interface.PrivateKey != "" {
		if err := validateWireGuardKey("private key", profile.Interface.PrivateKey); err != nil {
			return err
		}
	}
	if profile.Interface.PublicKey != "" {
		if err := validateWireGuardKey("client public key", profile.Interface.PublicKey); err != nil {
			return err
		}
	}
	if profile.Interface.PrivateKey == "" && profile.Interface.PublicKey == "" {
		return errors.New("missing client WireGuard key")
	}
	if err := validateWireGuardKey("server public key", profile.Peer.PublicKey); err != nil {
		return err
	}
	if profile.Peer.PresharedKey != "" {
		if err := validateWireGuardKey("preshared key", profile.Peer.PresharedKey); err != nil {
			return err
		}
	}
	if len(profile.Interface.Addresses) == 0 {
		return errors.New("missing interface address")
	}
	for _, address := range profile.Interface.Addresses {
		if _, err := netip.ParsePrefix(address); err != nil {
			return fmt.Errorf("invalid interface address %q", address)
		}
	}
	for _, dns := range profile.Interface.DNS {
		if _, err := netip.ParseAddr(strings.TrimSpace(dns)); err != nil {
			return fmt.Errorf("invalid DNS address %q", dns)
		}
	}
	if profile.Interface.MTU < 0 || profile.Interface.MTU > 65535 {
		return errors.New("invalid MTU")
	}
	if profile.Interface.ListenPort < 0 || profile.Interface.ListenPort > 65535 {
		return errors.New("invalid ListenPort")
	}
	for _, prefix := range profile.Peer.AllowedIPs {
		if _, err := netip.ParsePrefix(strings.TrimSpace(prefix)); err != nil {
			return fmt.Errorf("invalid allowed IP %q", prefix)
		}
	}
	if err := profile.Peer.PersistentKeepalive.Validate(); err != nil {
		return fmt.Errorf("invalid PersistentKeepalive: %w", err)
	}
	if err := validateWireGuardEndpoint(profile.Peer.Endpoint); err != nil {
		return err
	}
	if err := validateAmneziaWGConfig(profile.AmneziaWG); err != nil {
		return err
	}
	return nil
}

func validateWireGuardEndpoint(endpoint string) error {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(endpoint))
	if err != nil || host == "" {
		return errors.New("invalid peer endpoint")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return errors.New("invalid peer endpoint port")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	if !validDNSName(host) {
		return errors.New("invalid peer endpoint host")
	}
	return nil
}

func validDNSName(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func validateAmneziaWGConfig(config AmneziaWGConfig) error {
	if config.JunkPacketCount < 0 || config.JunkPacketMinSize < 0 || config.JunkPacketMaxSize < 0 {
		return errors.New("invalid negative AmneziaWG junk value")
	}
	if config.JunkPacketMaxSize != 0 && config.JunkPacketMaxSize < config.JunkPacketMinSize {
		return errors.New("AmneziaWG Jmax is less than Jmin")
	}
	for index, padding := range []uint32{config.InitPadding, config.ResponsePadding, config.CookiePadding, config.TransportPadding} {
		if padding > 65535 {
			return fmt.Errorf("AmneziaWG S%d exceeds UDP size", index+1)
		}
	}
	if config.HeaderProtectionKey != "" {
		if !validAWGKey(config.HeaderProtectionKey) {
			return errors.New("invalid AmneziaWG HeaderProtectionKey")
		}
		for index, padding := range []uint32{config.InitPadding, config.ResponsePadding, config.CookiePadding, config.TransportPadding} {
			if padding < 12 {
				return fmt.Errorf("AmneziaWG S%d must be at least 12 with header protection", index+1)
			}
		}
	}
	headers := []Uint32Range{config.InitHeader, config.ResponseHeader, config.CookieHeader, config.TransportHeader}
	allRanges := append(append([]Uint32Range(nil), headers...),
		config.ContentPaddingAddition, config.RekeyAfterTime, config.RekeyTimeout,
		config.RejectAfterTime, config.KeepaliveTimeout, config.MaxHandshakeAttempts)
	for _, value := range allRanges {
		if err := value.Validate(); err != nil {
			return fmt.Errorf("invalid AmneziaWG range: %w", err)
		}
	}
	for left := 0; left < len(headers); left++ {
		if !headers[left].Set {
			continue
		}
		for right := left + 1; right < len(headers); right++ {
			if headers[right].Set && headers[left].Min <= headers[right].Max && headers[right].Min <= headers[left].Max {
				return fmt.Errorf("AmneziaWG H%d overlaps H%d", left+1, right+1)
			}
		}
	}
	for index, packet := range config.InitiationPackets {
		if len(packet) > 1<<20 || strings.ContainsAny(packet, "\r\n\x00") {
			return fmt.Errorf("invalid AmneziaWG I%d", index+1)
		}
	}
	return nil
}

func validAWGKey(value string) bool {
	_, err := decodeAWGKey(value)
	return err == nil
}

func canonicalAWGKey(value string) (string, error) {
	decoded, err := decodeAWGKey(value)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(decoded), nil
}

func decodeAWGKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(value); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return nil, errors.New("key must encode exactly 32 bytes")
	}
	return decoded, nil
}

func validateWireGuardKey(name, value string) error {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("invalid %s", name)
	}
	return nil
}

func wireGuardPublicFromPrivate(privateKey string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil || len(decoded) != 32 {
		return "", errors.New("invalid private key")
	}
	key, err := ecdh.X25519().NewPrivateKey(decoded)
	if err != nil {
		return "", fmt.Errorf("derive public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func sameWireGuardKey(left, right string) bool {
	leftBytes, leftErr := base64.StdEncoding.DecodeString(strings.TrimSpace(left))
	rightBytes, rightErr := base64.StdEncoding.DecodeString(strings.TrimSpace(right))
	return leftErr == nil && rightErr == nil && len(leftBytes) == 32 && bytes.Equal(leftBytes, rightBytes)
}

func forceNativeInterfacePrivateKey(native, privateKey string) (string, error) {
	hadFinalNewline := strings.HasSuffix(native, "\n")
	lines := strings.Split(strings.ReplaceAll(native, "\r\n", "\n"), "\n")
	section := ""
	foundInterface := false
	foundPrivateKey := false
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.ToLower(strings.TrimSpace(trimmed[1 : len(trimmed)-1]))
			if section == "interface" {
				foundInterface = true
			}
			continue
		}
		if section != "interface" {
			continue
		}
		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), "PrivateKey") {
			lines[index] = "PrivateKey = " + privateKey
			foundPrivateKey = true
		}
	}
	if !foundInterface || !foundPrivateKey {
		return "", errors.New("native config is missing [Interface] PrivateKey")
	}
	result := strings.Join(lines, "\n")
	if hadFinalNewline && !strings.HasSuffix(result, "\n") {
		result += "\n"
	}
	return result, nil
}

func normalizeInterfaceAddresses(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		for _, address := range splitComma(value) {
			if strings.Contains(address, "/") {
				result = append(result, address)
				continue
			}
			ip := net.ParseIP(address)
			if ip == nil {
				result = append(result, address)
			} else if ip.To4() != nil {
				result = append(result, address+"/32")
			} else {
				result = append(result, address+"/128")
			}
		}
	}
	return result
}

func anyString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		if typed {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func anyInt(value any) int {
	parsed, _ := strconv.Atoi(anyString(value))
	return parsed
}

func parseLooseInt(value any) int { return anyInt(value) }

func anyStringSlice(value any) []string {
	switch typed := value.(type) {
	case []any:
		result := make([]string, 0, len(typed))
		for _, entry := range typed {
			result = append(result, splitComma(anyString(entry))...)
		}
		return result
	case []string:
		return append([]string(nil), typed...)
	case string:
		return splitComma(typed)
	default:
		return nil
	}
}

func splitComma(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func nonEmptyStrings(values ...string) []string {
	var result []string
	for _, value := range values {
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func firstString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func parsePreConnect(value any) []PreConnectAction {
	entries, _ := value.([]any)
	result := make([]PreConnectAction, 0, len(entries))
	for _, raw := range entries {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		timeout := anyInt(entry["timeout_ms"])
		result = append(result, PreConnectAction{
			Endpoint:             anyString(entry["endpoint"]),
			Protocol:             strings.ToLower(anyString(entry["protocol"])),
			Timeout:              time.Duration(timeout) * time.Millisecond,
			PayloadSpec:          anyString(entry["payload"]),
			ExpectedResponseSpec: anyString(entry["expected_response"]),
		})
	}
	return result
}

// ConfigText renders the validated structured profile and never returns
// unrecognized server-supplied native directives. It returns
// ErrWireGuardPrivateKeyRequired when Interface.PrivateKey is empty. The
// result is secret.
func (p Profile) ConfigText() (string, error) {
	return p.RenderConfig()
}

// RenderConfig renders a backend-neutral profile as an amneziawg-tools style
// configuration. It returns ErrWireGuardPrivateKeyRequired when
// Interface.PrivateKey is empty. The result contains private key material.
func (p Profile) RenderConfig() (string, error) {
	if strings.TrimSpace(p.Interface.PrivateKey) == "" {
		return "", ErrWireGuardPrivateKeyRequired
	}
	if err := validateProfile(&p); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("[Interface]\n")
	writeConfigLine(&b, "PrivateKey", p.Interface.PrivateKey)
	writeConfigLine(&b, "Address", strings.Join(p.Interface.Addresses, ", "))
	writeConfigLine(&b, "DNS", strings.Join(p.Interface.DNS, ", "))
	if p.Interface.MTU > 0 {
		writeConfigLine(&b, "MTU", strconv.Itoa(p.Interface.MTU))
	}
	if p.Interface.ListenPort > 0 {
		writeConfigLine(&b, "ListenPort", strconv.Itoa(p.Interface.ListenPort))
	}
	if p.Interface.FirewallMark > 0 {
		writeConfigLine(&b, "FwMark", fmt.Sprintf("0x%x", p.Interface.FirewallMark))
	}
	awg := p.AmneziaWG
	writeNonZeroInt(&b, "Jc", awg.JunkPacketCount)
	writeNonZeroInt(&b, "Jmin", awg.JunkPacketMinSize)
	writeNonZeroInt(&b, "Jmax", awg.JunkPacketMaxSize)
	writeOptionalUint(&b, "S1", awg.InitPadding, awg.paddingSet[0] || awg.InitPadding != 0)
	writeOptionalUint(&b, "S2", awg.ResponsePadding, awg.paddingSet[1] || awg.ResponsePadding != 0)
	writeOptionalUint(&b, "S3", awg.CookiePadding, awg.paddingSet[2] || awg.CookiePadding != 0)
	writeOptionalUint(&b, "S4", awg.TransportPadding, awg.paddingSet[3] || awg.TransportPadding != 0)
	writeConfigLine(&b, "H1", awg.InitHeader.String())
	writeConfigLine(&b, "H2", awg.ResponseHeader.String())
	writeConfigLine(&b, "H3", awg.CookieHeader.String())
	writeConfigLine(&b, "H4", awg.TransportHeader.String())
	for index, packet := range awg.InitiationPackets {
		writeConfigLine(&b, fmt.Sprintf("I%d", index+1), packet)
	}
	if awg.HeaderProtectionKey != "" {
		headerKey, err := canonicalAWGKey(awg.HeaderProtectionKey)
		if err != nil {
			return "", err
		}
		writeConfigLine(&b, "HeaderProtectionKey", headerKey)
	}
	writeConfigLine(&b, "ContentPaddingAddition", awg.ContentPaddingAddition.String())
	writeConfigLine(&b, "RekeyAfterTime", awg.RekeyAfterTime.String())
	writeConfigLine(&b, "RekeyTimeout", awg.RekeyTimeout.String())
	writeConfigLine(&b, "RejectAfterTime", awg.RejectAfterTime.String())
	writeConfigLine(&b, "KeepaliveTimeout", awg.KeepaliveTimeout.String())
	writeConfigLine(&b, "MaxHandshakeAttempts", awg.MaxHandshakeAttempts.String())
	writeConfigLine(&b, "RandomTrailers", awg.RandomTrailers.String())
	writeConfigLine(&b, "DisableCookies", awg.DisableCookies.String())
	b.WriteString("\n[Peer]\n")
	writeConfigLine(&b, "PublicKey", p.Peer.PublicKey)
	writeConfigLine(&b, "PresharedKey", p.Peer.PresharedKey)
	writeConfigLine(&b, "AllowedIPs", strings.Join(p.Peer.AllowedIPs, ", "))
	writeConfigLine(&b, "Endpoint", p.Peer.Endpoint)
	writeConfigLine(&b, "PersistentKeepalive", p.Peer.PersistentKeepalive.String())
	return b.String(), nil
}

func writeConfigLine(b *strings.Builder, key, value string) {
	if value != "" {
		fmt.Fprintf(b, "%s = %s\n", key, value)
	}
}

func writeNonZeroInt(b *strings.Builder, key string, value int) {
	if value != 0 {
		writeConfigLine(b, key, strconv.Itoa(value))
	}
}

func writeOptionalUint(b *strings.Builder, key string, value uint32, set bool) {
	if set {
		writeConfigLine(b, key, strconv.FormatUint(uint64(value), 10))
	}
}
