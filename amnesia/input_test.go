package amnezia

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func testKeyByte(value byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}

func encodeQtCompressedPayload(t *testing.T, value any) string {
	t.Helper()
	plain, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	writer, err := zlib.NewWriterLevel(&compressed, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	framed := make([]byte, 4, 4+compressed.Len())
	binary.BigEndian.PutUint32(framed, uint32(len(plain)))
	framed = append(framed, compressed.Bytes()...)
	return vpnScheme + base64.RawURLEncoding.EncodeToString(framed)
}

func selfHostedGuestFixture(t *testing.T, protocolKey, containerName string, awg bool) (string, string) {
	t.Helper()
	privateKey := testKeyByte(0x11)
	publicKey, err := wireGuardPublicFromPrivate(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	serverKey := testKeyByte(0x22)
	headerKey := testKeyByte(0x33)
	native := "[Interface]\n" +
		"PrivateKey = " + privateKey + "\n" +
		"Address = 10.88.0.2/32\n" +
		"DNS = 1.1.1.1\n" +
		"PostUp = must-not-be-rendered\n"
	client := map[string]any{
		"config":                native,
		"hostName":              "198.51.100.10",
		"port":                  51820,
		"client_ip":             "10.88.0.2",
		"client_priv_key":       privateKey,
		"client_pub_key":        publicKey,
		"server_pub_key":        serverKey,
		"allowed_ips":           []string{"0.0.0.0/0", "::/0"},
		"persistent_keep_alive": "25",
	}
	protocol := map[string]any{}
	if awg {
		for key, value := range map[string]string{
			"Jc": "3", "Jmin": "10", "Jmax": "20",
			"S1": "12", "S2": "12", "S3": "12", "S4": "12",
			"H1": "100", "H2": "200", "H3": "300", "H4": "400",
			"HeaderProtectionKey":    headerKey,
			"ContentPaddingAddition": "4-20",
			"protocol_version":       "3.1",
		} {
			client[key] = value
			protocol[key] = value
		}
	}
	lastConfig, err := json.Marshal(client)
	if err != nil {
		t.Fatal(err)
	}
	protocol["last_config"] = string(lastConfig)
	document := map[string]any{
		"description":      "Self-hosted test",
		"hostName":         "198.51.100.10",
		"defaultContainer": containerName,
		"dns1":             "1.1.1.1",
		"containers": []any{map[string]any{
			"container": containerName,
			protocolKey: protocol,
		}},
	}
	return encodeQtCompressedPayload(t, document), privateKey
}

func selfHostedAWGVersionFixture(t *testing.T, awgFields map[string]string) string {
	t.Helper()
	input, privateKey := selfHostedGuestFixture(t, "awg", "amnezia-awg2", false)
	plain, err := DecodeVPNPayload(input)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(plain, &document); err != nil {
		t.Fatal(err)
	}
	containers := document["containers"].([]any)
	awg := containers[0].(map[string]any)["awg"].(map[string]any)
	var client map[string]any
	if err := json.Unmarshal([]byte(awg["last_config"].(string)), &client); err != nil {
		t.Fatal(err)
	}
	for key, value := range awgFields {
		awg[key] = value
		client[key] = value
	}
	client["client_priv_key"] = privateKey
	lastConfig, err := json.Marshal(client)
	if err != nil {
		t.Fatal(err)
	}
	awg["last_config"] = string(lastConfig)
	return encodeQtCompressedPayload(t, document)
}

func TestParseSelfHostedAWGGuestAndUnifiedImport(t *testing.T) {
	input, privateKey := selfHostedGuestFixture(t, "awg", "amnezia-awg2", true)
	parsed, err := ParseInput(input)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Format != InputFormatSelfHostedKey || parsed.Profile == nil || parsed.ActivationKey != nil {
		t.Fatalf("parsed input = %#v", parsed)
	}
	if parsed.Profile.Interface.PrivateKey != privateKey {
		t.Fatal("self-hosted private key mismatch")
	}
	if parsed.Profile.AmneziaWG.ProtocolVersion != "3.1" {
		t.Fatalf("AWG version = %q", parsed.Profile.AmneziaWG.ProtocolVersion)
	}
	if strings.Contains(parsed.String(), privateKey) {
		t.Fatal("ParsedInput.String leaked private key")
	}
	config, err := parsed.Profile.ConfigText()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(config, "PostUp") || !strings.Contains(config, "HeaderProtectionKey = ") {
		t.Fatalf("safe config projection is wrong:\n%s", config)
	}

	// Static inputs do not need a configured gateway Client and perform no I/O.
	var client *Client
	session, err := client.StartImport(input, NegotiationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if session.Format() != InputFormatSelfHostedKey || session.State() != NegotiationReady {
		t.Fatalf("new session: format=%q state=%d", session.Format(), session.State())
	}
	if strings.Contains(session.String(), privateKey) {
		t.Fatal("ImportSession.String leaked private key")
	}
	step, err := session.Next(context.Background())
	if err != nil || step.Profile == nil || step.State != NegotiationComplete {
		t.Fatalf("static Next = %#v, %v", step, err)
	}
	if _, err := session.Next(context.Background()); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("second static Next error = %v", err)
	}
	profile, err := client.ImportNonInteractive(context.Background(), input, NegotiationOptions{})
	if err != nil || profile == nil || profile.Interface.PrivateKey != privateKey {
		t.Fatalf("static non-interactive import = %#v, %v", profile, err)
	}
}

func TestParseSelfHostedWireGuardGuest(t *testing.T) {
	input, _ := selfHostedGuestFixture(t, "wireguard", "amnezia-wireguard", false)
	parsed, err := ParseInput(input)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Format != InputFormatSelfHostedKey || parsed.Profile.AmneziaWG.ProtocolVersion != "" {
		t.Fatalf("parsed WireGuard guest = %#v", parsed.Profile.AmneziaWG)
	}
}

func TestParseSelfHostedAWGGenerations(t *testing.T) {
	tests := []struct {
		name    string
		fields  map[string]string
		version string
	}{
		{
			name: "v1.5",
			fields: map[string]string{
				"Jc": "3", "Jmin": "10", "Jmax": "20",
				"S1": "12", "S2": "12", "I1": "<b 0x01>",
			},
			version: "1.5",
		},
		{
			name: "v2",
			fields: map[string]string{
				"Jc": "3", "Jmin": "10", "Jmax": "20",
				"S1": "12", "S2": "12", "S3": "12", "S4": "12",
				"H1": "100-120", "H2": "200-220", "H3": "300-320", "H4": "400-420",
			},
			version: "2",
		},
		{
			name: "v3.1",
			fields: map[string]string{
				"S1": "12", "S2": "12", "S3": "12", "S4": "12",
				"HeaderProtectionKey":    testKeyByte(0x99),
				"ContentPaddingAddition": "10-20",
			},
			version: "3.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseInput(selfHostedAWGVersionFixture(t, tt.fields))
			if err != nil {
				t.Fatal(err)
			}
			if got := parsed.Profile.AmneziaWG.ProtocolVersion; got != tt.version {
				t.Fatalf("AWG version = %q, want %q", got, tt.version)
			}
		})
	}
}

func TestParseSelfHostedRejectsOverlappingAWGHeaderRanges(t *testing.T) {
	input := selfHostedAWGVersionFixture(t, map[string]string{
		"S1": "12", "S2": "12", "S3": "12", "S4": "12",
		"H1": "100-200",
		"H2": "200-300",
	})
	if _, err := ParseInput(input); err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("overlapping AWG header range error = %v", err)
	}
}

func TestParseSelfHostedManagementAndEmptyKeys(t *testing.T) {
	fullAccess := encodeQtCompressedPayload(t, map[string]any{
		"hostName": "192.0.2.10",
		"userName": "root",
		"password": "test-only-secret",
		"port":     22,
		"containers": []any{map[string]any{
			"container": "amnezia-awg2",
			"awg":       map[string]any{},
		}},
	})
	if _, err := ParseInput(fullAccess); !errors.Is(err, ErrSelfHostedManagementKey) || strings.Contains(err.Error(), "test-only-secret") {
		t.Fatalf("full-access error = %v", err)
	}

	noClient := encodeQtCompressedPayload(t, map[string]any{
		"hostName": "192.0.2.10",
		"containers": []any{map[string]any{
			"container": "amnezia-awg2",
			"awg":       map[string]any{},
		}},
	})
	if _, err := ParseInput(noClient); !errors.Is(err, ErrStaticProfileUnavailable) {
		t.Fatalf("empty guest error = %v", err)
	}
}

func TestParseNativeAWGConfig(t *testing.T) {
	privateKey := testKeyByte(0x44)
	serverKey := testKeyByte(0x55)
	headerKey := testKeyByte(0x66)
	input := "\ufeff[Interface]\r\n" +
		"PrivateKey = " + privateKey + "\r\n" +
		"Address = 10.99.0.2/32\r\n" +
		"DNS = 9.9.9.9\r\n" +
		"ListenPort = 51821\r\n" +
		"FwMark = 0xca6c\r\n" +
		"S1 = 12\r\nS2 = 12\r\nS3 = 12\r\nS4 = 12\r\n" +
		"H1 = 100\r\nH2 = 200\r\nH3 = 300\r\nH4 = 400\r\n" +
		"HeaderProtectionKey = " + headerKey + "\r\n" +
		"ContentPaddingAddition = 10-20\r\n" +
		"PreUp = must-not-be-rendered\r\n\r\n" +
		"[Peer]\r\n" +
		"PublicKey = " + serverKey + "\r\n" +
		"AllowedIPs = 0.0.0.0/0, ::/0\r\n" +
		"Endpoint = vpn.example.test:443\r\n" +
		"PersistentKeepalive = 25-35\r\n"

	parsed, err := ParseInputBytes([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Format != InputFormatNativeConfig || parsed.Profile.AmneziaWG.ProtocolVersion != "3.1" {
		t.Fatalf("parsed native config = %#v", parsed)
	}
	if parsed.Profile.HostName != "vpn.example.test" {
		t.Fatalf("native hostname = %q", parsed.Profile.HostName)
	}
	if parsed.Profile.Interface.ListenPort != 51821 || parsed.Profile.Interface.FirewallMark != 0xca6c {
		t.Fatalf("native interface fields = %#v", parsed.Profile.Interface)
	}
	config, err := parsed.Profile.ConfigText()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(config, "PreUp") || !strings.Contains(config, "PersistentKeepalive = 25-35") ||
		!strings.Contains(config, "ListenPort = 51821") || !strings.Contains(config, "FwMark = 0xca6c") {
		t.Fatalf("safe native config projection is wrong:\n%s", config)
	}
}

func TestParseNativeConfigDoesNotRenderUnsafeDirectives(t *testing.T) {
	privateKey := testKeyByte(0xaa)
	serverKey := testKeyByte(0xbb)
	input := "[Interface]\n" +
		"PrivateKey = " + privateKey + "\n" +
		"Address = 10.99.0.2/32\n" +
		"DNS = 9.9.9.9\n" +
		"Table = off\n" +
		"PreUp = pre-up-secret\n" +
		"PostUp = post-up-secret\n" +
		"PreDown = pre-down-secret\n" +
		"PostDown = post-down-secret\n" +
		"UnknownDirective = unknown-secret\n\n" +
		"[Peer]\n" +
		"PublicKey = " + serverKey + "\n" +
		"AllowedIPs = 0.0.0.0/0\n" +
		"Endpoint = vpn.example.test:443\n"

	profile, err := ParseWireGuardConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	config, err := profile.ConfigText()
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"Table", "PreUp", "PostUp", "PreDown", "PostDown", "UnknownDirective", "-secret"} {
		if strings.Contains(config, forbidden) {
			t.Fatalf("safe config reproduced %q:\n%s", forbidden, config)
		}
	}
}

func TestParseInputClassifiesServiceAndUnsupportedInput(t *testing.T) {
	parsed, err := ParseInput(testActivationKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Format != InputFormatServiceKey || parsed.ActivationKey == nil || parsed.Profile != nil {
		t.Fatalf("service classification = %#v", parsed)
	}
	if _, err := ParseInput("client\ndev tun\n"); !errors.Is(err, ErrUnsupportedInput) {
		t.Fatalf("unsupported input error = %v", err)
	}

	_, publicPEM := newTestRSA(t)
	client := testClient(t, "http://127.0.0.1:1", publicPEM, []string{})
	session, err := client.StartImport(testActivationKey(t), NegotiationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if session.Format() != InputFormatServiceKey || session.State() != NegotiationReady {
		t.Fatalf("service import session: format=%q state=%d", session.Format(), session.State())
	}
	if strings.Contains(session.String(), "test-only-secret") {
		t.Fatal("service ImportSession.String leaked auth_data")
	}
}

func TestParseInputRejectsMalformedCompressedPayloads(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "malformed base64", input: "vpn://%%%"},
		{name: "truncated zlib", input: vpnScheme + base64.RawURLEncoding.EncodeToString([]byte{0, 0, 0, 100, 0x78, 0x9c})},
		{name: "decompression bomb size", input: vpnScheme + base64.RawURLEncoding.EncodeToString([]byte{0x7f, 0xff, 0xff, 0xff, 0x78, 0x9c})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseInput(tt.input); !errors.Is(err, ErrUnsupportedInput) {
				t.Fatalf("error = %v, want ErrUnsupportedInput", err)
			}
		})
	}
}

func TestParseSelfHostedRejectsUnsupportedProtocol(t *testing.T) {
	input := encodeQtCompressedPayload(t, map[string]any{
		"hostName": "192.0.2.10",
		"containers": []any{map[string]any{
			"container": "openvpn",
			"openvpn": map[string]any{
				"last_config": map[string]any{"client_priv_key": testKeyByte(0xcc)},
			},
		}},
	})
	if _, err := ParseInput(input); !errors.Is(err, ErrUnsupportedProtocol) {
		t.Fatalf("unsupported protocol error = %v", err)
	}
}

func TestParseNativeConfigRejectsMultiplePeers(t *testing.T) {
	privateKey := testKeyByte(0x77)
	serverKey := testKeyByte(0x88)
	input := "[Interface]\nPrivateKey = " + privateKey + "\nAddress = 10.0.0.2/32\n" +
		"[Peer]\nPublicKey = " + serverKey + "\nAllowedIPs = 10.0.0.0/24\nEndpoint = one.example:1\n" +
		"[Peer]\nPublicKey = " + serverKey + "\nAllowedIPs = 10.1.0.0/24\nEndpoint = two.example:2\n"
	if _, err := ParseWireGuardConfig(input); err == nil || !strings.Contains(err.Error(), "at most one [Peer]") {
		t.Fatalf("multiple-peer error = %v", err)
	}
}
