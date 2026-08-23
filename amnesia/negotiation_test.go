package amnezia

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type decodedGatewayRequest struct {
	payload map[string]any
	key     []byte
	iv      []byte
	body    []byte
	id      string
}

func newTestRSA(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func decodeGatewayRequest(t *testing.T, request *http.Request, privateKey *rsa.PrivateKey) decodedGatewayRequest {
	t.Helper()
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]string
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	encryptedKey, err := base64.StdEncoding.DecodeString(envelope["key_payload"])
	if err != nil {
		t.Fatal(err)
	}
	keyJSON, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedKey)
	if err != nil {
		t.Fatal(err)
	}
	var keyPayload map[string]string
	if err := json.Unmarshal(keyJSON, &keyPayload); err != nil {
		t.Fatal(err)
	}
	key, _ := base64.StdEncoding.DecodeString(keyPayload["aes_key"])
	iv, _ := base64.StdEncoding.DecodeString(keyPayload["aes_iv"])
	encryptedAPI, _ := base64.StdEncoding.DecodeString(envelope["api_payload"])
	plain, err := decryptAES256CBC(encryptedAPI, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(plain, &payload); err != nil {
		t.Fatal(err)
	}
	return decodedGatewayRequest{payload: payload, key: key, iv: iv, body: body, id: request.Header.Get("X-Client-Request-ID")}
}

func writeGatewayResponse(t *testing.T, writer http.ResponseWriter, request decodedGatewayRequest, status int, object any) {
	t.Helper()
	plain, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := encryptAES256CBC(plain, request.key, request.iv)
	if err != nil {
		t.Fatal(err)
	}
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.WriteHeader(status)
	if _, err := writer.Write(encrypted); err != nil {
		t.Error(err)
	}
}

func testActivationKey(t *testing.T) string {
	t.Helper()
	key, err := EncodeActivationKey(ActivationKey{
		Name:          "Test",
		ConfigVersion: 2,
		APIConfig: ActivationAPIConfig{
			ServiceType:     "amnezia-free",
			ServiceProtocol: "awg",
			UserCountryCode: "xx",
		},
		AuthData: json.RawMessage(`{"api_key":"test-only-secret"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testWireGuardKeypair(t *testing.T, marker byte) (string, string) {
	t.Helper()
	privateBytes := make([]byte, 32)
	privateBytes[0] = marker
	privateKey := base64.StdEncoding.EncodeToString(privateBytes)
	publicKey, err := wireGuardPublicFromPrivate(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey, publicKey
}

func testGatewayConfig(t *testing.T, clientPublicKey string) string {
	t.Helper()
	serverKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	pskBytes := make([]byte, 32)
	pskBytes[0] = 1
	psk := base64.StdEncoding.EncodeToString(pskBytes)
	lastConfig, err := json.Marshal(map[string]any{
		"hostName":               "vpn.example.test",
		"port":                   443,
		"client_ip":              "10.9.0.2",
		"client_priv_key":        "$WIREGUARD_CLIENT_PRIVATE_KEY",
		"client_pub_key":         clientPublicKey,
		"server_pub_key":         serverKey,
		"psk_key":                psk,
		"allowed_ips":            []string{"0.0.0.0/0", "::/0"},
		"persistent_keep_alive":  "25-35",
		"mtu":                    "1280",
		"Jc":                     "3",
		"Jmin":                   "10",
		"Jmax":                   "30",
		"S1":                     "12",
		"S2":                     "12",
		"S3":                     "12",
		"S4":                     "12",
		"H1":                     "100-200",
		"H2":                     "300-400",
		"H3":                     "500-600",
		"H4":                     "700-800",
		"HeaderProtectionKey":    serverKey,
		"ContentPaddingAddition": "10-100",
		"RekeyAfterTime":         "100-120",
		"RekeyTimeout":           "3-7",
		"RejectAfterTime":        "150-180",
		"KeepaliveTimeout":       "5-15",
		"MaxHandshakeAttempts":   "15-20",
		"RandomTrailers":         "on",
		"DisableCookies":         "on",
	})
	if err != nil {
		t.Fatal(err)
	}
	config := map[string]any{
		"name":           "Negotiated test",
		"config_version": 2,
		"hostName":       "vpn.example.test",
		"dns1":           "1.1.1.1",
		"send_payload": []any{map[string]any{
			"endpoint": "vpn.example.test:9", "protocol": "udp", "timeout_ms": 100,
			"payload": "<b 0x01>", "expected_response": "",
		}},
		"containers": []any{map[string]any{
			"container": "amnezia-awg2",
			"awg":       map[string]any{"last_config": string(lastConfig)},
		}},
	}
	encoded, err := EncodeVPNPayload(config)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func testClient(t *testing.T, serverURL string, publicPEM []byte, static []string) *Client {
	t.Helper()
	client, err := NewClient(ClientOptions{
		HTTPClient:          explicitTestHTTPClient(),
		GatewayURL:          serverURL,
		GatewayPublicKeyPEM: publicPEM,
		PrimaryS3URLs:       []string{},
		FallbackS3URLs:      []string{},
		StaticProxyURLs:     static,
		DisableS3Discovery:  true,
		Metadata: ClientMetadata{
			OSVersion: "test", AppVersion: "5.0.1.5", CLIName: "AmneziaVPN",
			Distribution: "test", Language: "en", InstallationUUID: "00000000-0000-4000-8000-000000000001",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestNegotiationPausesAndResumesCaptchaWithSameKeypair(t *testing.T) {
	privateKey, publicPEM := newTestRSA(t)
	var mu sync.Mutex
	var requestCount int
	var firstPublicKey string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		decoded := decodeGatewayRequest(t, request, privateKey)
		mu.Lock()
		defer mu.Unlock()
		requestCount++
		publicKey, _ := decoded.payload["public_key"].(string)
		if requestCount == 1 {
			firstPublicKey = publicKey
			writeGatewayResponse(t, writer, decoded, http.StatusPaymentRequired, map[string]any{
				"http_status": 402, "message": "rate_limit_exceeded", "captcha_id": "captcha-1",
				"captcha_image": "aW1hZ2U=", "hint": "digits",
			})
			return
		}
		if publicKey != firstPublicKey {
			t.Errorf("WireGuard public key changed across CAPTCHA: %q != %q", publicKey, firstPublicKey)
		}
		if decoded.payload["captcha_id"] != "captcha-1" || decoded.payload["captcha_solution"] != "123" {
			t.Errorf("CAPTCHA retry fields = %#v", decoded.payload)
		}
		writeGatewayResponse(t, writer, decoded, http.StatusOK, map[string]any{
			"config": testGatewayConfig(t, publicKey), "service_info": map[string]any{"ok": true},
		})
	}))
	defer server.Close()

	client := testClient(t, server.URL, publicPEM, []string{})
	negotiation, err := client.StartImport(testActivationKey(t), NegotiationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if negotiation.Format() != InputFormatServiceKey {
		t.Fatalf("unified import format = %q", negotiation.Format())
	}
	step, err := negotiation.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if step.State != NegotiationAwaitingInteraction || step.Interaction == nil || step.Interaction.Kind != InteractionCaptcha {
		t.Fatalf("first step = %#v", step)
	}
	if step.Interaction.Captcha == nil || step.Interaction.Captcha.Reason != ErrorCaptchaRequired {
		t.Fatalf("CAPTCHA reason = %#v, want %q", step.Interaction.Captcha, ErrorCaptchaRequired)
	}
	step, err = negotiation.Resume(context.Background(), InteractionResponse{CaptchaSolution: "１２ 3a"})
	if err != nil {
		t.Fatal(err)
	}
	if step.State != NegotiationComplete || step.Profile == nil {
		t.Fatalf("completed step = %#v", step)
	}
	if step.Profile.AmneziaWG.ProtocolVersion != "3.1" || step.Profile.Peer.PersistentKeepalive.String() != "25-35" {
		t.Fatalf("parsed AWG profile = %#v", step.Profile.AmneziaWG)
	}
	config, err := step.Profile.RenderConfig()
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"HeaderProtectionKey = ", "ContentPaddingAddition = 10-100", "PersistentKeepalive = 25-35"} {
		if !strings.Contains(config, expected) {
			t.Fatalf("rendered config missing %q:\n%s", expected, config)
		}
	}
	if strings.Contains(config, "$WIREGUARD_CLIENT_PRIVATE_KEY") {
		t.Fatal("private-key placeholder was not substituted")
	}
}

func TestNegotiationUsesCallerPublicKeyWithoutPrivateKey(t *testing.T) {
	privateKey, publicKey := testWireGuardKeypair(t, 0x42)
	gatewayPrivateKey, publicPEM := newTestRSA(t)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		decoded := decodeGatewayRequest(t, request, gatewayPrivateKey)
		if got, _ := decoded.payload["public_key"].(string); got != publicKey {
			t.Errorf("request public key = %q, want caller key %q", got, publicKey)
		}
		writeGatewayResponse(t, writer, decoded, http.StatusOK, map[string]any{
			"config": testGatewayConfig(t, publicKey),
		})
	}))
	defer server.Close()

	client := testClient(t, server.URL, publicPEM, []string{})
	profile, err := client.AcquireNonInteractive(context.Background(), testActivationKey(t), NegotiationOptions{
		WireGuardPublicKey: publicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if profile.Interface.PublicKey != publicKey {
		t.Fatalf("profile public key = %q, want %q", profile.Interface.PublicKey, publicKey)
	}
	if profile.Interface.PrivateKey != "" {
		t.Fatal("profile unexpectedly contains a private key")
	}
	if _, err := profile.ConfigText(); !errors.Is(err, ErrWireGuardPrivateKeyRequired) {
		t.Fatalf("ConfigText error = %v, want ErrWireGuardPrivateKeyRequired", err)
	}

	// Supplying the matching key for config rendering is deliberately the
	// caller's responsibility; structured backends can keep it external.
	profile.Interface.PrivateKey = privateKey
	config, err := profile.ConfigText()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(config, "PrivateKey = "+privateKey) {
		t.Fatal("rendered config does not contain the caller-supplied private key")
	}
}

func TestNegotiationRejectsInvalidCallerPublicKey(t *testing.T) {
	_, publicPEM := newTestRSA(t)
	client := testClient(t, "https://gateway.example.test", publicPEM, []string{})
	_, err := client.Start(testActivationKey(t), NegotiationOptions{WireGuardPublicKey: "not-a-wireguard-key"})
	if err == nil || !strings.Contains(err.Error(), "invalid client public key") {
		t.Fatalf("invalid public key error = %v", err)
	}
}

func TestNonInteractiveModeFailsOnCaptcha(t *testing.T) {
	privateKey, publicPEM := newTestRSA(t)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		decoded := decodeGatewayRequest(t, request, privateKey)
		writeGatewayResponse(t, writer, decoded, http.StatusPaymentRequired, map[string]any{
			"http_status": 402, "message": "rate_limit_exceeded", "captcha_id": "captcha-1", "captcha_image": "aW1hZ2U=",
		})
	}))
	defer server.Close()
	client := testClient(t, server.URL, publicPEM, []string{})
	_, err := client.AcquireNonInteractive(context.Background(), testActivationKey(t), NegotiationOptions{})
	if !errors.Is(err, ErrInteractionRequired) {
		t.Fatalf("error = %v, want ErrInteractionRequired", err)
	}
}

func TestAPIErrorStringRedactsServerMessage(t *testing.T) {
	err := (&APIError{Code: ErrorConfigDownload, HTTPStatus: 400, Message: "echoed-secret"}).Error()
	if strings.Contains(err, "echoed-secret") {
		t.Fatal("APIError.Error leaked untrusted server message")
	}
}

func TestNonInteractiveModeRecognizesPlaintextCaptchaError(t *testing.T) {
	_, publicPEM := newTestRSA(t)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusPaymentRequired)
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"http_status": 402, "message": "rate_limit_exceeded",
			"captcha_id": "captcha-plaintext", "captcha_image": "aW1hZ2U=",
		})
	}))
	defer server.Close()
	client := testClient(t, server.URL, publicPEM, []string{})
	_, err := client.AcquireNonInteractive(context.Background(), testActivationKey(t), NegotiationOptions{})
	if !errors.Is(err, ErrInteractionRequired) {
		t.Fatalf("plaintext CAPTCHA error = %v, want ErrInteractionRequired", err)
	}
}

func TestGatewayRejectsPlaintextSuccess(t *testing.T) {
	_, publicPEM := newTestRSA(t)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"config":"` + testGatewayConfig(t, "") + `"}`))
	}))
	defer server.Close()

	client := testClient(t, server.URL, publicPEM, []string{})
	_, err := client.AcquireNonInteractive(context.Background(), testActivationKey(t), NegotiationOptions{})
	var protocolErr *ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Op != "decrypt gateway response" {
		t.Fatalf("plaintext success error = %v, want decrypt ProtocolError", err)
	}
}

func TestGatewayRejectsMalformedEncryptedProfile(t *testing.T) {
	privateKey, publicPEM := newTestRSA(t)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		decoded := decodeGatewayRequest(t, request, privateKey)
		writeGatewayResponse(t, writer, decoded, http.StatusOK, map[string]any{"config": "vpn://not-valid"})
	}))
	defer server.Close()

	client := testClient(t, server.URL, publicPEM, []string{})
	_, err := client.AcquireNonInteractive(context.Background(), testActivationKey(t), NegotiationOptions{})
	var protocolErr *ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Op != "decode gateway profile" {
		t.Fatalf("malformed encrypted profile error = %v, want decode ProtocolError", err)
	}
}

func TestGatewayMalformedRefreshDoesNotReplaceAcceptedProfile(t *testing.T) {
	callerPrivateKey, callerPublicKey := testWireGuardKeypair(t, 0x51)
	gatewayPrivateKey, publicPEM := newTestRSA(t)
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		decoded := decodeGatewayRequest(t, request, gatewayPrivateKey)
		requestCount++
		if got, _ := decoded.payload["public_key"].(string); got != callerPublicKey {
			t.Errorf("request public key = %q, want %q", got, callerPublicKey)
		}
		switch requestCount {
		case 1:
			writeGatewayResponse(t, writer, decoded, http.StatusOK, map[string]any{
				"config": testGatewayConfig(t, callerPublicKey),
			})
		case 2:
			writeGatewayResponse(t, writer, decoded, http.StatusOK, map[string]any{
				"config": "vpn://not-valid",
			})
		default:
			t.Fatalf("unexpected request %d", requestCount)
		}
	}))
	defer server.Close()

	client := testClient(t, server.URL, publicPEM, []string{})
	cachedProfile, err := client.AcquireNonInteractive(context.Background(), testActivationKey(t), NegotiationOptions{
		WireGuardPublicKey: callerPublicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	cachedProfile.Interface.PrivateKey = callerPrivateKey
	cachedConfig, err := cachedProfile.ConfigText()
	if err != nil {
		t.Fatal(err)
	}
	cachedEndpoint := cachedProfile.Peer.Endpoint
	cachedRawConfig := string(cachedProfile.RawConfig)

	replacement, err := client.AcquireNonInteractive(context.Background(), testActivationKey(t), NegotiationOptions{
		WireGuardPublicKey: callerPublicKey,
	})
	var protocolErr *ProtocolError
	if replacement != nil || !errors.As(err, &protocolErr) || protocolErr.Op != "decode gateway profile" {
		t.Fatalf("malformed refresh returned profile=%#v err=%v, want nil profile and decode ProtocolError", replacement, err)
	}
	if cachedProfile.Peer.Endpoint != cachedEndpoint || string(cachedProfile.RawConfig) != cachedRawConfig {
		t.Fatal("cached profile changed after malformed refresh")
	}
	if config, err := cachedProfile.ConfigText(); err != nil || config != cachedConfig {
		t.Fatalf("cached rendered config changed after malformed refresh: changed=%t err=%v", config != cachedConfig, err)
	}
}

func TestNegotiationRetryRetainsSelectedPublicKey(t *testing.T) {
	privateKey, publicPEM := newTestRSA(t)
	var mu sync.Mutex
	var requestCount int
	var firstPublicKey string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		decoded := decodeGatewayRequest(t, request, privateKey)
		mu.Lock()
		defer mu.Unlock()
		requestCount++
		publicKey, _ := decoded.payload["public_key"].(string)
		if requestCount == 1 {
			firstPublicKey = publicKey
			http.Error(writer, "temporary failure", http.StatusBadGateway)
			return
		}
		if publicKey != firstPublicKey {
			t.Errorf("WireGuard public key changed on retry: %q != %q", publicKey, firstPublicKey)
		}
		writeGatewayResponse(t, writer, decoded, http.StatusOK, map[string]any{
			"config": testGatewayConfig(t, publicKey),
		})
	}))
	defer server.Close()

	client := testClient(t, server.URL, publicPEM, []string{})
	negotiation, err := client.Start(testActivationKey(t), NegotiationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	step, err := negotiation.Next(context.Background())
	if err == nil || step.State != NegotiationReady || negotiation.State() != NegotiationReady {
		t.Fatalf("first retryable step = %#v, err=%v", step, err)
	}
	step, err = negotiation.Next(context.Background())
	if err != nil || step.State != NegotiationComplete || step.Profile == nil {
		t.Fatalf("retry step = %#v, err=%v", step, err)
	}
}

func TestNegotiationCaptchaRefreshKeepsPreviousChallengeMaterial(t *testing.T) {
	privateKey, publicPEM := newTestRSA(t)
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		decoded := decodeGatewayRequest(t, request, privateKey)
		requestCount++
		switch requestCount {
		case 1:
			writeGatewayResponse(t, writer, decoded, http.StatusPaymentRequired, map[string]any{
				"http_status": 402, "message": "rate_limit_exceeded", "captcha_id": "captcha-1",
				"captcha_image": "aW1hZ2UtMQ==", "hint": "digits",
			})
		case 2:
			writeGatewayResponse(t, writer, decoded, http.StatusPaymentRequired, map[string]any{
				"http_status": 402, "message": "refresh_captcha",
			})
		default:
			t.Fatalf("unexpected request %d", requestCount)
		}
	}))
	defer server.Close()

	client := testClient(t, server.URL, publicPEM, []string{})
	negotiation, err := client.Start(testActivationKey(t), NegotiationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	step, err := negotiation.Next(context.Background())
	if err != nil || step.Interaction == nil || step.Interaction.Captcha == nil {
		t.Fatalf("initial CAPTCHA step = %#v, err=%v", step, err)
	}
	step, err = negotiation.Resume(context.Background(), InteractionResponse{CaptchaSolution: "123"})
	if err != nil || step.Interaction == nil || step.Interaction.Captcha == nil {
		t.Fatalf("refreshed CAPTCHA step = %#v, err=%v", step, err)
	}
	if got := step.Interaction.Captcha; got.ID != "captcha-1" || got.ImageBase64 != "aW1hZ2UtMQ==" || got.Hint != "digits" || got.Reason != ErrorCaptchaRefresh {
		t.Fatalf("refreshed CAPTCHA = %#v", got)
	}
}

func TestGatewayProxyFallbackReusesEncryptedRequest(t *testing.T) {
	privateKey, publicPEM := newTestRSA(t)
	var directBody, proxyBody []byte
	var directID, proxyID string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/blocked/v1/config":
			directBody, _ = io.ReadAll(request.Body)
			directID = request.Header.Get("X-Client-Request-ID")
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write([]byte("<!doctype html>blocked"))
		case "/lmbd-health":
			writer.WriteHeader(http.StatusNoContent)
		case "/v1/config":
			decoded := decodeGatewayRequest(t, request, privateKey)
			proxyBody = decoded.body
			proxyID = decoded.id
			publicKey, _ := decoded.payload["public_key"].(string)
			writeGatewayResponse(t, writer, decoded, http.StatusOK, map[string]any{"config": testGatewayConfig(t, publicKey)})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	client := testClient(t, server.URL+"/blocked", publicPEM, []string{server.URL})
	profile, err := client.AcquireNonInteractive(context.Background(), testActivationKey(t), NegotiationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if profile == nil || !json.Valid(profile.RawConfig) {
		t.Fatal("proxy fallback returned no profile")
	}
	if string(directBody) != string(proxyBody) || directID == "" || directID != proxyID {
		t.Fatal("proxy fallback did not reuse encrypted body and request ID")
	}
}
