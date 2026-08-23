//go:build linux && e2e

// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 AsciiMoth

package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	amnezia "github.com/asciimoth/wgo/amnesia"
)

const vpnScheme = "vpn://"

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "amnesia-e2e-tool: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("missing command")
	}
	switch args[0] {
	case "make-key":
		return makeKey(args[1:], stdout)
	case "make-activation-key":
		return makeActivationKey(args[1:], stdout)
	case "make-gateway-profile":
		return makeGatewayProfile(args[1:], stdout)
	case "make-gateway-rsa":
		return makeGatewayRSA(args[1:], stdout)
	case "render-negotiated-uapi":
		return renderNegotiatedUAPI(args[1:], stdin, stdout)
	case "render-uapi":
		return renderUAPI(args[1:], stdin, stdout)
	case "exercise-gateway-edge-cases":
		return exerciseGatewayEdgeCases(args[1:], stdout)
	case "serve-gateway":
		return serveGateway(args[1:])
	case "serve-selfhost":
		return serveHTTP(args[1:], true)
	case "serve-http":
		return serveHTTP(args[1:], false)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func makeActivationKey(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("make-activation-key", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	serviceType := flags.String("service-type", "wgo-e2e", "service type")
	country := flags.String("country", "xx", "user country code")
	if err := flags.Parse(args); err != nil {
		return err
	}
	key, err := amnezia.EncodeActivationKey(amnezia.ActivationKey{
		Name:          "wgo mock gateway e2e",
		ConfigVersion: 2,
		APIConfig: amnezia.ActivationAPIConfig{
			ServiceType:     *serviceType,
			ServiceProtocol: "awg",
			UserCountryCode: *country,
		},
		AuthData: json.RawMessage(`{"api_key":"wgo-e2e-secret"}`),
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, key)
	return err
}

func makeKey(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("make-key", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var cfg fixtureConfig
	flags.StringVar(&cfg.format, "format", "", "output format: vpn or conf")
	flags.StringVar(&cfg.protocol, "protocol", "", "protocol: wireguard or awg")
	flags.StringVar(&cfg.endpoint, "endpoint", "", "server endpoint")
	flags.StringVar(&cfg.clientPrivateKey, "client-private-key", "", "client private key in base64")
	flags.StringVar(&cfg.clientPublicKey, "client-public-key", "", "client public key in base64")
	flags.StringVar(&cfg.serverPublicKey, "server-public-key", "", "server public key in base64")
	flags.StringVar(&cfg.clientAddress, "client-address", "", "client tunnel address")
	flags.StringVar(&cfg.allowedIP, "allowed-ip", "", "peer allowed IP")
	flags.StringVar(&cfg.presharedKey, "preshared-key", "", "optional preshared key in base64")
	flags.StringVar(&cfg.headerProtectionKeyHex, "header-protection-key", "", "AWG v3.1 header protection key in hex")
	flags.IntVar(&cfg.mtu, "mtu", 1420, "MTU")
	flags.UintVar(&cfg.keepalive, "keepalive", 0, "persistent keepalive seconds")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := cfg.validate(); err != nil {
		return err
	}

	native, client, protocol, err := cfg.profileParts()
	if err != nil {
		return err
	}
	switch cfg.format {
	case "conf":
		_, err = io.WriteString(stdout, native)
		return err
	case "vpn":
		lastConfig, err := json.Marshal(client)
		if err != nil {
			return err
		}
		protocol["last_config"] = string(lastConfig)
		protocolKey := cfg.protocol
		containerName := "wireguard"
		if cfg.protocol == "awg" {
			protocolKey = "awg"
			containerName = "amnezia-awg2"
		}
		host, _, _ := net.SplitHostPort(cfg.endpoint)
		document := map[string]any{
			"description":      "wgo self-hosted e2e",
			"hostName":         host,
			"defaultContainer": containerName,
			"dns1":             "1.1.1.1",
			"containers": []any{map[string]any{
				"container": containerName,
				protocolKey: protocol,
			}},
		}
		key, err := encodeQtCompressedPayload(document)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, key)
		return err
	default:
		return fmt.Errorf("unsupported format %q", cfg.format)
	}
}

func makeGatewayProfile(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("make-gateway-profile", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var cfg fixtureConfig
	flags.StringVar(&cfg.endpoint, "endpoint", "", "server endpoint")
	flags.StringVar(&cfg.clientPublicKey, "client-public-key", "", "client public key in base64")
	flags.StringVar(&cfg.serverPublicKey, "server-public-key", "", "server public key in base64")
	flags.StringVar(&cfg.clientAddress, "client-address", "", "client tunnel address")
	flags.StringVar(&cfg.allowedIP, "allowed-ip", "", "peer allowed IP")
	flags.StringVar(&cfg.presharedKey, "preshared-key", "", "optional preshared key in base64")
	flags.StringVar(&cfg.headerProtectionKeyHex, "header-protection-key", "", "AWG v3.1 header protection key in hex")
	flags.IntVar(&cfg.mtu, "mtu", 1420, "MTU")
	flags.UintVar(&cfg.keepalive, "keepalive", 0, "persistent keepalive seconds")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg.protocol = "awg"
	if _, err := decodeBase64Key(cfg.clientPublicKey); err != nil {
		return fmt.Errorf("client-public-key: %w", err)
	}
	if _, err := decodeBase64Key(cfg.serverPublicKey); err != nil {
		return fmt.Errorf("server-public-key: %w", err)
	}
	if cfg.presharedKey != "" {
		if _, err := decodeBase64Key(cfg.presharedKey); err != nil {
			return fmt.Errorf("preshared-key: %w", err)
		}
	}
	if _, err := decodeHexKey(cfg.headerProtectionKeyHex); err != nil {
		return fmt.Errorf("header-protection-key: %w", err)
	}
	if _, _, err := net.SplitHostPort(cfg.endpoint); err != nil {
		return fmt.Errorf("endpoint: %w", err)
	}
	if strings.TrimSpace(cfg.clientAddress) == "" {
		return errors.New("missing client-address")
	}
	if strings.TrimSpace(cfg.allowedIP) == "" {
		return errors.New("missing allowed-ip")
	}

	headerKey, err := hexKeyToBase64(cfg.headerProtectionKeyHex)
	if err != nil {
		return err
	}
	client := map[string]any{
		"hostName":               hostFromEndpoint(cfg.endpoint),
		"port":                   portFromEndpoint(cfg.endpoint),
		"client_ip":              cfg.clientAddress,
		"client_pub_key":         cfg.clientPublicKey,
		"server_pub_key":         cfg.serverPublicKey,
		"allowed_ips":            []string{cfg.allowedIP},
		"mtu":                    strconv.Itoa(cfg.mtu),
		"Jc":                     "2",
		"Jmin":                   "11",
		"Jmax":                   "23",
		"S1":                     "12",
		"S2":                     "12",
		"S3":                     "12",
		"S4":                     "12",
		"H1":                     "6111",
		"H2":                     "6222",
		"H3":                     "6333",
		"H4":                     "6444",
		"I1":                     "<b 0xaa55><rc 3><rd 2><t>",
		"I2":                     "<r 5>",
		"I3":                     "<rd 4>",
		"I4":                     "<rc 6>",
		"I5":                     "<b 0x01020304>",
		"HeaderProtectionKey":    headerKey,
		"ContentPaddingAddition": "4-16",
		"RekeyAfterTime":         "90-120",
		"RekeyTimeout":           "5-8",
		"RejectAfterTime":        "180-220",
		"KeepaliveTimeout":       "10-15",
		"MaxHandshakeAttempts":   "3-5",
		"RandomTrailers":         "true",
		"DisableCookies":         "true",
		"protocol_version":       "3.1",
	}
	if cfg.presharedKey != "" {
		client["psk_key"] = cfg.presharedKey
	}
	if cfg.keepalive > 0 {
		client["persistent_keep_alive"] = strconv.FormatUint(uint64(cfg.keepalive), 10)
	}
	lastConfig, err := json.Marshal(client)
	if err != nil {
		return err
	}
	protocol := make(map[string]any, len(client)+1)
	for key, value := range client {
		protocol[key] = value
	}
	protocol["last_config"] = string(lastConfig)
	document := map[string]any{
		"name":           "wgo mock gateway e2e",
		"config_version": 2,
		"hostName":       hostFromEndpoint(cfg.endpoint),
		"dns1":           "1.1.1.1",
		"containers": []any{map[string]any{
			"container": "amnezia-awg2",
			"awg":       protocol,
		}},
	}
	key, err := amnezia.EncodeVPNPayload(document)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, key)
	return err
}

func makeGatewayRSA(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("make-gateway-rsa", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	privatePath := flags.String("private-file", "", "private key output path")
	publicPath := flags.String("public-file", "", "public key output path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *privatePath == "" || *publicPath == "" {
		return errors.New("missing -private-file or -public-file")
	}
	key, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		return err
	}
	privatePEM := pemBlock("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	publicPEM := pemBlock("PUBLIC KEY", publicDER)
	if err := os.WriteFile(*privatePath, privatePEM, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(*publicPath, publicPEM, 0644); err != nil {
		return err
	}
	_, err = stdout.Write(publicPEM)
	return err
}

type fixtureConfig struct {
	format                 string
	protocol               string
	endpoint               string
	clientPrivateKey       string
	clientPublicKey        string
	serverPublicKey        string
	clientAddress          string
	allowedIP              string
	presharedKey           string
	headerProtectionKeyHex string
	mtu                    int
	keepalive              uint
}

func (cfg fixtureConfig) validate() error {
	if cfg.format != "vpn" && cfg.format != "conf" {
		return fmt.Errorf("format must be vpn or conf, got %q", cfg.format)
	}
	if cfg.protocol != "wireguard" && cfg.protocol != "awg" {
		return fmt.Errorf("protocol must be wireguard or awg, got %q", cfg.protocol)
	}
	for name, value := range map[string]string{
		"client-private-key": cfg.clientPrivateKey,
		"client-public-key":  cfg.clientPublicKey,
		"server-public-key":  cfg.serverPublicKey,
	} {
		if _, err := decodeBase64Key(value); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if cfg.presharedKey != "" {
		if _, err := decodeBase64Key(cfg.presharedKey); err != nil {
			return fmt.Errorf("preshared-key: %w", err)
		}
	}
	if cfg.protocol == "awg" {
		if _, err := decodeHexKey(cfg.headerProtectionKeyHex); err != nil {
			return fmt.Errorf("header-protection-key: %w", err)
		}
	}
	if _, _, err := net.SplitHostPort(cfg.endpoint); err != nil {
		return fmt.Errorf("endpoint: %w", err)
	}
	if strings.TrimSpace(cfg.clientAddress) == "" {
		return errors.New("missing client-address")
	}
	if strings.TrimSpace(cfg.allowedIP) == "" {
		return errors.New("missing allowed-ip")
	}
	return nil
}

func (cfg fixtureConfig) profileParts() (string, map[string]any, map[string]any, error) {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	writeConfigLine(&b, "PrivateKey", cfg.clientPrivateKey)
	writeConfigLine(&b, "Address", cfg.clientAddress)
	if cfg.mtu > 0 {
		writeConfigLine(&b, "MTU", strconv.Itoa(cfg.mtu))
	}

	client := map[string]any{
		"config":          "",
		"hostName":        hostFromEndpoint(cfg.endpoint),
		"port":            portFromEndpoint(cfg.endpoint),
		"client_ip":       cfg.clientAddress,
		"client_priv_key": cfg.clientPrivateKey,
		"client_pub_key":  cfg.clientPublicKey,
		"server_pub_key":  cfg.serverPublicKey,
		"allowed_ips":     []string{cfg.allowedIP},
		"mtu":             strconv.Itoa(cfg.mtu),
	}
	protocol := map[string]any{}
	if cfg.protocol == "awg" {
		headerKey, err := hexKeyToBase64(cfg.headerProtectionKeyHex)
		if err != nil {
			return "", nil, nil, err
		}
		awg := map[string]string{
			"Jc": "2", "Jmin": "11", "Jmax": "23",
			"S1": "12", "S2": "12", "S3": "12", "S4": "12",
			"H1": "6111", "H2": "6222", "H3": "6333", "H4": "6444",
			"I1":                     "<b 0xaa55><rc 3><rd 2><t>",
			"I2":                     "<r 5>",
			"I3":                     "<rd 4>",
			"I4":                     "<rc 6>",
			"I5":                     "<b 0x01020304>",
			"HeaderProtectionKey":    headerKey,
			"ContentPaddingAddition": "4-16",
			"RekeyAfterTime":         "90-120",
			"RekeyTimeout":           "5-8",
			"RejectAfterTime":        "180-220",
			"KeepaliveTimeout":       "10-15",
			"MaxHandshakeAttempts":   "3-5",
			"RandomTrailers":         "true",
			"DisableCookies":         "true",
			"protocol_version":       "3.1",
		}
		for key, value := range awg {
			client[key] = value
			protocol[key] = value
			if key != "protocol_version" {
				writeConfigLine(&b, key, value)
			}
		}
	}

	b.WriteString("\n[Peer]\n")
	writeConfigLine(&b, "PublicKey", cfg.serverPublicKey)
	if cfg.presharedKey != "" {
		writeConfigLine(&b, "PresharedKey", cfg.presharedKey)
		client["psk_key"] = cfg.presharedKey
	}
	writeConfigLine(&b, "AllowedIPs", cfg.allowedIP)
	writeConfigLine(&b, "Endpoint", cfg.endpoint)
	if cfg.keepalive > 0 {
		value := strconv.FormatUint(uint64(cfg.keepalive), 10)
		writeConfigLine(&b, "PersistentKeepalive", value)
		client["persistent_keep_alive"] = value
	}

	native := b.String()
	client["config"] = native
	return native, client, protocol, nil
}

func renderUAPI(args []string, stdin io.Reader, stdout io.Writer) error {
	flags := flag.NewFlagSet("render-uapi", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	inputPath := flags.String("input", "-", "input file, or - for stdin")
	if err := flags.Parse(args); err != nil {
		return err
	}

	input, err := readInput(*inputPath, stdin)
	if err != nil {
		return err
	}
	parsed, err := amnezia.ParseInput(string(input))
	if err != nil {
		return err
	}
	if parsed.Profile == nil {
		return fmt.Errorf("input format %s does not contain a static profile", parsed.Format)
	}
	config, err := parsed.Profile.ConfigText()
	if err != nil {
		return err
	}
	payload, err := configToUAPI(config)
	if err != nil {
		return err
	}
	_, err = io.WriteString(stdout, payload)
	return err
}

func renderNegotiatedUAPI(args []string, stdin io.Reader, stdout io.Writer) error {
	flags := flag.NewFlagSet("render-negotiated-uapi", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	inputPath := flags.String("input", "-", "input file, or - for stdin")
	gatewayURL := flags.String("gateway-url", "", "mock gateway URL")
	publicKeyPath := flags.String("gateway-public-key", "", "gateway public key PEM path")
	clientPrivateKey := flags.String("client-private-key", "", "client WireGuard private key in base64")
	timeout := flags.Duration("timeout", 10*time.Second, "negotiation timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	input, err := readInput(*inputPath, stdin)
	if err != nil {
		return err
	}
	publicPEM, err := os.ReadFile(*publicKeyPath)
	if err != nil {
		return err
	}
	clientPublicKey, err := wireGuardPublicFromPrivate(*clientPrivateKey)
	if err != nil {
		return err
	}
	client, err := newGatewayClient(*gatewayURL, publicPEM)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	profile, err := client.ImportNonInteractive(ctx, string(input), amnezia.NegotiationOptions{
		WireGuardPublicKey: clientPublicKey,
	})
	if err != nil {
		return err
	}
	profile.Interface.PrivateKey = *clientPrivateKey
	config, err := profile.ConfigText()
	if err != nil {
		return err
	}
	payload, err := configToUAPI(config)
	if err != nil {
		return err
	}
	_, err = io.WriteString(stdout, payload)
	return err
}

func exerciseGatewayEdgeCases(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("exercise-gateway-edge-cases", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	gatewayURL := flags.String("gateway-url", "", "mock gateway URL")
	publicKeyPath := flags.String("gateway-public-key", "", "gateway public key PEM path")
	clientPrivateKey := flags.String("client-private-key", "", "client WireGuard private key in base64")
	timeout := flags.Duration("timeout", 10*time.Second, "test timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	publicPEM, err := os.ReadFile(*publicKeyPath)
	if err != nil {
		return err
	}
	clientPublicKey, err := wireGuardPublicFromPrivate(*clientPrivateKey)
	if err != nil {
		return err
	}
	client, err := newGatewayClient(*gatewayURL, publicPEM)
	if err != nil {
		return err
	}
	activationKey, err := e2eActivationKey()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if err := exerciseCaptchaFlow(ctx, client, activationKey, clientPublicKey); err != nil {
		return err
	}
	if err := exerciseCaptchaRefresh(ctx, client, activationKey, clientPublicKey); err != nil {
		return err
	}
	for _, test := range []struct {
		name string
		code amnezia.ErrorCode
	}{
		{"rate-limit-429", amnezia.ErrorRateLimited},
		{"trial-used-409", amnezia.ErrorTrialAlreadyUsed},
		{"subscription-expired-422", amnezia.ErrorSubscriptionExpired},
		{"subscription-inactive-402", amnezia.ErrorSubscriptionInactive},
		{"update-required-501", amnezia.ErrorUpdateRequired},
		{"not-found-404", amnezia.ErrorNotFound},
	} {
		_, err := client.AcquireNonInteractive(ctx, activationKey, amnezia.NegotiationOptions{
			WireGuardPublicKey: clientPublicKey,
			ExtraPayload:       map[string]any{"e2e_case": test.name},
		})
		if err := expectAPIError(err, test.code); err != nil {
			return fmt.Errorf("%s: %w", test.name, err)
		}
	}
	_, err = client.AcquireNonInteractive(ctx, activationKey, amnezia.NegotiationOptions{
		WireGuardPublicKey: clientPublicKey,
		ExtraPayload:       map[string]any{"e2e_case": "plaintext-captcha-402"},
	})
	var plaintextInteractionErr *amnezia.InteractionRequiredError
	if !errors.As(err, &plaintextInteractionErr) || plaintextInteractionErr.Request.Captcha == nil || plaintextInteractionErr.Request.Captcha.Reason != amnezia.ErrorCaptchaRequired {
		return fmt.Errorf("plaintext-captcha-402: error = %v, want CAPTCHA interaction", err)
	}
	_, err = client.AcquireNonInteractive(ctx, activationKey, amnezia.NegotiationOptions{
		WireGuardPublicKey: clientPublicKey,
		ExtraPayload:       map[string]any{"e2e_case": "wrong-public-key"},
	})
	if err := expectProtocolError(err, "validate gateway profile"); err != nil {
		return fmt.Errorf("wrong-public-key: %w", err)
	}
	_, err = client.AcquireNonInteractive(ctx, activationKey, amnezia.NegotiationOptions{
		WireGuardPublicKey: clientPublicKey,
		ExtraPayload:       map[string]any{"e2e_case": "unknown-interaction"},
	})
	var interactionErr *amnezia.InteractionRequiredError
	if !errors.As(err, &interactionErr) || interactionErr.Request.Kind != amnezia.InteractionUnknown {
		return fmt.Errorf("unknown-interaction: error = %v, want unknown interaction", err)
	}

	_, err = fmt.Fprintln(stdout, "gateway edge cases passed")
	return err
}

func newGatewayClient(gatewayURL string, publicPEM []byte) (*amnezia.Client, error) {
	return amnezia.NewClient(amnezia.ClientOptions{
		HTTPClient:          &http.Client{Transport: &http.Transport{}},
		GatewayURL:          gatewayURL,
		GatewayPublicKeyPEM: publicPEM,
		PrimaryS3URLs:       []string{},
		FallbackS3URLs:      []string{},
		StaticProxyURLs:     []string{},
		DisableS3Discovery:  true,
		Metadata: amnezia.ClientMetadata{
			OSVersion: "linux", AppVersion: "5.0.1.5", CLIName: "AmneziaVPN",
			Distribution: "wgo-e2e", Language: "en",
			InstallationUUID: "00000000-0000-4000-8000-000000000001",
		},
	})
}

func e2eActivationKey() (string, error) {
	return amnezia.EncodeActivationKey(amnezia.ActivationKey{
		Name:          "wgo mock gateway e2e",
		ConfigVersion: 2,
		APIConfig: amnezia.ActivationAPIConfig{
			ServiceType:     "wgo-e2e",
			ServiceProtocol: "awg",
			UserCountryCode: "xx",
		},
		AuthData: json.RawMessage(`{"api_key":"wgo-e2e-secret"}`),
	})
}

func exerciseCaptchaFlow(ctx context.Context, client *amnezia.Client, activationKey, clientPublicKey string) error {
	session, err := client.StartImport(activationKey, amnezia.NegotiationOptions{
		InteractionPolicy:  amnezia.PauseOnInteraction,
		WireGuardPublicKey: clientPublicKey,
		ExtraPayload: map[string]any{
			"e2e_case":     "captcha-flow",
			"e2e_marker":   "initial",
			"service_type": "poison",
			"public_key":   "poison",
			"auth_data":    map[string]any{"api_key": "poison"},
		},
	})
	if err != nil {
		return err
	}
	step, err := session.Next(ctx)
	if err != nil {
		return err
	}
	if step.State != amnezia.NegotiationAwaitingInteraction || step.Interaction == nil || step.Interaction.Captcha == nil {
		return fmt.Errorf("captcha-flow: first step = %#v, want CAPTCHA interaction", step)
	}
	if step.Interaction.Captcha.ID != "edge-captcha-1" || step.Interaction.Captcha.Reason != amnezia.ErrorCaptchaRequired {
		return fmt.Errorf("captcha-flow: challenge = %#v", step.Interaction.Captcha)
	}
	step, err = session.Resume(ctx, amnezia.InteractionResponse{
		CaptchaSolution: "１２ 3a",
		Fields: map[string]string{
			"e2e_marker": "resumed",
			"public_key": "poison-on-resume",
		},
	})
	if err != nil {
		return err
	}
	if step.State != amnezia.NegotiationComplete || step.Profile == nil {
		return fmt.Errorf("captcha-flow: resumed step = %#v, want completed profile", step)
	}
	if step.Profile.Interface.PublicKey != clientPublicKey {
		return fmt.Errorf("captcha-flow: profile public key changed")
	}
	return nil
}

func exerciseCaptchaRefresh(ctx context.Context, client *amnezia.Client, activationKey, clientPublicKey string) error {
	session, err := client.StartImport(activationKey, amnezia.NegotiationOptions{
		InteractionPolicy:  amnezia.PauseOnInteraction,
		WireGuardPublicKey: clientPublicKey,
		ExtraPayload:       map[string]any{"e2e_case": "captcha-refresh"},
	})
	if err != nil {
		return err
	}
	step, err := session.Next(ctx)
	if err != nil {
		return err
	}
	if step.Interaction == nil || step.Interaction.Captcha == nil {
		return fmt.Errorf("captcha-refresh: first step = %#v, want CAPTCHA interaction", step)
	}
	step, err = session.Resume(ctx, amnezia.InteractionResponse{CaptchaSolution: "111"})
	if err != nil {
		return err
	}
	if step.State != amnezia.NegotiationAwaitingInteraction || step.Interaction == nil || step.Interaction.Captcha == nil {
		return fmt.Errorf("captcha-refresh: second step = %#v, want CAPTCHA interaction", step)
	}
	captcha := step.Interaction.Captcha
	if captcha.ID != "edge-refresh-1" || captcha.ImageBase64 != "aW1hZ2UtMQ==" || captcha.Hint != "digits" || captcha.Reason != amnezia.ErrorCaptchaRefresh {
		return fmt.Errorf("captcha-refresh: challenge = %#v", captcha)
	}
	return nil
}

func expectAPIError(err error, code amnezia.ErrorCode) error {
	var apiErr *amnezia.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != code {
		return fmt.Errorf("error = %v, want API code %s", err, code)
	}
	return nil
}

func expectProtocolError(err error, op string) error {
	var protocolErr *amnezia.ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Op != op {
		return fmt.Errorf("error = %v, want protocol op %q", err, op)
	}
	return nil
}

func serveGateway(args []string) error {
	flags := flag.NewFlagSet("serve-gateway", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	listen := flags.String("listen", "0.0.0.0:18080", "HTTP listen address")
	privatePath := flags.String("private-key", "", "gateway private key PEM path")
	configPath := flags.String("config-file", "", "gateway config vpn payload path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	privateKey, err := readRSAPrivateKey(*privatePath)
	if err != nil {
		return err
	}
	state := &gatewayEdgeState{
		firstPublicKey: make(map[string]string),
		attempts:       make(map[string]int),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/v1/config", func(w http.ResponseWriter, r *http.Request) {
		decoded, err := decodeGatewayRequest(r, privateKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if caseName := objectString(decoded.payload, "e2e_case"); caseName != "" {
			handleGatewayEdgeCase(w, decoded, caseName, *configPath, state)
			return
		}
		if strings.TrimSpace(objectString(decoded.payload, "public_key")) == "" {
			writeEncryptedGatewayResponse(w, decoded, http.StatusBadRequest, map[string]any{
				"http_status": 400,
				"message":     "missing public_key",
			})
			return
		}
		config, err := os.ReadFile(*configPath)
		if err != nil {
			writeEncryptedGatewayResponse(w, decoded, http.StatusInternalServerError, map[string]any{
				"http_status": 500,
				"message":     err.Error(),
			})
			return
		}
		writeEncryptedGatewayResponse(w, decoded, http.StatusOK, map[string]any{
			"config": strings.TrimSpace(string(config)),
			"service_info": map[string]any{
				"mock_gateway": true,
			},
		})
	})
	return (&http.Server{Addr: *listen, Handler: mux}).ListenAndServe()
}

type gatewayEdgeState struct {
	mu             sync.Mutex
	firstPublicKey map[string]string
	attempts       map[string]int
}

func (s *gatewayEdgeState) next(caseName string) (int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts[caseName]++
	return s.attempts[caseName], s.firstPublicKey[caseName]
}

func (s *gatewayEdgeState) rememberPublicKey(caseName, publicKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.firstPublicKey[caseName] == "" {
		s.firstPublicKey[caseName] = publicKey
	}
}

func handleGatewayEdgeCase(w http.ResponseWriter, request decodedGatewayRequest, caseName, configPath string, state *gatewayEdgeState) {
	if err := validateGatewayEdgeRequest(request, caseName); err != nil {
		writeEncryptedGatewayResponse(w, request, http.StatusBadRequest, map[string]any{
			"http_status": 400,
			"message":     err.Error(),
		})
		return
	}
	attempt, firstPublicKey := state.next(caseName)
	publicKey := objectString(request.payload, "public_key")
	switch caseName {
	case "captcha-flow":
		if attempt == 1 {
			state.rememberPublicKey(caseName, publicKey)
			writeEncryptedGatewayResponse(w, request, http.StatusPaymentRequired, map[string]any{
				"http_status":   402,
				"message":       "rate_limit_exceeded",
				"captcha_id":    "edge-captcha-1",
				"captcha_image": "aW1hZ2UtMQ==",
				"hint":          "digits",
			})
			return
		}
		if publicKey != firstPublicKey {
			writeEncryptedGatewayResponse(w, request, http.StatusBadRequest, map[string]any{
				"http_status": 400,
				"message":     "public_key changed across CAPTCHA retry",
			})
			return
		}
		if objectString(request.payload, "captcha_id") != "edge-captcha-1" || objectString(request.payload, "captcha_solution") != "123" {
			writeEncryptedGatewayResponse(w, request, http.StatusBadRequest, map[string]any{
				"http_status": 400,
				"message":     "CAPTCHA retry fields are not reference-compatible",
			})
			return
		}
		if objectString(request.payload, "e2e_marker") != "resumed" {
			writeEncryptedGatewayResponse(w, request, http.StatusBadRequest, map[string]any{
				"http_status": 400,
				"message":     "non-reserved resume fields were not sent",
			})
			return
		}
		writeGatewayConfig(w, request, configPath)
	case "captcha-refresh":
		if attempt == 1 {
			state.rememberPublicKey(caseName, publicKey)
			writeEncryptedGatewayResponse(w, request, http.StatusPaymentRequired, map[string]any{
				"http_status":   402,
				"message":       "rate_limit_exceeded",
				"captcha_id":    "edge-refresh-1",
				"captcha_image": "aW1hZ2UtMQ==",
				"hint":          "digits",
			})
			return
		}
		if publicKey != firstPublicKey {
			writeEncryptedGatewayResponse(w, request, http.StatusBadRequest, map[string]any{
				"http_status": 400,
				"message":     "public_key changed across CAPTCHA refresh",
			})
			return
		}
		writeEncryptedGatewayResponse(w, request, http.StatusPaymentRequired, map[string]any{
			"http_status": 402,
			"message":     "refresh_captcha",
		})
	case "rate-limit-429":
		writeEncryptedGatewayResponse(w, request, http.StatusTooManyRequests, map[string]any{"http_status": 429, "message": "too many requests"})
	case "trial-used-409":
		writeEncryptedGatewayResponse(w, request, http.StatusConflict, map[string]any{"http_status": 409, "message": "trial subscription already used"})
	case "subscription-expired-422":
		writeEncryptedGatewayResponse(w, request, http.StatusUnprocessableEntity, map[string]any{"http_status": 422, "message": "Failed to retrieve subscription information. Is it activated?"})
	case "subscription-inactive-402":
		writeEncryptedGatewayResponse(w, request, http.StatusPaymentRequired, map[string]any{"http_status": 402, "message": "subscription inactive"})
	case "update-required-501":
		writeEncryptedGatewayResponse(w, request, http.StatusNotImplemented, map[string]any{"http_status": 501, "message": "client version update is required"})
	case "not-found-404":
		writeEncryptedGatewayResponse(w, request, http.StatusNotFound, map[string]any{"http_status": 404, "message": "account not found."})
	case "plaintext-captcha-402":
		writePlaintextGatewayJSON(w, http.StatusPaymentRequired, map[string]any{
			"http_status":   402,
			"message":       "rate_limit_exceeded",
			"captcha_id":    "edge-plain-1",
			"captcha_image": "aW1hZ2U=",
		})
	case "wrong-public-key":
		data, err := os.ReadFile(configPath)
		if err != nil {
			writeEncryptedGatewayResponse(w, request, http.StatusInternalServerError, map[string]any{"http_status": 500, "message": err.Error()})
			return
		}
		config, err := replaceGatewayProfilePublicKey(strings.TrimSpace(string(data)))
		if err != nil {
			writeEncryptedGatewayResponse(w, request, http.StatusInternalServerError, map[string]any{"http_status": 500, "message": err.Error()})
			return
		}
		writeEncryptedGatewayResponse(w, request, http.StatusOK, map[string]any{"config": config})
	case "unknown-interaction":
		writeEncryptedGatewayResponse(w, request, http.StatusOK, map[string]any{
			"interaction_required": true,
			"required_action":      "confirm_terms",
			"message":              "confirm terms",
		})
	default:
		writeEncryptedGatewayResponse(w, request, http.StatusBadRequest, map[string]any{"http_status": 400, "message": "unknown e2e case"})
	}
}

func validateGatewayEdgeRequest(request decodedGatewayRequest, caseName string) error {
	if strings.TrimSpace(requestIDFromRequest(request)) == "" {
		return errors.New("missing X-Client-Request-ID")
	}
	for key, want := range map[string]string{
		"os_version":        "linux",
		"app_version":       "5.0.1.5",
		"cli_name":          "AmneziaVPN",
		"distribution":      "wgo-e2e",
		"app_language":      "en",
		"installation_uuid": "00000000-0000-4000-8000-000000000001",
		"user_country_code": "xx",
		"service_type":      "wgo-e2e",
		"service_protocol":  "awg",
	} {
		if objectString(request.payload, key) != want {
			return fmt.Errorf("%s = %q, want %q", key, objectString(request.payload, key), want)
		}
	}
	if strings.TrimSpace(objectString(request.payload, "public_key")) == "" || objectString(request.payload, "public_key") == "poison" || objectString(request.payload, "public_key") == "poison-on-resume" {
		return errors.New("public_key was missing or overwritten by extra fields")
	}
	authData, _ := request.payload["auth_data"].(map[string]any)
	if objectString(authData, "api_key") != "wgo-e2e-secret" {
		return errors.New("auth_data was not the activation key auth_data")
	}
	if caseName == "captcha-flow" && objectString(request.payload, "captcha_solution") == "" && objectString(request.payload, "e2e_marker") != "initial" {
		return errors.New("initial custom payload marker missing")
	}
	return nil
}

func requestIDFromRequest(request decodedGatewayRequest) string {
	return request.requestID
}

func writeGatewayConfig(w http.ResponseWriter, request decodedGatewayRequest, configPath string) {
	config, err := os.ReadFile(configPath)
	if err != nil {
		writeEncryptedGatewayResponse(w, request, http.StatusInternalServerError, map[string]any{
			"http_status": 500,
			"message":     err.Error(),
		})
		return
	}
	writeEncryptedGatewayResponse(w, request, http.StatusOK, map[string]any{
		"config": strings.TrimSpace(string(config)),
		"service_info": map[string]any{
			"mock_gateway": true,
			"edge_case":    true,
		},
	})
}

func writePlaintextGatewayJSON(w http.ResponseWriter, status int, object any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(object)
}

func replaceGatewayProfilePublicKey(input string) (string, error) {
	plain, err := amnezia.DecodeVPNPayload(input)
	if err != nil {
		return "", err
	}
	var root map[string]any
	if err := json.Unmarshal(plain, &root); err != nil {
		return "", err
	}
	containers, _ := root["containers"].([]any)
	if len(containers) == 0 {
		return "", errors.New("missing containers")
	}
	container, _ := containers[0].(map[string]any)
	awg, _ := container["awg"].(map[string]any)
	lastConfig, _ := awg["last_config"].(string)
	var client map[string]any
	if err := json.Unmarshal([]byte(lastConfig), &client); err != nil {
		return "", err
	}
	wrongKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))
	client["client_pub_key"] = wrongKey
	updated, err := json.Marshal(client)
	if err != nil {
		return "", err
	}
	awg["last_config"] = string(updated)
	container["awg"] = awg
	containers[0] = container
	root["containers"] = containers
	return amnezia.EncodeVPNPayload(root)
}

func serveHTTP(args []string, includeGuest bool) error {
	flags := flag.NewFlagSet("serve-http", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	listen := flags.String("listen", "0.0.0.0:8080", "HTTP listen address")
	text := flags.String("text", "ok", "response text for /")
	guestFile := flags.String("guest-file", "", "guest access file served from /guest.vpn")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if includeGuest && strings.TrimSpace(*guestFile) == "" {
		return errors.New("missing -guest-file")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintf(w, "%s\n", *text)
	})
	if includeGuest {
		serveGuest := func(w http.ResponseWriter, _ *http.Request) {
			data, err := os.ReadFile(*guestFile)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write(data)
		}
		mux.HandleFunc("/guest.vpn", serveGuest)
		mux.HandleFunc("/guest", serveGuest)
	}
	server := &http.Server{
		Addr:    *listen,
		Handler: mux,
	}
	return server.ListenAndServe()
}

func configToUAPI(config string) (string, error) {
	var b strings.Builder
	b.WriteString("set=1\n")
	b.WriteString("replace_peers=true\n")
	section := ""
	scanner := bufio.NewScanner(strings.NewReader(config))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch section {
		case "interface":
			if err := writeInterfaceUAPI(&b, key, value); err != nil {
				return "", err
			}
		case "peer":
			if err := writePeerUAPI(&b, key, value); err != nil {
				return "", err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return b.String(), nil
}

func writeInterfaceUAPI(b *strings.Builder, key, value string) error {
	switch strings.ToLower(key) {
	case "privatekey":
		hexKey, err := base64KeyToHex(value)
		if err != nil {
			return fmt.Errorf("PrivateKey: %w", err)
		}
		fmt.Fprintf(b, "private_key=%s\n", hexKey)
	case "listenport":
		fmt.Fprintf(b, "listen_port=%s\n", value)
	case "fwmark":
		fmt.Fprintf(b, "fwmark=%s\n", value)
	case "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5":
		fmt.Fprintf(b, "%s=%s\n", strings.ToLower(key), value)
	case "headerprotectionkey":
		hexKey, err := flexibleKeyToHex(value)
		if err != nil {
			return fmt.Errorf("HeaderProtectionKey: %w", err)
		}
		fmt.Fprintf(b, "header_protection_key=%s\n", hexKey)
	case "contentpaddingaddition":
		fmt.Fprintf(b, "content_padding_addition=%s\n", value)
	case "rekeyaftertime":
		fmt.Fprintf(b, "rekey_after_time=%s\n", value)
	case "rekeytimeout":
		fmt.Fprintf(b, "rekey_timeout=%s\n", value)
	case "rejectaftertime":
		fmt.Fprintf(b, "reject_after_time=%s\n", value)
	case "keepalivetimeout":
		fmt.Fprintf(b, "keepalive_timeout=%s\n", value)
	case "maxhandshakeattempts":
		fmt.Fprintf(b, "max_handshake_attempts=%s\n", value)
	case "randomtrailers":
		fmt.Fprintf(b, "random_trailers=%s\n", toggleToBool(value))
	case "disablecookies":
		fmt.Fprintf(b, "disable_cookies=%s\n", toggleToBool(value))
	}
	return nil
}

func writePeerUAPI(b *strings.Builder, key, value string) error {
	switch strings.ToLower(key) {
	case "publickey":
		hexKey, err := base64KeyToHex(value)
		if err != nil {
			return fmt.Errorf("PublicKey: %w", err)
		}
		fmt.Fprintf(b, "public_key=%s\nprotocol_version=1\n", hexKey)
	case "presharedkey":
		hexKey, err := base64KeyToHex(value)
		if err != nil {
			return fmt.Errorf("PresharedKey: %w", err)
		}
		fmt.Fprintf(b, "preshared_key=%s\n", hexKey)
	case "allowedips":
		b.WriteString("replace_allowed_ips=true\n")
		for _, prefix := range strings.Split(value, ",") {
			prefix = strings.TrimSpace(prefix)
			if prefix != "" {
				fmt.Fprintf(b, "allowed_ip=%s\n", prefix)
			}
		}
	case "endpoint":
		fmt.Fprintf(b, "endpoint=%s\n", value)
	case "persistentkeepalive":
		fmt.Fprintf(b, "persistent_keepalive_interval=%s\n", value)
	}
	return nil
}

func encodeQtCompressedPayload(value any) (string, error) {
	plain, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	var compressed bytes.Buffer
	writer, err := zlib.NewWriterLevel(&compressed, 8)
	if err != nil {
		return "", err
	}
	if _, err := writer.Write(plain); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}
	framed := make([]byte, 4, 4+compressed.Len())
	binary.BigEndian.PutUint32(framed, uint32(len(plain)))
	framed = append(framed, compressed.Bytes()...)
	return vpnScheme + base64.RawURLEncoding.EncodeToString(framed), nil
}

func writeConfigLine(b *strings.Builder, key, value string) {
	if strings.TrimSpace(value) != "" {
		fmt.Fprintf(b, "%s = %s\n", key, value)
	}
}

func readInput(path string, stdin io.Reader) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(path)
}

func hostFromEndpoint(endpoint string) string {
	host, _, _ := net.SplitHostPort(endpoint)
	return strings.Trim(host, "[]")
}

func portFromEndpoint(endpoint string) int {
	_, portText, _ := net.SplitHostPort(endpoint)
	port, _ := strconv.Atoi(portText)
	return port
}

func decodeBase64Key(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, err
	}
	if len(decoded) != 32 {
		return nil, fmt.Errorf("decoded key length is %d, want 32", len(decoded))
	}
	return decoded, nil
}

func decodeHexKey(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, err
	}
	if len(decoded) != 32 {
		return nil, fmt.Errorf("decoded key length is %d, want 32", len(decoded))
	}
	return decoded, nil
}

func base64KeyToHex(value string) (string, error) {
	decoded, err := decodeBase64Key(value)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(decoded), nil
}

func flexibleKeyToHex(value string) (string, error) {
	if decoded, err := decodeBase64Key(value); err == nil {
		return hex.EncodeToString(decoded), nil
	}
	decoded, err := decodeHexKey(value)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(decoded), nil
}

func hexKeyToBase64(value string) (string, error) {
	decoded, err := decodeHexKey(value)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(decoded), nil
}

func toggleToBool(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "on", "true", "1", "yes":
		return "true"
	default:
		return "false"
	}
}

func pemBlock(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func readRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("missing PEM block")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return key, nil
}

func wireGuardPublicFromPrivate(privateKey string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privateKey))
	if err != nil || len(decoded) != 32 {
		return "", errors.New("invalid private key")
	}
	key, err := ecdh.X25519().NewPrivateKey(decoded)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

type decodedGatewayRequest struct {
	payload   map[string]any
	key       []byte
	iv        []byte
	requestID string
}

func decodeGatewayRequest(r *http.Request, privateKey *rsa.PrivateKey) (decodedGatewayRequest, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return decodedGatewayRequest{}, err
	}
	var envelope map[string]string
	if err := json.Unmarshal(body, &envelope); err != nil {
		return decodedGatewayRequest{}, err
	}
	encryptedKey, err := base64.StdEncoding.DecodeString(envelope["key_payload"])
	if err != nil {
		return decodedGatewayRequest{}, err
	}
	keyJSON, err := rsa.DecryptPKCS1v15(crand.Reader, privateKey, encryptedKey)
	if err != nil {
		return decodedGatewayRequest{}, err
	}
	var keyPayload map[string]string
	if err := json.Unmarshal(keyJSON, &keyPayload); err != nil {
		return decodedGatewayRequest{}, err
	}
	key, err := base64.StdEncoding.DecodeString(keyPayload["aes_key"])
	if err != nil {
		return decodedGatewayRequest{}, err
	}
	iv, err := base64.StdEncoding.DecodeString(keyPayload["aes_iv"])
	if err != nil {
		return decodedGatewayRequest{}, err
	}
	encryptedAPI, err := base64.StdEncoding.DecodeString(envelope["api_payload"])
	if err != nil {
		return decodedGatewayRequest{}, err
	}
	plain, err := decryptAES256CBC(encryptedAPI, key, iv)
	if err != nil {
		return decodedGatewayRequest{}, err
	}
	var payload map[string]any
	if err := json.Unmarshal(plain, &payload); err != nil {
		return decodedGatewayRequest{}, err
	}
	return decodedGatewayRequest{payload: payload, key: key, iv: iv, requestID: r.Header.Get("X-Client-Request-ID")}, nil
}

func writeEncryptedGatewayResponse(w http.ResponseWriter, request decodedGatewayRequest, status int, object any) {
	plain, err := json.Marshal(object)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	encrypted, err := encryptAES256CBC(plain, request.key, request.iv)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(status)
	_, _ = w.Write(encrypted)
}

func encryptAES256CBC(plain, key, iv []byte) ([]byte, error) {
	if len(key) != 32 || len(iv) < aes.BlockSize {
		return nil, errors.New("invalid AES-256-CBC key or IV length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plain, aes.BlockSize)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv[:aes.BlockSize]).CryptBlocks(out, padded)
	return out, nil
}

func decryptAES256CBC(ciphertext, key, iv []byte) ([]byte, error) {
	if len(key) != 32 || len(iv) < aes.BlockSize {
		return nil, errors.New("invalid AES-256-CBC key or IV length")
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("invalid AES-CBC ciphertext length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv[:aes.BlockSize]).CryptBlocks(out, ciphertext)
	return pkcs7Unpad(out, aes.BlockSize)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	return append(append([]byte(nil), data...), bytes.Repeat([]byte{byte(padding)}, padding)...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid PKCS#7 length")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize || padding > len(data) {
		return nil, errors.New("invalid PKCS#7 padding")
	}
	for _, value := range data[len(data)-padding:] {
		if int(value) != padding {
			return nil, errors.New("invalid PKCS#7 padding")
		}
	}
	return data[:len(data)-padding], nil
}

func objectString(object map[string]any, key string) string {
	value, _ := object[key].(string)
	return value
}
