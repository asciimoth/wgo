package amnezia

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
)

// InputFormat identifies a supported user-supplied connection representation.
// The zero value is not a recognized format.
type InputFormat string

const (
	InputFormatUnknown       InputFormat = ""
	InputFormatServiceKey    InputFormat = "service-key"
	InputFormatSelfHostedKey InputFormat = "self-hosted-key"
	InputFormatNativeConfig  InputFormat = "native-config"
)

// String returns a non-secret display name for the format.
func (f InputFormat) String() string {
	if f == InputFormatUnknown {
		return "unknown"
	}
	return string(f)
}

// ParsedInput is the offline result of ParseInput. Exactly one of
// ActivationKey or Profile is non-nil. Both variants contain secrets.
type ParsedInput struct {
	Format        InputFormat
	ActivationKey *ActivationKey
	Profile       *Profile
}

// String is deliberately redacted.
func (p ParsedInput) String() string {
	return fmt.Sprintf("ParsedInput{format:%q, contents:<redacted>}", p.Format)
}

// ParseInput detects and parses an API-v2 service key, a self-hosted guest
// vpn:// key, or a native WireGuard/AmneziaWG configuration. It performs no
// network access. Self-hosted full-access keys are recognized but rejected
// with ErrSelfHostedManagementKey because using them requires SSH management.
func ParseInput(input string) (*ParsedInput, error) {
	input = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(input), "\ufeff"))
	if input == "" {
		return nil, fmt.Errorf("%w: empty input", ErrUnsupportedInput)
	}
	if looksLikeNativeConfig(input) {
		profile, err := ParseWireGuardConfig(input)
		if err != nil {
			return nil, err
		}
		return &ParsedInput{Format: InputFormatNativeConfig, Profile: profile}, nil
	}

	plain, err := DecodeVPNPayload(input)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedInput, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(plain, &fields); err != nil {
		return nil, &ProtocolError{Op: "parse input JSON", Err: err}
	}
	_, hasAPIConfig := fields["api_config"]
	_, hasAuthData := fields["auth_data"]
	if hasAPIConfig || hasAuthData {
		key, err := ParseActivationKey(input)
		if err != nil {
			return nil, err
		}
		return &ParsedInput{Format: InputFormatServiceKey, ActivationKey: key}, nil
	}
	if _, legacyEndpoint := fields["api_endpoint"]; legacyEndpoint {
		return nil, ErrLegacyKeyUnsupported
	}
	if _, legacyKey := fields["api_key"]; legacyKey {
		return nil, ErrLegacyKeyUnsupported
	}
	if _, hasContainers := fields["containers"]; hasContainers {
		profile, err := ParseSelfHostedProfile(input)
		if err != nil {
			return nil, err
		}
		return &ParsedInput{Format: InputFormatSelfHostedKey, Profile: profile}, nil
	}
	return nil, fmt.Errorf("%w: unrecognized vpn payload", ErrUnsupportedInput)
}

// ParseInputBytes is ParseInput for data read from a file, clipboard, or QR
// decoder. It does not interpret data as a filesystem path.
func ParseInputBytes(data []byte) (*ParsedInput, error) {
	return ParseInput(string(data))
}

// ParseSelfHostedProfile decodes a self-hosted guest vpn:// key into a static
// backend-neutral profile. No gateway request is made. Only ready-to-use
// WireGuard and AmneziaWG guest profiles are supported.
func ParseSelfHostedProfile(input string) (*Profile, error) {
	plain, err := DecodeVPNPayload(input)
	if err != nil {
		return nil, &ProtocolError{Op: "decode self-hosted key", Err: err}
	}
	var root map[string]any
	if err := json.Unmarshal(plain, &root); err != nil {
		return nil, &ProtocolError{Op: "parse self-hosted key JSON", Err: err}
	}
	if _, ok := root["containers"].([]any); !ok {
		return nil, fmt.Errorf("%w: missing containers", ErrUnsupportedInput)
	}
	if anyString(root["userName"]) != "" || anyString(root["password"]) != "" {
		return nil, ErrSelfHostedManagementKey
	}

	_, client, err := findWireGuardClient(root)
	if err != nil {
		if errors.Is(err, errWireGuardClientProfileNotFound) {
			return nil, fmt.Errorf("%w: %v", ErrUnsupportedProtocol, err)
		}
		return nil, &ProtocolError{Op: "parse self-hosted client profile", Err: err}
	}
	privateKey := strings.TrimSpace(anyString(client["client_priv_key"]))
	native := anyString(client["config"])
	nativePrivateKey, err := nativeInterfacePrivateKey(native)
	if err != nil {
		return nil, &ProtocolError{Op: "read self-hosted native config", Err: err}
	}
	if privateKey != "" && nativePrivateKey != "" && !sameWireGuardKey(privateKey, nativePrivateKey) {
		return nil, &ProtocolError{Op: "validate self-hosted profile", Err: errors.New("client private key does not match native config")}
	}
	if privateKey == "" {
		privateKey = nativePrivateKey
	}
	if privateKey == "" {
		return nil, ErrStaticProfileUnavailable
	}

	profile, err := ParseGatewayProfile(string(plain), privateKey, ProfileAPI{})
	if err != nil {
		return nil, &ProtocolError{Op: "parse self-hosted profile", Err: err}
	}
	return profile, nil
}

// ParseWireGuardConfig parses a native WireGuard or AmneziaWG client config.
// Unknown directives remain only in NativeConfig; ConfigText renders the
// validated safe subset and therefore never reproduces wg-quick shell hooks.
// Exactly one [Interface] and one [Peer] are currently required.
func ParseWireGuardConfig(input string) (*Profile, error) {
	input = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(input), "\ufeff"))
	if input == "" {
		return nil, fmt.Errorf("%w: empty native config", ErrUnsupportedInput)
	}
	if len(input) > maxVPNPayloadBytes {
		return nil, &ProtocolError{Op: "parse native config", Err: errors.New("configuration exceeds size limit")}
	}
	if !looksLikeNativeConfig(input) {
		return nil, fmt.Errorf("%w: missing WireGuard sections", ErrUnsupportedInput)
	}
	if _, err := nativeInterfacePrivateKey(input); err != nil {
		return nil, &ProtocolError{Op: "parse native config", Err: err}
	}
	profile := &Profile{NativeConfig: input}
	if err := applyNativeFallback(profile, input); err != nil {
		return nil, &ProtocolError{Op: "parse native config", Err: err}
	}
	publicKey, err := wireGuardPublicFromPrivate(profile.Interface.PrivateKey)
	if err != nil {
		return nil, &ProtocolError{Op: "validate native private key", Err: err}
	}
	profile.Interface.PublicKey = publicKey
	profile.Interface.Addresses = normalizeInterfaceAddresses(profile.Interface.Addresses)
	if host, _, splitErr := net.SplitHostPort(profile.Peer.Endpoint); splitErr == nil {
		profile.HostName = strings.Trim(host, "[]")
	}
	if err := validateProfile(profile); err != nil {
		return nil, &ProtocolError{Op: "validate native config", Err: err}
	}
	return profile, nil
}

func looksLikeNativeConfig(input string) bool {
	scanner := bufio.NewScanner(strings.NewReader(input))
	scanner.Buffer(make([]byte, 64*1024), maxVPNPayloadBytes)
	hasInterface := false
	hasPeer := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "[") || !strings.HasSuffix(line, "]") {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(line[1 : len(line)-1])) {
		case "interface":
			hasInterface = true
		case "peer":
			hasPeer = true
		}
	}
	return hasInterface && hasPeer
}

func nativeInterfacePrivateKey(native string) (string, error) {
	if strings.TrimSpace(native) == "" {
		return "", nil
	}
	scanner := bufio.NewScanner(strings.NewReader(native))
	scanner.Buffer(make([]byte, 64*1024), maxVPNPayloadBytes)
	section := ""
	interfaceCount := 0
	privateKey := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "interface" {
				interfaceCount++
			}
			continue
		}
		if section != "interface" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), "PrivateKey") {
			continue
		}
		if privateKey != "" {
			return "", errors.New("native config contains multiple interface private keys")
		}
		privateKey = strings.TrimSpace(parts[1])
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if interfaceCount != 1 {
		return "", errors.New("native config must contain exactly one [Interface]")
	}
	return privateKey, nil
}

// ImportSession provides one state-machine API for negotiated service keys and
// immediate static profiles. For a static input, Next completes without any
// network operation. For a service key, Next and Resume delegate to a
// Negotiation and retain its CAPTCHA/identity behavior.
type ImportSession struct {
	format      InputFormat
	negotiation *Negotiation
	profile     *Profile

	mu    sync.Mutex
	state NegotiationState
}

// String is deliberately redacted.
func (s *ImportSession) String() string {
	if s == nil {
		return "ImportSession<nil>"
	}
	return fmt.Sprintf("ImportSession{format:%q, state:%d, contents:<redacted>}", s.Format(), s.State())
}

// StartImport parses arbitrary supported input without making a request.
// NegotiationOptions are used only for a service-key input.
func (c *Client) StartImport(input string, options NegotiationOptions) (*ImportSession, error) {
	parsed, err := ParseInput(input)
	if err != nil {
		return nil, err
	}
	session := &ImportSession{format: parsed.Format, state: NegotiationReady}
	switch parsed.Format {
	case InputFormatServiceKey:
		if c == nil {
			return nil, errors.New("amnezia: nil client")
		}
		negotiation, err := c.StartKey(*parsed.ActivationKey, options)
		if err != nil {
			return nil, err
		}
		session.negotiation = negotiation
	case InputFormatSelfHostedKey, InputFormatNativeConfig:
		session.profile = parsed.Profile
	default:
		return nil, ErrUnsupportedInput
	}
	return session, nil
}

// Format reports which input representation StartImport recognized.
func (s *ImportSession) Format() InputFormat {
	if s == nil {
		return InputFormatUnknown
	}
	return s.format
}

// State returns a snapshot of the unified import state.
func (s *ImportSession) State() NegotiationState {
	if s == nil {
		return NegotiationFailed
	}
	if s.negotiation != nil {
		return s.negotiation.State()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Next completes a static import immediately or performs the service
// negotiation's initial request.
func (s *ImportSession) Next(ctx context.Context) (Step, error) {
	if s == nil {
		return Step{State: NegotiationFailed}, ErrInvalidState
	}
	if s.negotiation != nil {
		return s.negotiation.Next(ctx)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != NegotiationReady || s.profile == nil {
		return Step{State: s.state}, ErrInvalidState
	}
	s.state = NegotiationComplete
	return Step{State: NegotiationComplete, Profile: s.profile}, nil
}

// Resume delegates to a service negotiation. Static inputs never pause and
// return ErrInvalidState.
func (s *ImportSession) Resume(ctx context.Context, response InteractionResponse) (Step, error) {
	if s == nil || s.negotiation == nil {
		state := NegotiationFailed
		if s != nil {
			state = s.State()
		}
		return Step{State: state}, ErrInvalidState
	}
	return s.negotiation.Resume(ctx, response)
}

// ImportNonInteractive is the high-level fail-on-interaction API for arbitrary
// supported input. Static profiles complete locally; a service-requested
// interaction returns an error matching ErrInteractionRequired.
func (c *Client) ImportNonInteractive(ctx context.Context, input string, options NegotiationOptions) (*Profile, error) {
	options.InteractionPolicy = FailOnInteraction
	session, err := c.StartImport(input, options)
	if err != nil {
		return nil, err
	}
	step, err := session.Next(ctx)
	if err != nil {
		return nil, err
	}
	if step.Profile == nil {
		return nil, &ProtocolError{Op: "complete import", Err: errors.New("import returned no profile")}
	}
	return step.Profile, nil
}
