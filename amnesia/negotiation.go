package amnezia

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"unicode"
)

// InteractionPolicy controls what happens when a gateway requests human input.
type InteractionPolicy uint8

const (
	// PauseOnInteraction returns an InteractionRequest and preserves the
	// selected WireGuard public key so the caller can resume later.
	PauseOnInteraction InteractionPolicy = iota
	// FailOnInteraction is the no-interrupt/headless mode. Any recognized
	// interaction request immediately returns InteractionRequiredError.
	FailOnInteraction
)

// InteractionKind is extensible so non-CAPTCHA server actions fail safely in
// headless mode instead of being mistaken for ordinary API errors.
type InteractionKind string

const (
	InteractionCaptcha InteractionKind = "captcha"
	InteractionUnknown InteractionKind = "unknown"
)

// CaptchaChallenge is the public UI material returned by the gateway.
type CaptchaChallenge struct {
	ID          string
	ImageBase64 string
	Hint        string
	Reason      ErrorCode
}

// InteractionRequest is a paused negotiation step. Message is untrusted
// server text and may be sensitive; show it deliberately and do not log it.
type InteractionRequest struct {
	Kind    InteractionKind
	Message string
	Captcha *CaptchaChallenge
	Attempt int
}

// InteractionResponse resumes a paused negotiation. Fields is reserved for
// compatible custom gateways that define a non-CAPTCHA interaction.
type InteractionResponse struct {
	CaptchaSolution string
	Fields          map[string]string
}

// NegotiationState is the externally observable state of a Negotiation.
type NegotiationState uint8

const (
	NegotiationReady NegotiationState = iota
	NegotiationRequesting
	NegotiationAwaitingInteraction
	NegotiationComplete
	NegotiationFailed
)

// Step is returned after a network transition. Exactly one of Profile or
// Interaction is non-nil.
type Step struct {
	State       NegotiationState
	Profile     *Profile
	Interaction *InteractionRequest
}

// NegotiationOptions customizes one configuration request.
type NegotiationOptions struct {
	InteractionPolicy InteractionPolicy
	ServerCountryCode string
	ConnectEvent      bool
	// WireGuardPublicKey selects an existing caller-owned WireGuard identity.
	// It must be a standard padded Base64 encoding of exactly 32 bytes. The
	// matching private key is never requested or transmitted, and the caller is
	// responsible for configuring the tunnel backend with it. If this field is
	// empty, the library generates a new keypair as a fallback and returns the
	// private key in the completed Profile.
	WireGuardPublicKey string
	ExtraPayload       map[string]any
}

// Negotiation is a resumable, single-profile state machine. It retains the
// selected WireGuard identity while paused. privateKey is populated only for
// the generated-key fallback. Do not serialize or log a Negotiation.
type Negotiation struct {
	client     *Client
	key        ActivationKey
	options    NegotiationOptions
	privateKey string
	publicKey  string

	mu          sync.Mutex
	state       NegotiationState
	inFlight    bool
	interaction *InteractionRequest
	attempt     int
	profile     *Profile
}

// String is deliberately redacted.
func (n *Negotiation) String() string {
	if n == nil {
		return "Negotiation<nil>"
	}
	return fmt.Sprintf("Negotiation{state:%d, secrets:<redacted>}", n.State())
}

// Start parses a secret vpn:// key and creates a negotiation without making a
// network request.
func (c *Client) Start(rawActivationKey string, options NegotiationOptions) (*Negotiation, error) {
	key, err := ParseActivationKey(rawActivationKey)
	if err != nil {
		return nil, err
	}
	return c.StartKey(*key, options)
}

// StartKey creates a negotiation from an already parsed activation key.
func (c *Client) StartKey(key ActivationKey, options NegotiationOptions) (*Negotiation, error) {
	if options.InteractionPolicy != PauseOnInteraction && options.InteractionPolicy != FailOnInteraction {
		return nil, &ProtocolError{Op: "validate negotiation options", Err: fmt.Errorf("unknown interaction policy %d", options.InteractionPolicy)}
	}
	if key.ConfigVersion < 2 {
		return nil, ErrLegacyKeyUnsupported
	}
	if key.ConfigVersion != 2 {
		return nil, &ProtocolError{Op: "validate activation key", Err: fmt.Errorf("unsupported config_version %d", key.ConfigVersion)}
	}
	if !strings.EqualFold(key.APIConfig.ServiceProtocol, "awg") {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedProtocol, key.APIConfig.ServiceProtocol)
	}
	if len(key.AuthData) == 0 || !json.Valid(key.AuthData) || firstNonSpace(key.AuthData) != '{' {
		return nil, &ProtocolError{Op: "validate activation key", Err: errors.New("invalid auth_data")}
	}
	private := ""
	public := strings.TrimSpace(options.WireGuardPublicKey)
	if public != "" {
		if err := validateWireGuardKey("client public key", public); err != nil {
			return nil, &ProtocolError{Op: "validate negotiation options", Err: err}
		}
	} else {
		if err := c.withRandom(func(reader io.Reader) error {
			privateKey, err := ecdh.X25519().GenerateKey(reader)
			if err != nil {
				return err
			}
			private = base64.StdEncoding.EncodeToString(privateKey.Bytes())
			public = base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes())
			return nil
		}); err != nil {
			return nil, fmt.Errorf("amnezia: generate WireGuard keypair: %w", err)
		}
	}
	return &Negotiation{
		client:     c,
		key:        cloneActivationKey(key),
		options:    cloneNegotiationOptions(options),
		privateKey: private,
		publicKey:  public,
		state:      NegotiationReady,
	}, nil
}

func cloneActivationKey(key ActivationKey) ActivationKey {
	key.AuthData = append(json.RawMessage(nil), key.AuthData...)
	key.Extra = cloneRawMap(key.Extra)
	return key
}

func cloneRawMap(in map[string]json.RawMessage) map[string]json.RawMessage {
	if in == nil {
		return nil
	}
	out := make(map[string]json.RawMessage, len(in))
	for key, value := range in {
		out[key] = append(json.RawMessage(nil), value...)
	}
	return out
}

func cloneNegotiationOptions(options NegotiationOptions) NegotiationOptions {
	if options.ExtraPayload != nil {
		copyMap := make(map[string]any, len(options.ExtraPayload))
		for key, value := range options.ExtraPayload {
			copyMap[key] = value
		}
		options.ExtraPayload = copyMap
	}
	return options
}

// State returns a snapshot of the current state.
func (n *Negotiation) State() NegotiationState {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.state
}

// Next performs the initial request. It is valid only in NegotiationReady.
func (n *Negotiation) Next(ctx context.Context) (Step, error) {
	return n.transition(ctx, nil, NegotiationReady)
}

// Resume submits user input while preserving the original WireGuard identity.
func (n *Negotiation) Resume(ctx context.Context, response InteractionResponse) (Step, error) {
	return n.transition(ctx, &response, NegotiationAwaitingInteraction)
}

func (n *Negotiation) transition(ctx context.Context, response *InteractionResponse, expected NegotiationState) (Step, error) {
	n.mu.Lock()
	if n.inFlight || n.state != expected {
		state := n.state
		n.mu.Unlock()
		return Step{State: state}, ErrInvalidState
	}
	if expected == NegotiationAwaitingInteraction && n.interaction == nil {
		n.mu.Unlock()
		return Step{State: n.state}, ErrInvalidState
	}
	currentInteraction := n.interaction
	n.inFlight = true
	n.state = NegotiationRequesting
	n.mu.Unlock()

	payload, err := n.requestPayload(response, currentInteraction)
	if err != nil {
		return n.finishError(expected, err)
	}
	reply, requestErr := n.client.postGateway(ctx, "v1/config", payload, n.key.APIConfig.ServiceType, n.key.APIConfig.UserCountryCode)
	if interaction, ok := interactionFromReply(reply, requestErr, currentInteraction); ok {
		n.mu.Lock()
		n.inFlight = false
		n.attempt++
		interaction.Attempt = n.attempt
		if n.options.InteractionPolicy == FailOnInteraction {
			n.state = NegotiationFailed
			n.interaction = nil
			n.mu.Unlock()
			return Step{State: NegotiationFailed}, &InteractionRequiredError{Request: interaction}
		}
		n.state = NegotiationAwaitingInteraction
		n.interaction = &interaction
		n.mu.Unlock()
		return Step{State: NegotiationAwaitingInteraction, Interaction: &interaction}, nil
	}
	if requestErr != nil {
		return n.finishError(expected, requestErr)
	}
	configValue := objectString(reply.object, "config")
	if configValue == "" {
		return n.finishError(expected, &ProtocolError{Op: "read gateway response", Err: errors.New("missing config")})
	}
	var serviceInfo json.RawMessage
	if value, ok := reply.object["service_info"]; ok {
		serviceInfo, _ = json.Marshal(value)
	}
	profile, err := parseGatewayProfile(configValue, n.publicKey, n.privateKey, ProfileAPI{
		ServiceType:     n.key.APIConfig.ServiceType,
		ServiceProtocol: n.key.APIConfig.ServiceProtocol,
		UserCountryCode: n.key.APIConfig.UserCountryCode,
		ServiceInfo:     serviceInfo,
	})
	if err != nil {
		return n.finishError(expected, err)
	}
	n.mu.Lock()
	n.inFlight = false
	n.state = NegotiationComplete
	n.interaction = nil
	n.profile = profile
	n.mu.Unlock()
	return Step{State: NegotiationComplete, Profile: profile}, nil
}

func (n *Negotiation) finishError(previous NegotiationState, err error) (Step, error) {
	n.mu.Lock()
	n.inFlight = false
	// A request or parse failure does not change the selected WireGuard identity;
	// callers may retry the same transition.
	n.state = previous
	state := n.state
	n.mu.Unlock()
	return Step{State: state}, err
}

func (n *Negotiation) requestPayload(response *InteractionResponse, interaction *InteractionRequest) (map[string]any, error) {
	payload := make(map[string]any, len(n.options.ExtraPayload)+16)
	for key, value := range n.options.ExtraPayload {
		payload[key] = value
	}
	payload["os_version"] = n.client.metadata.OSVersion
	payload["app_version"] = n.client.metadata.AppVersion
	payload["cli_name"] = n.client.metadata.CLIName
	if n.client.metadata.Distribution != "" {
		payload["distribution"] = n.client.metadata.Distribution
	}
	if n.client.metadata.Language != "" {
		payload["app_language"] = n.client.metadata.Language
	}
	if n.client.metadata.InstallationUUID != "" {
		payload["installation_uuid"] = n.client.metadata.InstallationUUID
	}
	if n.key.APIConfig.UserCountryCode != "" {
		payload["user_country_code"] = n.key.APIConfig.UserCountryCode
	}
	if n.options.ServerCountryCode != "" {
		payload["server_country_code"] = n.options.ServerCountryCode
	}
	payload["service_type"] = n.key.APIConfig.ServiceType
	payload["service_protocol"] = n.key.APIConfig.ServiceProtocol
	payload["public_key"] = n.publicKey
	var authData map[string]any
	if err := json.Unmarshal(n.key.AuthData, &authData); err != nil {
		return nil, &ProtocolError{Op: "parse auth_data", Err: err}
	}
	payload["auth_data"] = authData
	if n.options.ConnectEvent {
		payload["is_connect_event"] = true
	}
	if response != nil {
		for key, value := range response.Fields {
			if isReservedPayloadField(key) {
				continue
			}
			payload[key] = value
		}
		if interaction != nil && interaction.Kind == InteractionCaptcha && interaction.Captcha != nil {
			if strings.TrimSpace(response.CaptchaSolution) == "" {
				return nil, errors.New("amnezia: empty CAPTCHA solution")
			}
			payload["captcha_id"] = interaction.Captcha.ID
			payload["captcha_solution"] = normalizeCaptchaSolution(response.CaptchaSolution)
		}
	}
	return payload, nil
}

func isReservedPayloadField(key string) bool {
	switch key {
	case "os_version", "app_version", "cli_name", "distribution", "app_language", "installation_uuid",
		"user_country_code", "server_country_code", "service_type", "service_protocol", "public_key",
		"auth_data", "is_connect_event", "captcha_id", "captcha_solution":
		return true
	default:
		return false
	}
}

func normalizeCaptchaSolution(solution string) string {
	var digits strings.Builder
	for _, r := range solution {
		switch {
		case r >= '0' && r <= '9':
			digits.WriteRune(r)
		case r >= '\uff10' && r <= '\uff19':
			digits.WriteRune('0' + (r - '\uff10'))
		case unicode.IsDigit(r):
			// The official app only normalizes ASCII and full-width digits.
			// Ignore other digit scripts to preserve wire compatibility.
		}
	}
	if digits.Len() > 0 {
		return digits.String()
	}
	return strings.TrimSpace(solution)
}

func interactionFromReply(reply *gatewayReply, err error, previous *InteractionRequest) (InteractionRequest, bool) {
	if reply == nil {
		return InteractionRequest{}, false
	}
	message := objectString(reply.object, "message")
	captchaID := objectString(reply.object, "captcha_id")
	captchaImage := objectString(reply.object, "captcha_image")
	hint := objectString(reply.object, "hint")
	reason := ErrorUnknown
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		reason = apiErr.Code
	}
	lower := strings.ToLower(message)
	captchaSignal := captchaID != "" || captchaImage != "" || reason == ErrorCaptchaRequired || reason == ErrorCaptchaInvalid || reason == ErrorCaptchaRefresh ||
		(objectInt(reply.object, "http_status") == 402 && strings.Contains(lower, "rate_limit_exceeded"))
	if captchaSignal {
		challenge := &CaptchaChallenge{ID: captchaID, ImageBase64: captchaImage, Hint: hint, Reason: reason}
		if previous != nil && previous.Captcha != nil {
			if challenge.ID == "" {
				challenge.ID = previous.Captcha.ID
			}
			if challenge.ImageBase64 == "" {
				challenge.ImageBase64 = previous.Captcha.ImageBase64
			}
			if challenge.Hint == "" {
				challenge.Hint = previous.Captcha.Hint
			}
		}
		return InteractionRequest{Kind: InteractionCaptcha, Message: message, Captcha: challenge}, true
	}
	if required, _ := reply.object["interaction_required"].(bool); required || objectString(reply.object, "required_action") != "" {
		return InteractionRequest{Kind: InteractionUnknown, Message: message}, true
	}
	return InteractionRequest{}, false
}

// AcquireNonInteractive is the convenience API for daemons and IoT clients.
// It never pauses: any server-requested interaction returns an error matching
// ErrInteractionRequired.
func (c *Client) AcquireNonInteractive(ctx context.Context, rawActivationKey string, options NegotiationOptions) (*Profile, error) {
	options.InteractionPolicy = FailOnInteraction
	negotiation, err := c.Start(rawActivationKey, options)
	if err != nil {
		return nil, err
	}
	step, err := negotiation.Next(ctx)
	if err != nil {
		return nil, err
	}
	if step.Profile == nil {
		return nil, &ProtocolError{Op: "complete negotiation", Err: errors.New("gateway returned no profile")}
	}
	return step.Profile, nil
}
