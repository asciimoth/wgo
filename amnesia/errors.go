package amnezia

import (
	"errors"
	"fmt"
)

var (
	// ErrHTTPClientRequired means NewClient was called without a caller-owned
	// HTTP client. The package never falls back to http.DefaultClient.
	ErrHTTPClientRequired = errors.New("amnezia: explicit HTTP client required")
	// ErrHTTPTransportRequired means the supplied HTTP client would use Go's
	// implicit or shared default transport. Supply a dedicated RoundTripper,
	// typically configured with the caller's required proxy or dialer.
	ErrHTTPTransportRequired = errors.New("amnezia: explicit non-default HTTP transport required")
	// ErrInteractionRequired is matched by InteractionRequiredError.
	ErrInteractionRequired = errors.New("amnezia: user interaction required")
	// ErrInvalidState means a negotiation method was called out of order or
	// concurrently with another negotiation operation.
	ErrInvalidState = errors.New("amnezia: invalid negotiation state")
	// ErrLegacyKeyUnsupported is returned for official legacy API-v1 keys. The
	// current official application rejects that protocol too.
	ErrLegacyKeyUnsupported = errors.New("amnezia: legacy API-v1 keys are unsupported")
	// ErrUnsupportedProtocol means the input uses a tunnel protocol this
	// package does not project into Profile.
	ErrUnsupportedProtocol = errors.New("amnezia: unsupported tunnel protocol")
	// ErrUnsupportedInput means the input is not a recognized service key,
	// self-hosted guest key, or WireGuard/AmneziaWG native configuration.
	ErrUnsupportedInput = errors.New("amnezia: unsupported input")
	// ErrSelfHostedManagementKey means a self-hosted full-access key was
	// recognized. Such a key requires SSH provisioning/management and cannot be
	// converted into a tunnel profile by this package.
	ErrSelfHostedManagementKey = errors.New("amnezia: self-hosted full-access key requires server management")
	// ErrStaticProfileUnavailable means a self-hosted document was recognized
	// but contains no ready-to-use WireGuard/AmneziaWG client profile.
	ErrStaticProfileUnavailable = errors.New("amnezia: self-hosted key contains no client profile")
	// ErrWireGuardPrivateKeyRequired means a profile negotiated with a
	// caller-owned public key cannot be rendered as a standalone configuration
	// until the caller supplies the matching private key.
	ErrWireGuardPrivateKeyRequired = errors.New("amnezia: WireGuard private key required")
	// ErrDeviceRequired means an operation needs an attached device.DeviceAPI,
	// or an attach/replace call received a nil implementation.
	ErrDeviceRequired = errors.New("amnezia: device API required")
	// ErrDeviceAlreadyAttached means AttachDevice was called while the client
	// already had an open attached device API. Use ReplaceDevice for that case.
	ErrDeviceAlreadyAttached = errors.New("amnezia: device API already attached")
)

// ErrorCode classifies gateway domain failures without exposing response or
// activation-key secrets.
type ErrorCode string

const (
	ErrorUnknown              ErrorCode = "unknown"
	ErrorRateLimited          ErrorCode = "rate_limited"
	ErrorConfigLimit          ErrorCode = "config_limit"
	ErrorTrialAlreadyUsed     ErrorCode = "trial_already_used"
	ErrorNotFound             ErrorCode = "not_found"
	ErrorTimeout              ErrorCode = "timeout"
	ErrorUpdateRequired       ErrorCode = "update_required"
	ErrorSubscriptionExpired  ErrorCode = "subscription_expired"
	ErrorSubscriptionInactive ErrorCode = "subscription_inactive"
	ErrorConfigDownload       ErrorCode = "config_download"
	ErrorCaptchaRequired      ErrorCode = "captcha_required"
	ErrorCaptchaInvalid       ErrorCode = "captcha_invalid"
	ErrorCaptchaRefresh       ErrorCode = "captcha_refresh"
)

// APIError is a decrypted gateway domain error. Message is untrusted server
// text and may be sensitive; Error deliberately does not include it.
type APIError struct {
	Code       ErrorCode
	HTTPStatus int
	Message    string
}

func (e *APIError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("amnezia gateway: %s (status %d)", e.Code, e.HTTPStatus)
}

// ProtocolError reports malformed keys, envelopes, or gateway profiles.
type ProtocolError struct {
	Op  string
	Err error
}

func (e *ProtocolError) Error() string { return fmt.Sprintf("amnezia %s: %v", e.Op, e.Err) }
func (e *ProtocolError) Unwrap() error { return e.Err }

// InteractionRequiredError is returned in FailOnInteraction mode. Request is
// safe to show to a user but can contain a CAPTCHA image and server message.
type InteractionRequiredError struct {
	Request InteractionRequest
}

func (e *InteractionRequiredError) Error() string {
	return ErrInteractionRequired.Error() + ": " + string(e.Request.Kind)
}
func (e *InteractionRequiredError) Unwrap() error { return ErrInteractionRequired }
