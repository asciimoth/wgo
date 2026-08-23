# wgo/amnesia

`github.com/asciimoth/wgo/amnesia` is the Amnezia import and API-client
subpackage for `wgo`. It accepts API-v2 service `vpn://` keys, self-hosted
guest `vpn://` keys, and native WireGuard/AmneziaWG `.conf` contents. Service
keys negotiate an AmneziaWG profile and pause cleanly for CAPTCHA input; static
self-hosted and native inputs complete offline. Every path returns the same
backend-neutral profile.

The subpackage does **not** start a tunnel. In this repository, callers apply
the returned `Profile` to `github.com/asciimoth/wgo/device`. The profile model
also stays backend-neutral, so callers can translate it into another
WireGuard implementation that supports the returned Amnezia extensions.

This is a compatibility subpackage and is not an official Amnezia VPN product.
The bundled production defaults were verified against official
release **5.0.1.5**, source commit
[`7d4f3e0f`](https://github.com/amnezia-vpn/amnezia-client/tree/7d4f3e0f5090b74903609179653d1f669d2ad08a).
They can change server-side; pin and test the defaults appropriate for your
deployment.

## Features

- unified `ParseInput` / `StartImport` API with offline format detection;
- API-v2 `vpn://` parsing and encoding, including unknown-field preservation;
- self-hosted WireGuard and AmneziaWG guest-key import using the official
  qCompress/Base64URL representation;
- native WireGuard/AWG `.conf` parsing with a safe structured renderer that
  drops unrecognized and executable `wg-quick` directives;
- caller-owned WireGuard public keys for existing nodes, with local keypair
  generation only when no public key is supplied;
- RSA-PKCS#1 v1.5 + AES-256-CBC gateway envelope compatibility;
- explicit `Next` / `Resume` state machine for CAPTCHA-capable UIs;
- fail-closed non-interactive mode for daemons and IoT clients;
- official gateway, RSA public key, S3-compatible stores, and proxy bootstrap
  defaults, all overridable.
- mandatory caller-supplied HTTP client with a dedicated transport; the
  library never uses Go's default client or default transport.
- same encrypted request body and request ID reused across gateway proxies.
- backend-neutral WireGuard/AWG 1.5, 2, and 3.1 profile model and config
  renderer.
- server-supplied pre-connect actions exposed as data; they are never executed
  implicitly.
- standard-library-only runtime dependencies.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the wire protocol and public API.

## Installation

```sh
go get github.com/asciimoth/wgo/amnesia
```

The subpackage follows the root `wgo` module Go version.

`NewClient(ClientOptions{})` is intentionally invalid: applications must
inject a dedicated `HTTPClient` and transport. Pure parsing functions such as
`ParseInput`, `ParseActivationKey`, and `ParseWireGuardConfig` remain offline
and do not require a `Client`.

## Supported inputs

| Input | Result | Network during import |
|---|---|---|
| API-v2 service `vpn://` key with `api_config` and `auth_data` | resumable gateway negotiation | yes |
| Self-hosted guest `vpn://` key with a ready client under `containers` | static `Profile` | no |
| WireGuard or AmneziaWG `.conf` contents | static `Profile` | no |
| Self-hosted full-access key containing SSH management credentials | recognized error | no |

`vpn://` is only an outer transport. A self-hosted guest key embeds an already
generated client profile; a service key embeds credentials used to request a
profile. `ParseInput` distinguishes them from their decoded JSON structure.

Full-access self-hosted keys intentionally return
`ErrSelfHostedManagementKey`. They can authorize server-wide SSH management,
and official exports do not contain a ready guest profile. Installing services
or generating a peer over SSH is outside this tunnel-client library. Ask users
to export **guest access** for WireGuard or AmneziaWG instead.

```go
session, err := client.StartImport(input, amnezia.NegotiationOptions{})
if errors.Is(err, amnezia.ErrSelfHostedManagementKey) {
	// Show: export "Share VPN Access" (guest), not "Share full access".
}
```

Native configs currently require exactly one `[Interface]` and one `[Peer]`.
WireGuard and AWG 1.5/2/3.1 fields are projected into `Profile`; other VPN
protocols and multi-peer configs fail explicitly instead of being partially
imported.

## Unified interactive import

The library never owns a UI thread and never blocks waiting for a person.
`StartImport` parses any supported input without network access. `Next`
completes a static input immediately or performs the first service request. If
the server asks for a CAPTCHA, it returns an `InteractionRequest` and keeps the
same selected WireGuard public key. The application can close the request
context, display any UI it wants, and call `Resume` later with a new context.

```go
package main

import (
	"context"
	"fmt"
	"net/http"

	amnezia "github.com/asciimoth/wgo/amnesia"
)

func importConnection(ctx context.Context, apiHTTPClient *http.Client, input, wireGuardPublicKey string, solve func(amnezia.CaptchaChallenge) (string, error)) (*amnezia.Profile, error) {
	client, err := amnezia.NewClient(amnezia.ClientOptions{
		HTTPClient: apiHTTPClient,
	})
	if err != nil {
		return nil, err
	}

	// input may be clipboard text or the protected contents of a .vpn/.conf file.
	session, err := client.StartImport(input, amnezia.NegotiationOptions{
		InteractionPolicy: amnezia.PauseOnInteraction,
		// Pass the public key of an existing node. Leave it empty only when
		// this application wants the library to generate a new keypair.
		WireGuardPublicKey: wireGuardPublicKey,
	})
	if err != nil {
		return nil, err
	}

	step, err := session.Next(ctx)
	for err == nil && step.Interaction != nil {
		if step.Interaction.Kind != amnezia.InteractionCaptcha || step.Interaction.Captcha == nil {
			return nil, fmt.Errorf("unsupported interaction: %s", step.Interaction.Kind)
		}
		solution, solveErr := solve(*step.Interaction.Captcha)
		if solveErr != nil {
			return nil, solveErr
		}
		step, err = session.Resume(ctx, amnezia.InteractionResponse{
			CaptchaSolution: solution,
		})
	}
	if err != nil {
		return nil, err
	}
	return step.Profile, nil
}
```

The library treats the supplied string as content, never as a filesystem path.
Use `ParseInputBytes` for bytes read from a file or QR decoder.
`session.Format()` reports `InputFormatServiceKey`,
`InputFormatSelfHostedKey`, or `InputFormatNativeConfig` without exposing the
credential.

`Client.Start` / `StartKey` remain the lower-level API when an application
already knows that the input is an API service key.

`CaptchaChallenge.ImageBase64` is the server-provided image value. Decode and
render it according to the UI platform; do not log it. Invalid or refreshed
CAPTCHAs may produce another interaction step, so the loop is intentional.

When `WireGuardPublicKey` was supplied, the result deliberately has an empty
`Profile.Interface.PrivateKey`. Configure a structured backend with the
existing private key directly. If a standalone configuration is required,
the caller must first insert the matching private key:

```go
if profile.Interface.PrivateKey == "" {
	profile.Interface.PrivateKey = loadExistingWireGuardPrivateKey()
}
configText, err := profile.ConfigText()
if err != nil {
	return err
}
// Pass configText to the selected backend without logging it.
```

`Profile.Interface`, `Profile.Peer`, and `Profile.AmneziaWG` are the preferred
integration surface when a backend has a native API. `ConfigText` returns the
validated safe subset rendered from those fields. The original official or
imported native text is retained in `Profile.NativeConfig` for deliberate
inspection, but it is untrusted and may contain directives a tool such as
`wg-quick` could execute.
Do not apply it blindly. For caller-owned negotiation identities, the library
sends and validates only the public key; it is the caller's responsibility to
use its matching private key. `ConfigText` and `RenderConfig` return
`ErrWireGuardPrivateKeyRequired` while it is absent. If no public key was
provided, negotiation falls back to generating a keypair and returns its
private key in the profile. Static imports derive and validate the public key
from the embedded private key, and self-hosted imports reject a private-key
mismatch between structured and native representations.

## No-interrupt / headless use

Daemons, unattended clients, and IoT devices should use
`ImportNonInteractive`. It accepts every supported format and cannot pause. A
CAPTCHA or another recognized server interaction returns an error matching
`ErrInteractionRequired`.

```go
profile, err := client.ImportNonInteractive(
	ctx,
	input,
	amnezia.NegotiationOptions{},
)
if errors.Is(err, amnezia.ErrInteractionRequired) {
	// Report a permanent/operator-action-required condition. Do not retry-loop.
}
```

`AcquireNonInteractive` remains the lower-level service-key-only equivalent.

Use `errors.As(err, new(*amnezia.InteractionRequiredError))` to inspect the
interaction type without exposing the activation key. The library also treats
generic `interaction_required` / `required_action` responses as interaction,
so headless callers fail closed when a compatible gateway adds a non-CAPTCHA
action.

## Persistence and refresh

Persist a successful profile atomically in encrypted storage and load it on
normal application startup. For service keys, retain the activation credential,
stable installation UUID, and WireGuard identity so the application can
renegotiate with the same public key on expiry, explicit reload,
country/protocol change, or provider policy. If fallback generation was used,
persist the returned private key securely before discarding the profile. Never
persist an in-progress CAPTCHA `Negotiation`/`ImportSession`.

Self-hosted guest keys and native configs are static: there is no service
gateway refresh call. Cache the imported profile and use it until the server
revokes or replaces that peer, then import a newly generated guest key/config.
Keep the old working profile until a replacement has parsed and validated
successfully.

## Official defaults and custom deployments

`NewClient` requires a caller-owned `HTTPClient` with an explicit dedicated
`Transport`; it then selects these public defaults when their corresponding
options are omitted:

- the official production gateway;
- the official production RSA encryption public key;
- four primary and two fallback S3-compatible proxy-list stores;
- a dated static copy of the generic production proxy list.

The exact values and their provenance are in `defaults.go`. Dynamic discovery
is attempted before the static bootstrap. Every option can be replaced:

```go
client, err := amnezia.NewClient(amnezia.ClientOptions{
	HTTPClient:          apiHTTPClient,
	GatewayURL:          os.Getenv("CUSTOM_AMNEZIA_GATEWAY_URL"),
	GatewayPublicKeyPEM: []byte(os.Getenv("CUSTOM_AMNEZIA_GATEWAY_PUBLIC_KEY_PEM")),
	PrimaryS3URLs:       []string{"https://objects.example.net/proxy-list/"},
	FallbackS3URLs:      []string{},
	StaticProxyURLs:     []string{"https://gateway-proxy.example.net/"},
	Metadata: amnezia.ClientMetadata{
		AppVersion:       "my-client/1.0",
		CLIName:          "my-client",
		InstallationUUID: loadStableInstallationUUID(),
	},
})
```

The package rejects a nil `HTTPClient`, a client with `Transport == nil`, and
the shared `http.DefaultTransport`. This prevents accidental fallback to Go's
process-wide direct network path. All gateway POSTs, S3-compatible discovery
requests, and proxy health checks use the injected client. `NewClient` makes a
shallow copy of the `http.Client`, pinning its selected `RoundTripper` even if
the caller later changes the original client's fields.

The control plane's “direct gateway” attempt and its alternative gateway-proxy
destinations are only destination choices: both travel through this same
injected transport. They never bypass a configured local SOCKS/VPN transport.

For example, a SOCKS-only application can create a dedicated transport and
pass it in:

```go
proxyURL, err := url.Parse("socks5://127.0.0.1:1080")
if err != nil {
	return err
}
transport := http.DefaultTransport.(*http.Transport).Clone()
transport.Proxy = http.ProxyURL(proxyURL) // fixed proxy; no direct fallback
apiHTTPClient := &http.Client{
	Transport: transport,
	Timeout:   20 * time.Second,
}
client, err := amnezia.NewClient(amnezia.ClientOptions{
	HTTPClient: apiHTTPClient,
})
```

The caller owns the transport's proxy, DNS, TLS-root, redirect, timeout, and
logging policy. Do not implement proxy failure by retrying with a direct
transport. A custom `RoundTripper` may also be used for a VPN namespace,
Tor-like stack, test harness, or platform network framework.

Endpoint slices have deliberate three-state semantics:

| Value | Meaning |
|---|---|
| `nil` | use that official list |
| non-empty slice | use only the supplied list |
| non-nil empty slice | disable that list |

`DisableS3Discovery` disables both S3 lists. Set all three lists to non-nil
empty slices as well when a custom gateway must never fall back to official
infrastructure.

The gateway RSA **public** key is encryption material, not an API credential.
By contrast, caller-supplied service/API keys, activation keys, self-hosted
guest or full-access keys, native `.conf` files, every `auth_data` value,
private deployment credentials, and returned WireGuard private keys are
secrets. Load them from a secret store, environment, or protected file at
runtime. **Never commit them to source code, examples, public test fixtures,
logs, crash reports, or telemetry.** A private endpoint name may also be
operationally sensitive even when it contains no credential.

Persist `ClientMetadata.InstallationUUID` for an installed client. If omitted,
the library creates a random UUID that lasts only for that `Client` instance.

## S3-compatible proxy discovery

Discovery supports Amazon S3, Google Cloud Storage, Azure Blob Storage,
Oracle Object Storage, and compatible HTTP object stores because the protocol
only needs HTTPS `GET` access to a base URL. The service-specific object is
tried first, then `endpoints.json`. Objects use the official public-key-derived
AES format.

`ProxyCache` stores the original encrypted object. The default
`MemoryProxyCache` is process-local. Supply a persistent implementation if an
application needs proxy bootstrap after restart. Cache input is untrusted and
is size-limited and revalidated when loaded.

## Error handling and retries

- Use `errors.Is` for `ErrHTTPClientRequired`, `ErrHTTPTransportRequired`,
  `ErrInteractionRequired`, `ErrInvalidState`,
  `ErrLegacyKeyUnsupported`, `ErrUnsupportedProtocol`, `ErrUnsupportedInput`,
  `ErrSelfHostedManagementKey`, `ErrStaticProfileUnavailable`, and
  `ErrWireGuardPrivateKeyRequired`.
- Use `errors.As` with `*APIError` for stable gateway error categories and
  `*ProtocolError` for malformed protocol data.
- A canceled context or transient request error leaves a negotiation at its
  previous state, allowing the same `Next` or `Resume` transition to be
  retried with the same selected WireGuard identity.
- Only one method may be in flight on a `Negotiation`; concurrent or
  out-of-order calls return `ErrInvalidState`.
- Do not tight-loop on rate limits, subscription failures, or required human
  interaction.

## Pre-connect actions

Some profiles include `send_payload` actions. They can deliberately send
bytes to a TCP or UDP endpoint before tunnel connection. The library projects
them into `Profile.PreConnect` and provides `BuildTaggedPayload` for the
official `<b 0xHEX>` and `<r N>` grammar. It does not open sockets or perform
these actions: the embedding application must apply its own destination,
timeout, consent, and network-policy checks.

## Tests

Run the hermetic suite with:

```sh
go test ./...
go test -race ./...
go vet ./...
```

Tests cover activation-key and exact Qt qCompress framing, self-hosted AWG and
WireGuard guest imports, native `.conf` projection, unsafe-directive removal,
AES behavior, the frozen official S3 fixture, gateway encryption, proxy replay,
caller-owned public keys, generated fallback keys, CAPTCHA identity retention,
and headless failure.

Optional real-key tests auto-skip unless gitignored fixtures exist. Follow
[`testdata/PRIVATE_TESTS.md`](testdata/PRIVATE_TESTS.md) for parse-only and
explicitly enabled live tests. Live requests can consume or refresh a provider
configuration/device slot; keep the `enabled` latch off by default.

See [TESTING.md](TESTING.md) for the recommended integration matrix and a
Docker E2E topology combining a mock gateway with a real AmneziaWG data plane.

## Security notes

The client reproduces the deployed protocol, including its limitations. The
official gateway default is plain HTTP, and the payload encryption is
AES-CBC without an independent MAC/AEAD tag. This provides compatibility, not
modern end-to-end response authentication. Proxy-list encryption is derived
from a public key and provides obfuscation, not authenticity. Prefer a custom
HTTPS gateway where possible, keep TLS verification enabled, and treat every
decrypted response as untrusted input. See [ARCHITECTURE.md](ARCHITECTURE.md)
for the complete threat-model notes.

