// Package amnezia imports Amnezia service and self-hosted connection inputs
// for the github.com/asciimoth/wgo/amnesia subpackage.
//
// It detects API activation keys, self-hosted guest vpn:// keys, and native
// WireGuard/AmneziaWG configs. Service keys negotiate through the encrypted
// Amnezia gateway API and expose CAPTCHA requests as resumable state-machine
// steps; static inputs complete locally. Every supported path returns the same
// backend-neutral Profile/config representation. The package does not start a
// tunnel itself. A Client can attach a device.DeviceAPI and apply profiles to
// it, or callers can translate Profile for another WireGuard backend.
//
// NewClient requires a caller-supplied HTTP client with an explicit dedicated
// transport. All gateway, proxy-health, and S3-compatible requests use it; the
// package never falls back to http.DefaultClient or http.DefaultTransport.
//
// Activation keys, self-hosted keys, native configs, returned WireGuard private
// keys, and raw profiles are secrets. Applications must not log or commit them.
package amnezia
