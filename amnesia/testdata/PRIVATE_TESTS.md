# Private and live test fixtures

The `private/` directory is gitignored. Never commit activation keys, custom
API credentials, WireGuard private keys, or private deployment endpoints.

For parse-only checks, put one service or self-hosted `vpn://` key per line in:

```text
testdata/private/activation_keys.txt
```

For multiline inputs and original files, create this directory and put any
self-hosted `.vpn` exports or WireGuard/AmneziaWG `.conf` files inside it:

```text
testdata/private/inputs/
```

Every non-hidden regular file is passed to `ParseInputBytes`. Both parse-only
tests auto-skip when their corresponding private fixture is absent. These tests
are part of the normal `go test` suite because they do not contact a service.

## Live service E2E

The live service E2E is an individual command, not a package test. It reads one
real Amnezia service activation key, creates an `amnesia.Client`, performs a
non-interactive `v1/config` gateway request, and verifies that the returned
profile has the minimum fields needed to configure a tunnel. Then it builds a
userspace `VTun`, applies the returned profile to `device.DeviceAPI`, starts a
real WireGuard/AmneziaWG tunnel, compares the visible public IP outside the
tunnel and through the VTun dialer, resolves and pings `example.com`, and sends
HTTP requests to `http://example.com/` through the VTun dialer.
Server-provided pre-connect actions are executed before the device starts,
because some live profiles rely on them.

It prints colored terminal output: grey for minor traces, normal text for
regular progress, cyan for important profile and public-IP highlights, green
for success, and red for failure. It prints each network request and response
status, the selected fixture paths, the effective client metadata sent to the
gateway, activation-key display name and service selectors, pre-connect
destinations and byte counts, VTun setup, visible public IP and GeoIP results,
ping attempts, HTTP statuses, WGO device logs as grey minor traces, and a
redacted profile summary. It does not print the activation key, request body,
pre-connect payload bytes, CAPTCHA image, WireGuard private key, native config,
or raw gateway config.

Place the secret key in `testdata/private/live_activation_key.txt` and create
`testdata/private/live_api.json`:

```json
{
  "enabled": true,
  "activation_key_file": "live_activation_key.txt",
  "gateway_url": "",
  "gateway_public_key_pem_file": "",
  "primary_s3_urls": null,
  "fallback_s3_urls": null,
  "static_proxy_urls": null,
  "disable_s3_discovery": false,
  "accept_interaction_required": true,
  "metadata": {
    "installation_uuid": "persist-a-real-uuid-here"
  }
}
```

Empty endpoint/key fields select the public official defaults. The live E2E
uses no-interrupt mode and therefore never waits for a UI. A live query may
consume or refresh a provider device/config slot, so `enabled` is an explicit
safety latch in addition to the file being present. When
`metadata.installation_uuid` is missing, `null`, or empty, the command
generates a new UUID and saves it to `live_api.json` before the gateway
request. When `metadata.os_version` is empty, the command sends a descriptive
local default such as the Linux `/etc/os-release` `PRETTY_NAME` plus
`GOOS/GOARCH`; set `metadata.os_version` explicitly to override it.

Run it explicitly:

```sh
just test-amnesia-live
```

To use a different private fixture directory or config path:

```sh
go run ./cmd/amnesia_live_e2e -private-dir /path/to/private
go run ./cmd/amnesia_live_e2e -config /path/to/live_api.json
```

Useful traffic flags:

```sh
go run ./cmd/amnesia_live_e2e -traffic-host example.com -traffic-http-url http://example.com/
go run ./cmd/amnesia_live_e2e -ip-check-urls https://ifconfig.co/json,https://api.ipify.org
go run ./cmd/amnesia_live_e2e -ping-count 5 -http-count 3 -traffic-timeout 15s
go run ./cmd/amnesia_live_e2e -skip-traffic
```

The default live traffic check compares the visible public IP outside the
tunnel and through `VTun.Dial`, prints GeoIP location fields when the selected
service returns them, then uses ICMP ping and HTTP through `VTun.Dial`. Set
`-ip-check-urls ""` to disable only the visible-IP check.

This command is intentionally not included in `just test-total` or `just check`.
