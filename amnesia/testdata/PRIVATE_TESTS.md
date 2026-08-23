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
tests auto-skip when their corresponding private fixture is absent.

For an explicitly enabled live request, place the secret key in
`testdata/private/live_activation_key.txt` and create
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

Empty endpoint/key fields select the public official defaults. The live test
uses no-interrupt mode and therefore never waits for a UI. A live query may
consume or refresh a provider device/config slot, so `enabled` is an explicit
safety latch in addition to the file being present.
