# farlink-registry

Operator tool for the signed server list (`servers.json`, protocol v1 §12).

- `keygen -out key.pem` — new Ed25519 operator key; prints `key_id` and `public_key` to embed in the apps' trusted keys. Keep the key offline (the owner's copy lives in `~/.farlink/registry-key.pem`).
- `pin -cert cert.pem` — base64 SPKI SHA-256 pin for `tls_spki_pins`.
- `sign -key key.pem -in registry.json -out servers.json` — validates and signs. Bump `sequence` on every publish; clients refuse lower sequences. `issued_at` and `expires_at` are Unix milliseconds.

`registry.json` at the repo root is the unsigned source; `servers.json` is what the apps download (GitHub raw and the mirrors) and also ship built in.
