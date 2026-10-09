# Farlink Server

The relay server for [Farlink](https://farlink.pro): it helps your devices find each other and forwards encrypted data when they cannot connect directly. Files and messages are end-to-end encrypted on your devices, so the server only sees ciphertext.

**A server you run is completely separate from Farlink's own servers.** It makes no connection to them, has no billing and no traffic limits, and is used only by the people you invite to your networks.

> **License: source-available, not open source.** You may read the code and run it unmodified for yourself and your own networks. You may not modify it, redistribute it or use it commercially. See [LICENSE](LICENSE).

## What you need

- A Linux server (x86-64 or ARM64) with a public IPv4 address, or a Mac for testing.
- A domain name pointing to that address (the server gets a Let's Encrypt certificate by itself).
- Open ports: 443/tcp, 80/tcp (once, for the certificate), 3478/udp and 5349/tcp (TURN), and a UDP range for relayed media.
- **Farlink Pro** in the app, to connect your own server.

## Install

1. Download `farlink-server-<version>-linux-amd64.tar.gz` (or `-arm64`) and `SHA256SUMS` from the [Releases](../../releases) page and check the file:

   ```sh
   sha256sum -c SHA256SUMS --ignore-missing
   tar xzf farlink-server-*-linux-*.tar.gz && cd farlink-server
   ```

2. Run it (replace the domain and the IP address):

   ```sh
   ./farlink-server -id https://files.example.com -domain files.example.com -public-ip 203.0.113.5
   ```

   `-id` must be exactly the address people will type, in lower case, without a trailing slash. Use `-data /var/lib/farlink` (the default) for the data directory; back it up.

3. To keep it running, install the systemd unit from `deploy/farlink-server.service`:

   ```sh
   sudo useradd --system --home /var/lib/farlink farlink
   sudo install -m 755 farlink-server /usr/local/bin/
   sudo install -m 644 deploy/farlink-server.service /etc/systemd/system/
   sudo systemctl daemon-reload && sudo systemctl enable --now farlink-server
   ```

   Edit `-id`, `-domain` and `-public-ip` in the unit first.

4. In Farlink: **Settings → Servers → Add your own server.** Enter the address and check the certificate fingerprint printed in the server log. Create a network and invite people: the invitation link or QR code fills in your server for them.

### Docker

```sh
docker build -t farlink-server .
docker run -d --name farlink --restart unless-stopped --network host -v farlink:/var/lib/farlink \
  farlink-server -id https://files.example.com -domain files.example.com -public-ip 203.0.113.5
```

### Build from source

```sh
go build -trimpath -o farlink-server ./cmd/farlink-server
```

## Good to know

- Apple push notifications are available only on Farlink's own servers. With your own server an iPhone or iPad may receive new files only while the app is open or was recently used.
- Updating: download the new version, stop the server, replace the file, start it again. Keep the data directory.
- `./farlink-server -h` lists every option.

---

# Reference

## Server ID and device login

`-id` (or `FARLINK_ID`) is required and must stay the same for the life of the server. For a server listed in
the signed `servers.json` it is that listing's `server_id`. **For a self-hosted server added in Settings →
Servers it must be exactly the server's public origin — the address people type:** `https://files.example.com`
(no port for 443) or `https://203.0.113.5:8443`, lower-case, no path or trailing slash. Devices derive the
audience they expect from that typed address themselves and never take it from the server (a hostile server
could otherwise call itself another one), so a different `-id` means the server can't be added. The server
logs a warning at start when `-id` doesn't look like an origin (fine for catalog servers with short ids).

The server puts `-id` verbatim as `audience` in every auth challenge (`POST /v1/auth/challenges`), and devices sign it. A client must compare the challenge's
`audience` with the id it expects for the address it dialled and refuse to sign anything else — otherwise a
hostile server could relay another server's challenge and obtain a session there. The id reported by
`/v1/health` comes from the same server and is not proof of identity on its own; devices only check that it
matches the origin they derived. Changing `-id` (or the address) makes every client that knows the old one
refuse to log in until its server record is updated.

## Limits

Anyone can create a device key, so a public server bounds what one key or one address can take. These
connection and memory limits are always on, with or without `-quotas`; "address" is the client IP (IPv6 per
/64). Refusals are `429 RATE_LIMITED` (retryable) and happen before any socket upgrade or body read:

- auth: at most 64 outstanding challenges and 1024 live sessions per address, with global caps; auth, invite
  and relay-control bodies are limited to 16 KiB;
- signal: at most 16 open WebSockets per device (app and extensions each hold one), 1024 per address and
  100 000 in total, admitted before the upgrade; a socket must register within 10 s. Queued boxes are capped
  per recipient, per sender and in total, a sender can open mailboxes for at most 64 offline devices per
  10 minutes, and empty mailboxes are dropped. Each remembered `delivery_id` (kept 10 minutes for dedup, as
  a keyed 64-bit hash, expired from a queue) costs 64 bytes of the recipient's mailbox budget and the hub's,
  so send→ack loops can't grow memory;
- relay: 32 open sessions per owner device, 256 per owner address, 20 000 in total. A session ends with the
  auth session of either side;
- TURN: 16 allocations per device, 256 per client address, 20 000 in total (`486 Allocation Quota Reached`);
  an allocation may be permitted to at most 64 peers, never loopback, private, link-local or CGNAT
  addresses;
- spool: `-spool-max-bytes` per owner device, `-spool-ip-max-bytes` per address and `-spool-total-max-bytes`
  for the server (defaults 50/100/200 GiB, `0` = unlimited), plus object-count caps; every object, even an
  empty one, costs at least 4 KiB of quota. A part's body is read by one PUT at a time (a parallel PUT of the
  same part is refused before its body), part bodies being read hold their size against 64 MiB per owner,
  256 MiB per address and 2 GiB in total, and a body must arrive within 5 minutes.

## Quotas and App Store purchases (our servers)

A self-hosted server needs none of this: without `-quotas` (the default) nothing is metered and no purchase
is ever checked. Farlink's own servers run with `-quotas` (`FARLINK_QUOTAS=on`):

- devices send their StoreKit 2 signed transactions to `POST /v1/entitlements/verify`; the server verifies
  them offline against Apple Root CA G3 (pinned by fingerprint; no call to Apple), for `-bundle-id` and the
  environments in `-appstore-env` (default `Production`; add `Sandbox` for TestFlight). `-appstore-root` adds
  one more trusted root (DER or PEM), e.g. the local root Xcode signs StoreKit Testing transactions with;
- tiers per UTC month; relay traffic is counted in GiB (2^30), queues in decimal GB: Free `-free-relay-bytes`
  10 GiB per account (per key until the key is bound to an account, see below), queue `-free-spool-bytes` 2 GB;
  Relay subscription `-relay-bytes` 200 GiB, queue `-relay-spool-bytes` 20 GB; Teams `-teams-person-bytes`
  200 GB per seat pooled for the network, queue `-teams-spool-bytes` 20 GB (`-teams=false` ignores Teams packs).
  Relay, TURN and spool downloads all count;
- used up: no new relay sessions, TURN credentials or allocations, or spool reservations (`429
  QUOTA_EXCEEDED`); what already runs finishes (up to one more limit of overdraft);
- one meter for all transports: WSS relay frames (billed to the session's creator), TURN datagrams in both
  directions (to the device in the credentials; datagrams from peers the client never permitted are dropped
  uncharged) and spool downloads (to the object's owner) draw on the same allowance. A queued file is billed **once, in full, to
  its sender's account** at the first byte served - however many devices of the recipient download it, however often
  it is resumed, and an interrupted send keeps its charge; the recipient is never billed for receiving. A meter
  that cannot cover the whole object refuses the download before any byte goes out;
- fresh keys are free, so free-tier traffic from one address is capped at `-ip-traffic-bytes` a month
  (default 200 GB) whatever keys it uses; paid traffic is not held to it (a Teams office behind one NAT).
  `-total-traffic-bytes` caps the whole server's monthly traffic (default `0` = no cap; set it to what the
  VPS may send). Both are hard caps: the bytes that would cross them are not forwarded;
- `POST /v1/appstore/notifications` takes App Store Server Notifications v2 (set it as the URL in App Store
  Connect): refunds and revocations switch a known subscription off at once, renewals move its end. Without
  it the server learns the same the next time a device presents its transactions;
- entitlements are kept in `<data>/entitlements.json`; the month's byte counts in `<data>/ledger.cbor` (per
  tier bucket) and `<data>/traffic.cbor` (per address and total), saved every minute and at shutdown, so a
  restart forgives at most the last minute.

`-quotas` also reads `-quotas=on`, `-quotas on` or `FARLINK_QUOTAS=on`; `-quotas=off` (the default) is the
self-hosting policy: traffic is not metered or refused at all, while every limit in the section above stays.

### Account billing identity (`-billing-identity`, off by default)

Limits belong to the Farlink account, not to a device or a network (owner decision, 2026-10-06: Free 10 GiB a month
per account, paid 200 GiB, a file counted once per logical send however many devices receive it). The first step
is only the proof of who a transport key belongs to; no quota changes with it.

- `POST /v2/billing/identities/bind`: the session's own key (the one that signed in) is the transport key being
  bound. The body is signed by an account device that is **active now** (`farlink/billing-identity-bind/v1`,
  CBOR `protocol, account_id, account_device, transport_device, request_id, expires_at, audience`), valid for at
  most ten minutes and only for this server's ID (`audience`). Answers 200 `{bound, account_id}`; 403 for a signer
  that is not an active device of the account (including one revoked since), a signature that does not cover this
  key, or another audience; 400 for an expired or too-long-lived request; 409 when the key is already bound to
  another account or a request ID is reused with a different body (a key never moves to another account);
  429 past 256 keys for one account; 503 when the account cannot be resolved (never a guess).
- `GET /v2/billing/identities/me`: `{bound, account_id}` for the session's key.
- Both answer 404 while the flag is off. Bindings are kept in `<data>/billing-bindings.cbor`, written (fsync, rename)
  before the answer goes out.
- Not yet: this table is per server. Binding on ru1/ru2 will forward to the single billing authority (us) before any
  quota uses it; until then nothing may count on a binding made here.

Seats (people per network) are not a server matter: the Teams license travels in the network's signed
membership and every device checks it, on any server (protocol §13.1).

## Deleting an account

One signed request deletes an account everywhere: `POST /v1/accounts/{id}/delete`, signed (domain `farlink/account-delete/v1`)
by a device that is active now and naming the newest chain link it saw; it expires after ten minutes. The server that takes it
checks it against the chain it holds, then in one step saves the work and refuses the account for good: from then on the
account's chain, its devices (and the transport keys bound to it) are answered with `410 ACCOUNT_DELETED` /
`DEVICE_ACCOUNT_DELETED`, nothing is stored for or from them, and open relay, signal and TURN use stops at the next charge or
half minute.

It then erases what it keeps for the account (spool objects and grants, mailbox and outbox entries, contact relations, invites;
twice, a couple of minutes apart), and tells every other server of the directory (`POST /v1/federation/accounts/delete`, with the
chain and the request, which the receiver replays and checks itself) and repeats every half minute until each has answered, for
at most 90 days. Only then is the chain, the checkpoint and the billing bindings dropped.

What stays for good is a hash of the account id and a hash of each device key (`deleted.log`), so the same account cannot be made
again from old keys. Reports stay 90 days (`-reports`), as for everyone. Files already delivered to other people are theirs.
With `-billing-identity` off, only the account's own device keys are refused, not the network keys that were never bound.

## Build

```sh
go test ./... && go build -o bin/farlink-server ./cmd/farlink-server
```
