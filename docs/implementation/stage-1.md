# Stage 1: what was built

Implementer's notes (2026-11-18). This is not a spec: `docs/specs/keep-hub.md` says what the
hub must do. This file records what stage 1 of `AGENTS.md` section 5 built, the request
shapes it had to choose because the spec doesn't give them, the owner's decisions that the
spec doesn't say yet, and what is left for later stages.

## Built

- The relay on each registered app's port (`relay.rs`): routing by path, the token and
  grant check, the `Keep-` headers, `503 app_stopped`, the connection limits.
- The registry (`registry.rs`): apps, members, grants, devices, guest invites, the PIN's
  hash, with migrations.
- Pairing and guests (`hub.rs`), and registering apps with a shared secret.
- The admin address (`admin.rs`).
- Two small test apps and the acceptance tests (`crates/keep-hub/tests`).

Copied from ShareKeep's `crates/sk-hub` as the starting point: the certificate authority
and TLS settings (`ca.rs`, from `wifi.rs`), PIN hashing (`pin.rs`), the key store
(`keys.rs`, with `seal.rs` from `sk-client`), the device registry (`registry.rs`), the
accept loop, per-address limit and gate of the TLS relay (`relay.rs`), and `util.rs`.

## Acceptance tests covered

| Spec test | Where |
|---|---|
| 1, 2, 3, 4, 19 | `tests/hub.rs`: `at01_…`, `at02_…`, `at03_…`, `at04_…`, `at19_…` |
| 6 | `tests/hub.rs`: three `at06_…` tests |
| 7, 8 | `tests/hub.rs`: `at07_…`, `at08_…` |
| 9 | `tests/hub.rs`: three `at09_…` tests |
| 21 | `registry.rs`: `a_later_hub_opens_this_registry_and_a_newer_registry_is_refused` |
| 5 | Belongs to the small library (stage 6). The test apps do refuse a request without the secret (`a_backend_refuses_a_local_program_without_the_shared_secret`) |

| 24 (in part) | `tests/hub.rs`: `at24_a_hub_with_no_app_registered_listens_on_the_admin_address_only`. The service and the certificate page are stages 7 and 4 |

Tests 10 to 18, 20, 22, 23, 25 and 26 belong to later stages or to other repositories.

## The spec update of 2026-11-18 (how the hub gets onto the computer)

The hub became its own release package, installed, updated and removed by keep-launcher;
no app's installer carries it. Building that is stage 7 here, and work in keep-launcher
and in each app. What it means for stage 1, checked against the code:

- An app's desktop program registers when phones are first turned on in it and again
  whenever its version changes. Registering again already keeps the app's devices and
  grants (`registering_again_keeps_the_phones_and_gives_a_new_secret`).
- A hub with no app registered runs and answers on the admin address (new test, above).
- keep-launcher's Remove must name the registered apps: `GET /admin/v1/apps` gives them.
- "Never replaced by an older version": `GET /admin/v1/status` gives the hub's version;
  the refusal itself is the installer's (test 26, stage 7).
- An app finds the hub by the admin address and the admin token: unchanged.

## Owner decisions on 2026-11-18 that the spec doesn't say yet

The spec writer should bring `docs/specs/keep-hub.md` in line with these. (The spec
update of the same day, about installing, did not include them yet.)

1. **Pausing pairing.** The spec says ten failures pause all pairing. Built as ShareKeep
   does it: ten failures in ten minutes from one address pause that address; a hundred from
   everywhere pause everyone.
2. **Removing a grant.** The spec says it revokes the member's devices for that app, and
   also (test 7) that their tokens answer `no_access`, while a revoked device answers
   `not_paired` (test 3). Built: the devices are not revoked; they answer `403 no_access`
   while there is no grant and work again if the grant is given back.
3. **`Keep-Request-Id`.** A phone sends its request id in `Keep-Request-Id`. The hub
   removes every `Keep-` header a phone sent and adds this one back with the phone's value
   (up to 128 letters, digits and `-._:~`; anything else is left out).

## Choices the spec leaves to the implementation

These are choices, open to change before an app is built against them.

### On an app's port

- One request per connection. The hub answers and forwards with `Connection: close`, so
  nothing reaches a backend that the hub didn't read and check. A request body needs
  `Content-Length`; `Transfer-Encoding` is refused with `411`.
- Refusals are JSON: `{"error": "<code>", "message": "<plain words>"}`. Codes used:
  `not_paired` (401), `no_access` (403), `wrong_code` (403), `pairing_paused` (429),
  `pin_not_set` (409), `app_stopped` (503), `app_failed` (502), `busy` (503),
  `bad_request`, `bad_path`, `bad_name` (400), `method_not_allowed` (405),
  `length_needed` (411), `too_large` (413), `head_too_large` (431), `not_found` (404).
- `POST /hub/pair` takes `{"code", "pin", "device"}` for a household member, or
  `{"invite", "name"}` for a guest, and answers
  `{"token", "device_id", "member": {"id", "name"}, "app"}` (plus `"guest_scope"` for a
  guest). The token is 64 hex characters.
- `GET /hub/whoami` answers `{"member", "device", "guest_scope", "app": {"id", "title"},
  "hub": {"version", "protocols"}}`. `GET /hub/check` answers `{"hub": "keep-hub", "ok": true}`.
- Without a token, only `GET` and `HEAD` pass, without a body, and only for a path that can
  be read one way: a path with `..`, an empty segment, a backslash, or one that decodes to
  an `/api` or `/hub` path is refused (`400 bad_path`).
- `Keep-Hub-Auth` is added to every forwarded request, files included, since a backend
  refuses anything without it. The member and device headers are added to `/api/` requests
  only. Besides the `Keep-` and `Authorization` headers, the per-connection headers
  (`Connection`, `Upgrade`, `Expect`, `TE`, `Trailer`, `Proxy-…`) are not passed on.
- A guest invite's scope is 1 to 200 printable ASCII characters without spaces, checked
  when the invite is made, so it travels in `Keep-Guest-Scope` exactly as given.

### On the admin address

All under `/admin/v1/`, with `Authorization: Bearer <admin token>`; the list is at the top
of `admin.rs`. Registering answers `{"id", "secret", "protocol", "hub_version"}`; the secret
is 64 hex characters and is the value of `Keep-Hub-Auth`.

- Registering an app that is already registered (an update) keeps its devices and grants
  and gives a **new** secret. The hub keeps each secret in its key store (`keys/app-<id>.key`,
  sealed on Windows).
- Unregistering revokes the app's devices and also removes its grants and unused invites.
- The hub does not hold an app to the port table in the spec: it refuses a port another app
  holds, the hub's own ports and ports below 1024.
- A grant for an app that declared `money` always needs the PIN on `POST grants`. A pairing
  code needs it only when it has to make the grant.

### Settings

`hub.json` uses the spec's keys as nested names: `{"address": …, "ports": {"helper",
"admin"}, "pair": {"code_minutes"}, "guest": {"invite_days"}}`. The address is set at
`keep-hub setup`, as in ShareKeep, until stage 5.

## Not built in stage 1

- **Changing a forgotten PIN by "an administrator's confirmation".** The spec doesn't say
  how the hub recognises an administrator. Today a PIN is changed only with the old one.
- **The firewall rule** when an app registers (the spec's "adds it to the firewall rule"):
  with the firewall checks of stage 5 and the hub's installer of stage 7.
- **The QR code picture.** The admin address answers with the pairing address
  (`https://<address>:<port>/#pair=<code>`); drawing it is for the Phones screen.
- The hub's two headers (`nosniff`, `no-referrer`) are on the hub's own answers only.
  Adding them to passed-through answers, large files, the 30-second rule's tests and HSTS
  are stage 2.
- Everything in stages 2 to 7: names and the public certificate, the certificate page and
  two certificates on one port, addresses, Find the problem, the small library, the service.

## Verified

- **Linux** (cloud sandbox) and **Windows** (the owner's PC, 2026-11-18): `cargo xtask ci`
  passes on both, so `seal.rs` (DPAPI) compiles and its round-trip test passes on Windows.
  On Windows the guard first caught a hand-made `.cargo/config.toml` saved with CRLF; it
  passed once the file was saved with LF.

## Not verified

- The 10-second head limit and the 64-connection limit have no end-to-end test (the gate
  and the per-address limit have unit tests).
