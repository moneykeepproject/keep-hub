# Stage 3: what was built

Implementer's notes (2026-11-18). This is not a spec: `docs/specs/keep-hub.md` says what the
hub must do, and `name-service.md` in `keep-name-service` says what the name service does.
Stage 3 of `AGENTS.md` section 5 is the hub's name and its certificate, against the staging
services.

## Owner decisions on 2026-11-18

1. **The ACME client is the hub's own** (the spec's open point): RFC 8555 with the DNS
   challenge only, synchronous like the rest of the hub. It signs with ring and makes the
   certificate request with rcgen, both already in the build. Not instant-acme, which would
   have added 37 crates, tokio and hyper among them.
2. **Trust for the hub's own requests: `rustls-platform-verifier` 0.7** (MIT OR Apache-2.0,
   from the rustls team). It uses Windows' and macOS's own certificate checks. New crates:
   on Windows, only itself; on macOS, `core-foundation`, `security-framework` and their
   `-sys` crates; on Linux, `rustls-native-certs` and `openssl-probe`. All MIT/Apache/ISC.
   `ring` became a direct dependency of `keep-hub` (it was already compiled in through
   rustls).
3. **The public resolver is Cloudflare's, then Google's** if Cloudflare can't be reached
   (`dns::PUBLIC_RESOLVERS`). Fixed in the code; the spec doesn't name one yet.
4. **Tests use fakes; acceptance test 13 also runs end to end later.** The staging name
   service can't be deployed yet, and the build machine can't reach Let's Encrypt.

The spec writer should add 3 to `keep-hub.md`, and close the ACME open point with 1.

## Built

| Module | What |
|---|---|
| `names.rs` | The states, turning on and off, renewal, the limits, the self-test. Kept in `names.json` (public facts), `hub-name.crt`, and sealed keys |
| `acme.rs` | The ACME client: account, order, DNS challenge, finalize, certificate |
| `nameservice.rs` | The hub's side of the name service: Register, Set address, Set proof, Clear proof |
| `dns.rs` | DNS over HTTPS (RFC 8484 wire format) to the public resolvers; this computer's resolver |
| `client.rs` | The hub's HTTPS client (HTTP/1.1, rustls with ring, the platform verifier) |
| `der.rs` | A small DER reader: a certificate's dates, key and DNS names; a request's key |
| `config.rs` | The `names.*` and `cert.warn_days` settings in `hub.json` |
| `admin.rs` | `GET /admin/v1/names`, `POST names/on`, `names/off`, `names/renew` |

The hub runs the engine on its own thread: whenever the admin address asks, and once a
minute (it does real work only when something is due).

x509-parser was not used: it is only built through an optional rcgen feature, which would
bring in more crates. `der.rs` reads the few fields the hub needs.

## Acceptance tests covered

| Spec test | Where (`tests/names.rs`) |
|---|---|
| 13 | `at13_turning_on_ends_ready_…` with the fakes. `at13_end_to_end_against_the_staging_services` against the real ones, skipped unless run with `--ignored` and `KEEP_HUB_E2E_SERVICE`, `KEEP_HUB_E2E_CODE` (see the test) |
| 14 | `at14_a_router_that_refuses_the_name_is_blocked_…`, and `when_the_public_resolver_cant_tell_…` |
| 16 | `at16_renewal_starts_at_a_third_of_the_life_…` |
| 17 | `at17_a_fourth_certificate_request_inside_7_days_is_not_sent` |

Also tested: the registration code needed only the first time; a name service that can't
be reached; a proof that never appears (2 minutes, then cleared, tried the next day); Let's
Encrypt's limit and its Retry-After; restarts; staging; secrets kept out of the log and the
public files; the admin routes; the HTTPS client against a real TLS server.

### How strict the fake ACME server is

It checks every request's nonce, URL and ES256 signature against the account's key, wants
the proof in the fake name service's TXT record, and issues for the public key in the hub's
certificate request. Checked: with the hub's signing deliberately broken, the fake refused
it and the test failed.

## Readings of the spec to confirm

1. **Turning off** stops using the name and keeps the registration and the certificate, so
   turning on again needs no code. Nothing is released at the name service. ("Forget the
   name" isn't in the spec.)
2. **Staging needs the staging name service's address in `names.service`.** `names.staging`
   switches Let's Encrypt to its staging directory, but neither spec gives the staging name
   service's address. With `names.staging` on and `names.service` still the real service,
   turning on is refused, so a test hub can never touch real names.
3. **A name belongs to its name service.** With another `names.service` the hub needs a new
   registration code, and a certificate from the other Let's Encrypt service isn't used.
4. **"Retried daily"** applies to a first certificate as well as a renewal. "Renew now" on
   the admin address tries at once (the 7-day limit still holds).
5. **The 7-day limit counts orders sent** (`newOrder`), counted before sending, so a crash
   can't let a fourth through.
6. **Blocked** is decided only when the public resolver gives this computer's address:
   then a home answer without it (or none) is Blocked. When the public resolver can't tell,
   the state stays as it was.
7. **The ACME account** has no contact address.
8. **`Retry-After`** is read in seconds only. A date form, or none, means try the next day.
9. **The address** is the one in `hub.json` until stage 5 (Addresses).
10. **The registration code** is sent as typed; the name service ignores case and dashes.
    It is kept in memory until used, never stored or logged.

## Not built

- **Serving the certificate to phones**, and HSTS with it: stage 4 (both certificates on one
  port, chosen by the name the phone asks for). The spec gives no HSTS `max-age`.
- **Finding the address and following its changes** (test 15): stage 5.
- **Find the problem** checks 5 to 8: stage 5.

## Known

- **Stopping the hub waits for a certificate request in progress** (up to a few minutes:
  2 for the proof, 2 for Let's Encrypt). Matters when the hub is a service (stage 7).
- **Verified on Linux only** so far. `rustls-platform-verifier` is built for Windows for the
  first time on the owner's PC; `the_systems_trust_can_be_set_up` checks it starts there.
- The end-to-end test hasn't run: it needs the staging name service deployed.
