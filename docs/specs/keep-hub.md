# Spec: The shared hub (`keep-hub`)

- **Area / module:** shared hub; new program `keep-hub` used by every Keep and Pick app
- **Spec writer:** Claude session 2026-11-18 (spec-writer role; no target or prior-art source read)
- **Date:** 2026-11-18
- **Status:** draft

## Sources

| # | Type | Reference | Notes |
|---|---|---|---|
| 1 | Spec | ShareKeep `docs/specs/hub-and-client.md`, `web-app.md`, `installers.md` | Today's hub: listeners and their limits, certificate authority, pairing code and PIN rules, device tokens, outbox, service install. The shared hub starts from this code (the project's own work) |
| 2 | Spec | MoneyKeep `docs/specs/mobile-capture.md`, `docs/known-limits.md` | The Slint WASM phone client, its loading and caching, firewall check and Fix, the limit this spec removes ("if your computer's address changes, every phone has to install the new certificate again") |
| 3 | Spec | `name-service.md` in the `keep-name-service` repository (`docs/specs/`) | The service that gives a hub its name and places certificate proofs |
| 4 | Standard | RFC 8555 (ACME) | Requesting and renewing a certificate; DNS challenge |
| 5 | Vendor doc | Let's Encrypt, Rate Limits; staging environment | 50 new certificates per registered domain every 7 days; 5 per exact name every 7 days; staging has much higher limits and an untrusted root |
| 6 | Standard | RFC 6066 section 3 (Server Name Indication) | One listener can answer with different certificates by the name the phone asked for |
| 7 | Standard | HTML Living Standard: origin, storage, service workers; W3C Web Application Manifest; Content Security Policy Level 3 (`wasm-unsafe-eval`); WebAssembly Web API (streaming compilation needs `application/wasm`) | A web app's saved data is kept per scheme, host and port |
| 8 | Standard | RFC 9110 (HTTP), RFC 6750 (bearer tokens), RFC 8484 (DNS over HTTPS) | |
| 9 | Vendor doc | OPNsense manual, Unbound DNS, Private Domains; Plex support article on secure connections | Routers with DNS rebinding protection block public names that point to home addresses |
| 10 | Owner decision | 2026-11-18: the hub is its own release package, installed and updated by keep-launcher; an app offers it and hands over to the launcher; one shared hub per computer; one name and certificate per computer; a port per app; one household PIN; access granted per app; a new shared hub with VacaPick as its first app; MoneyKeep and ShareKeep move later; WASM and plain web clients both supported; wrong pairing tries pause the address they came from, and everyone only after a hundred; removing a grant does not revoke devices; a phone's request id is passed on in `Keep-Request-Id`; the request and answer details the implementer chose in stage 1 are adopted as written here; every member is an administrator or a standard member; every phone, a second one included, needs an administrator's approval; administrators approve at the hub computer only, not from a phone; HSTS is sent for one day; the hub has its own ACME client; the hub's outgoing requests trust what the operating system trusts; the public resolver is Cloudflare's, then Google's; the implementer's readings in stages 2 to 4 are adopted as written here | |
| 11 | Spec | keep-launcher `README.md`, `docs/known-limits.md` | The launcher installs each app from its official release package, checked against the release's SHA-256 checksums; on a Mac it cannot install or update yet (no Developer ID) |
| 12 | Standard | RFC 6797 (HTTP Strict Transport Security) | `max-age` in seconds; `includeSubDomains` is optional |

No target product was observed.

## Purpose

A household runs several Keep and Pick apps on one computer and uses them from phones on
the home Wi-Fi. They want to set a phone up once without installing a certificate, decide
which person may use which app, and have it keep working when the computer's address
changes.

The shared hub is the one program on the computer that phones connect to. It owns the
secure name and certificate, the household PIN, the list of members and phones, and the
record of who may use which app. It passes each request to the app it belongs to. It does
not hold any app's books or rules.

## Behaviour

### The parts

| Part | What it is |
|---|---|
| `keep-hub` | The service. One per computer, started with the computer |
| An app's **backend** | Each app's own local server on a loopback port. It holds the app's books and rules and serves the app's web client files |
| The **name service** | The Cloudflare Worker in `name-service.md`. Only the hub talks to it |
| A **web client** | The app as a phone runs it: a Slint WASM client or a plain HTML and JavaScript client. The hub treats both the same |

### One name, a port per app

- The hub has one name, `<id>.hub.getmoneykeep.org`, and one certificate for it.
- Each app answers on its own port under that name. A browser keeps saved data apart by
  scheme, name and port, so each app's web client has its own storage, service worker and
  home-screen entry.
- The hub listens on every registered app's port. An app never listens on the Wi-Fi
  address itself.

| App | Port |
|---|---|
| MoneyKeep | 14443 (today's) |
| ShareKeep | 15443 (today's) |
| VacaPick | 16443 |
| Later Pick apps | 16444 upward, one each |
| Certificate page (fallback) | 16080, plain HTTP |
| Admin, this computer only | 127.0.0.1:16081 |

These are the ports the apps are given. The hub does not hold an app to this table: it
accepts the port an app registers with unless another app holds it, it is one of the
hub's own ports, or it is below 1024.

### How a request travels

1. A phone connects to `https://<name>:<app port>/...`.
2. The hub completes the secure connection with its certificate.
3. The hub decides by path:

| Path | Who answers | Needs a device token |
|---|---|---|
| `/hub/pair` (POST) | The hub: pairing | No |
| `/hub/whoami` (GET) | The hub: the member's name, the app, the hub's version | Yes |
| `/hub/check` (GET) | The hub: a fixed short answer, for the self-test | No |
| `/api/...` | The app's backend | Yes, with a grant for this app |
| Anything else, GET or HEAD only | The app's backend: the web client's files | No |

4. For `/api/...` the hub checks the token (sent as `Authorization: Bearer`), finds the
   device, checks it is not revoked and that its member holds a grant for this app, then
   forwards the request to the app's loopback port with these headers added:

| Header | Value |
|---|---|
| `Keep-Hub-Auth` | The secret the hub and this app share (see Registering an app) |
| `Keep-Member` | The member's id |
| `Keep-Member-Name` | The member's name, percent-encoded |
| `Keep-Member-Class` | `administrator`, `standard` or `guest` |
| `Keep-Device` | The device's id |
| `Keep-Device-Name` | The device's name, percent-encoded |
| `Keep-Guest-Scope` | Present only for a guest: what the invite was for |
| `Keep-Request-Id` | The request id the phone sent in its own `Keep-Request-Id` header, for safe resends. Passed on only when it is 1 to 128 characters from letters, digits and `-._:~`; otherwise the header is left out |

5. The hub removes every header beginning `Keep-` that a phone sent, and removes the
   `Authorization` header before forwarding. An app's backend never sees a device token.
   The one value a phone can supply is its request id: the hub reads the phone's
   `Keep-Request-Id`, checks it as the table says, and writes the header again itself.
6. An app's backend refuses any request without the right `Keep-Hub-Auth`, and listens on
   127.0.0.1 only.
7. Without a valid token or grant, `/api/...` answers 401 (`not_paired`) or 403
   (`no_access`) from the hub. The app's backend is not contacted.

### Request and answer details

On an app's port:

- **One request per connection.** The hub answers and forwards with `Connection: close`,
  so nothing reaches a backend that the hub did not read and check. A request body needs
  `Content-Length`. `Transfer-Encoding` is refused with 411.
- **Refusals are JSON:** `{"error": "<code>", "message": "<plain words>"}`.

| Status | Code | When |
|---|---|---|
| 400 | `bad_request`, `bad_path`, `bad_name` | The request, its path or a name in it cannot be used |
| 401 | `not_paired` | No token, an unknown token, or a revoked device |
| 403 | `no_access` | The member has no grant for this app |
| 403 | `wrong_code` | A wrong pairing code, invite or PIN |
| 404 | `not_found` | No such `/hub/` path |
| 405 | `method_not_allowed` | A method the path does not take |
| 409 | `pin_not_set` | Pairing before the household PIN exists |
| 411 | `length_needed` | A body without `Content-Length` |
| 413 | `too_large` | A body over the limit |
| 429 | `pairing_paused` | Too many wrong pairing tries |
| 431 | `head_too_large` | A request head over the limit |
| 502 | `app_failed` | The app's backend answered badly or broke off |
| 503 | `app_stopped` | The app's backend is not running |
| 503 | `busy` | The connection limits are reached |

- **`POST /hub/pair`** takes `{"code", "pin", "device"}` for a household member, or
  `{"invite", "name"}` for a guest. It answers
  `{"token", "device_id", "member": {"id", "name", "class"}, "app"}`, with `"guest_scope"`
  for a guest. The token is 64 hexadecimal characters (32 random bytes).
- **`GET /hub/whoami`** answers `{"member", "device", "guest_scope", "app": {"id",
  "title"}, "hub": {"version", "protocols"}}`. `member` includes its class.
- **`GET /hub/check`** answers `{"hub": "keep-hub", "ok": true}`.
- **`POST /hub/unpair`**, with the device's token, revokes that one device. This is how a
  person removes the app from their own phone.
- **Without a token,** only `GET` and `HEAD` pass, without a body, and only for a path
  that can be read one way. A path with `..`, an empty segment, a backslash, or one that
  decodes to an `/api` or `/hub` path is refused with 400 `bad_path`.
- **`Keep-Hub-Auth` goes on every forwarded request,** files included, since a backend
  refuses anything without it. The member, class and device headers go on `/api/`
  requests only.
- **Per-connection headers are not passed on:** `Connection`, `Upgrade`, `Expect`, `TE`,
  `Trailer` and the `Proxy-` headers.

Connection limits are today's (source 1): at most 64 connections and 8 from one address
per app port; a request head must arrive within 10 seconds until it carries a token;
requests without a token that send a body take one of 2 waiting places.

### Web clients, WASM and plain

The hub passes an app's web client files through unchanged, so an app chooses its own
kind of client. To make both kinds work well:

- **Large files.** A Slint WASM client is several megabytes (MoneyKeep's is about 12 MB
  before compression). The hub streams responses of any size without holding them in
  memory, and gives a download in progress no fixed time limit as long as bytes keep
  moving (closed after 30 seconds with none).
- **Compression.** The hub passes `Accept-Encoding` to the backend and `Content-Encoding`
  back, and never compresses or decompresses itself. An app serves its files already
  compressed (Brotli and gzip), as MoneyKeep's capture server does.
- **Content types.** Passed through untouched. An app must serve `.wasm` as
  `application/wasm`, or browsers refuse the faster streaming start.
- **Caching.** `ETag`, `If-None-Match`, `Cache-Control` and 304 answers pass through, so
  a phone downloads a large client once per version.
- **Security policy.** The hub adds no Content-Security-Policy of its own and never
  weakens the app's. A WASM client's policy must allow `'wasm-unsafe-eval'` in
  `script-src`; a plain client's need not.
- **Secure context.** Service workers, WebAssembly streaming, the clipboard and
  installing to the home screen all need HTTPS that the browser trusts. The hub name
  provides it with nothing installed on the phone.
- **Headers the hub adds to every answer,** its own and those it passes on:
  `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`. A backend's own
  header of the same name is replaced, never sent twice.
- **`Strict-Transport-Security: max-age=86400`** (one day, without `includeSubDomains`)
  is added when the phone used the hub name and the name's certificate is a real one. It
  is not sent to a phone that came by address, and not with a staging certificate. A
  backend's own header of this name is replaced. One day keeps the lock-in small if the
  name's certificate ever lapses; the value can be raised later.
- **Slow answers.** A backend may take up to 120 seconds to start its answer, so an app
  can work out a slow report. Once bytes move, only the 30-second rule above applies.

### Members, grants and devices

- A **member** is a person in the household: an id, a name and a class, kept by the hub.
  An app links a hub member to its own records by the member id.
- A **grant** says a member may use an app. Grants are made on the hub computer by an
  administrator.
- A **device** is one app on one phone: a token (32 random bytes, only its SHA-256
  stored), the member, the app, a name, when it was paired and last seen.
- Removing a grant stops that member's devices for that app at once: their requests
  answer 403 `no_access`. The devices are not revoked. If the grant is given back, the
  same devices work again without pairing.
- Revoking a device keeps its row for the list and refuses its token from then on.
- The household **PIN** is 6 to 12 digits, kept only as an Argon2id hash. There is one
  per household. Knowing it opens nothing without a pairing code.

### Administrators and standard members

Every member is an **administrator** or a **standard member**. A guest is a third kind,
outside the household (see Guests).

| | Administrator | Standard member | Guest |
|---|---|---|---|
| Use the apps they hold a grant for, from their phones | Yes | Yes | Within the invite's scope |
| Remove the app from their own phone | Yes | Yes | Yes |
| See the lists of members, phones and apps on the hub computer | Yes | Yes | No |
| Add, rename or remove members, and change a member's class | Yes | No | No |
| Give and remove grants | Yes | No | No |
| Make pairing codes and guest invites | Yes | No | No |
| Revoke anyone's phone | Yes | No | No |
| Set or change the household PIN | Yes | No | No |
| Turn hub names on or off | Yes | No | No |
| Approve a new app, or remove an app from the hub | Yes | No | No |

How the hub knows an administrator:

- Each administrator has their own **administrator password**, at least 8 characters,
  kept only as an Argon2id hash. It is separate from the household PIN, which every
  member may know.
- On the hub computer, an administrator signs in with their name and password. The hub
  answers with a session that lasts 15 minutes from its last use. The desktop app drops
  it when it closes.
- Five wrong passwords for one administrator in 10 minutes pause sign-in for that
  administrator for 10 minutes.
- A standard member has no password on the hub computer and cannot start a session.

Rules:

- **The first administrator** is made when the hub is first set up: a name, an
  administrator password and the household PIN. Until then the hub accepts nothing else.
- **There is always at least one administrator.** The last one cannot be removed or made
  a standard member.
- **Removing a member** revokes their phones and removes their grants.
- **A forgotten household PIN** is set again by any administrator. The old PIN is not
  needed.
- **A forgotten administrator password** is set again by another administrator. If no
  administrator can sign in, `keep-hub reset-administrator`, run with the computer's own
  administrator rights on the hub computer, sets a new password for a named
  administrator. Paired phones are not affected.
- **Apps see the class** in `Keep-Member-Class` and may use it for their own rules. The
  hub does not decide what a class may do inside an app.
- **Every phone needs an administrator's approval,** a member's second phone included.
  Each one is paired with a code an administrator makes. A standard member cannot add a
  phone for themselves, and a paired phone cannot approve another.
- **Administrators act at the hub computer only.** For now nothing an administrator does
  can be done from a phone, their own included: there is no administrator request on an
  app's port.
- **Every grant is an administrator's act.** This replaces the earlier rule that a grant
  for an app that declared `money` asks for the household PIN.

### Pairing a phone

1. On the hub computer, an administrator picks a member and an app. If the member has no
   grant for the app, the hub makes one first.
2. The hub makes a pairing code for that member and app: 8 characters shown as
   `ABCD-EFGH`, typed forgivingly, one use, 10 minutes. The QR code carries
   `https://<name>:<app port>/#pair=<code>`. With the code, and with a guest invite, the
   admin address gives four addresses: `url` (by name when the name has a real
   certificate, otherwise by address), `url_by_name`, `url_by_address`, and
   `certificate_page`.
3. The phone opens the address. The app's web client sends the code, the PIN and a device
   name to `/hub/pair`.
4. The hub checks the code belongs to this app's port, checks the PIN, makes the device
   and answers with its token. The web client keeps the token in its own storage.
5. Five wrong PINs burn a code.
6. Wrong tries are counted over the last 10 minutes. Ten from one address pause pairing
   for that address only, so one person cannot stop the household from pairing. A hundred
   from all addresses together pause pairing for everyone. A pause ends when the count
   for the last 10 minutes falls below the limit. A paused try answers 429
   `pairing_paused`.

Adding a second app to a phone is the same steps with the other app chosen. Adding a
second phone for the same member is the same steps again: a new code from an
administrator, one phone per code.

### Guests

- An app that declared `guests` can invite someone outside the household.
- An invite is made on the hub computer by an administrator, for one app and one scope
  (a text the app chooses, such as a trip's id). It is 8 characters, one use, valid 7
  days. A scope is 1 to 200 printable ASCII characters without spaces, checked when the
  invite is made, so it travels in `Keep-Guest-Scope` exactly as given.
- A guest sends the invite and a name to `/hub/pair`. No PIN is asked. The hub makes a
  guest member and a device whose requests carry `Keep-Guest-Scope`.
- The app's backend limits a guest to that scope. The hub does not interpret the scope.
- An app that declared `money` cannot declare `guests`. The hub refuses such a
  registration.

### Registering an app

An app's desktop program registers with the hub, the first time the person turns on
phones in that app and again whenever its version changes, through
the admin address using the admin token from the hub's data folder:

| Field | Meaning |
|---|---|
| `id` | Short name, such as `vacapick` |
| `title` | The name people see |
| `version` | The app's version |
| `protocol` | The hub protocol the app was built for (1) |
| `public_port` | The app's port, normally from the table above |
| `loopback_port` | Where the app's backend listens on 127.0.0.1 |
| `money` | True for an app that holds financial records |
| `guests` | True if the app accepts guests |

- The hub answers `{"id", "secret", "protocol", "hub_version"}`. The **shared secret**
  is 64 hexadecimal characters (32 random bytes) and is the value of `Keep-Hub-Auth`.
  The app keeps it sealed for this computer, as today's hub keys are. The hub keeps each
  secret in its key store.
- **The first registration of an app needs an administrator's session.** Registering an
  app that is already registered, as happens after an update, needs only the admin token:
  it keeps the app's phones and grants and gives a new secret.
- A port already taken by another app, a `money` app with `guests`, or a protocol the hub
  does not know is refused with a plain message.
- The hub opens the app's public port at once and adds it to the firewall rule.
- When an app's backend is not running, the hub answers 503 (`app_stopped`) on its port.
- Unregistering closes the port, revokes the app's devices and removes its grants and
  unused invites. It needs an administrator's session. Removing the last app
  leaves the hub installed: it is removed in keep-launcher, like an app.
- A newer hub accepts every older protocol number it has ever supported.

### The name and the certificate

The hub is a client of `name-service.md` and of Let's Encrypt.

States: **Off**, **Registering**, **Proving**, **Ready**, **Blocked** (the home router
refuses the name), **Waiting** (no internet, or a limit was reached).

Turning names on:

1. Register with the name service; keep the id and token sealed in the data folder.
2. Find the home address (see Addresses) and send Set address.
3. Make a private key (ECDSA P-256), open an ACME account with no contact address, order
   a certificate for the one name, and receive the DNS proof value.
4. Send Set proof. Ask a public resolver over DNS over HTTPS until the proof is visible,
   for at most 2 minutes, then tell Let's Encrypt to check. The public resolver is
   Cloudflare's, and Google's if Cloudflare's cannot be reached. This is fixed, not a
   setting.
5. Save the certificate, send Clear proof, start answering by name. State: Ready.
6. Self-test: look the name up through the computer's own resolver and through the
   public resolver. If the public one answers and the home one does not, or answers
   without the address, the state is Blocked and the fallback is offered. Blocked is
   decided only when the public resolver gives this computer's address. When the public
   resolver cannot tell, the state stays as it was.

Turning names off:

- The hub stops using the name and keeps its registration and its certificate, so
  turning on again needs no registration code. Nothing is released at the name service.
- The app ports go back to answering by address only.

The registration code:

- It is needed only the first time. It is sent as typed, kept in memory until used, and
  never stored or logged.
- A name belongs to its name service. With a different `names.service` the hub needs a
  new registration code, and a certificate from the other Let's Encrypt service is not
  used.

Renewing:

- Checked once a day. Renewal starts when a third of the certificate's lifetime remains,
  worked out from the certificate's own dates.
- A failed renewal is retried daily, and so is a failed first certificate. The apps are
  told (through the admin address) only when 14 days or fewer remain.
- "Renew now" on the admin address tries at once. The 7-day limit below still holds.
- A proof that never becomes visible is cleared after the 2 minutes and tried again the
  next day.
- A new certificate replaces the old one without dropping connected phones.

Limits:

- The hub never asks for more than 3 certificates for its name in 7 days, below Let's
  Encrypt's limit of 5, so a fault cannot lock the name out for a week. What is counted
  is each order sent, and it is counted before sending, so a crash cannot let a fourth
  through.
- A refusal for the weekly domain limit puts the hub in Waiting and it tries again after
  the time Let's Encrypt gives. That time is read in seconds only. A date, or none,
  means try the next day.
- Tests and development use Let's Encrypt's staging service and the staging name
  service. `names.staging` selects Let's Encrypt's staging service, and `names.service`
  must then hold the staging name service's address. With `names.staging` on and
  `names.service` still the real service, turning on is refused, so a test hub can never
  touch real names.
- A staging certificate is served by name and never as trusted: no
  `Strict-Transport-Security`, and pairing codes keep to the address.

Building blocks:

- **The ACME client is the hub's own:** RFC 8555 with the DNS challenge only, signing
  with ring and making the certificate request with rcgen, both already in the build.
- **The hub's own outgoing requests** (to the name service, Let's Encrypt and the public
  resolvers) trust what the operating system trusts, through `rustls-platform-verifier`.

### Addresses

- The home address is the IPv4 address of the adapter the default route uses, if it is in
  a private range. The person can choose another adapter.
- The hub looks again at start, when the system reports a network change, and every 5
  minutes. A new address is sent to the name service at once.
- The certificate is for the name, so it stays valid. Paired phones reconnect when the
  old address ages out, within a minute or two.
- With no private address, the state is Waiting and the troubleshooter says the computer
  is not on a home network.

### The fallback: the hub's own certificate authority

Kept from today's hubs (source 1), for homes where names cannot work or the person
declines the name service:

- The hub's own authority (ECDSA P-256, 10 years, name-constrained to the hub's address)
  and a server certificate (825 days, renewed 30 days before it ends).
- The certificate page on port 16080: the fingerprint to compare, the two downloads,
  the steps for the kind of device that asked, then the steps for the others (Android,
  iPhone and iPad, Windows and Mac computers), and a link to each registered app.
- Opened from a pairing code, as `/?app=<id>&pair=<code>` (or `invite=<code>`), the page
  ends with the link that pairs. A code is used only if it is 8 letters and digits;
  anything else is ignored and never shown back.
- The page answers `GET` and `HEAD` only, and sends any other path to `/`. It sits
  behind a front with today's limits: 32 connections, 8 from one address, closed after 15
  seconds without traffic.
- **Both at once.** Each app port answers with the Let's Encrypt certificate when the
  phone asked for the hub name, and with the hub's own certificate when it asked by
  address or for any other name. A phone paired one way and a phone paired the other
  work side by side. A renewed certificate is used for new connections; a connection in
  progress keeps the one it started with.
- A phone paired by address is a different installed app from one paired by name. Moving
  between them means pairing again.
- A changed address still means a new authority and re-installing on phones that use the
  fallback. Phones that use the name are unaffected.

### Finding the problem

The hub runs the checks and gives the results to whichever app asks, in this order,
stopping at the first failure. Each result has a code, plain words, and one action.

| # | Check | Action offered |
|---|---|---|
| 1 | The hub service is running (asked by the app, not the hub) | Start it |
| 2 | This computer has a private home address | Open network settings |
| 3 | The network is set to Private (Windows) | Open the Windows setting |
| 4 | The firewall rule exists for every app port, and no rule blocks the hub | Fix |
| 5 | The name service can be reached | Try again |
| 6 | Public DNS gives this computer's address for the name | Update the name |
| 7 | The home resolver gives the same answer | Use the other way to connect |
| 8 | The certificate has more than 14 days left | Renew now |
| 9 | Each app's backend answers on its loopback port | Start that app |
| 10 | The hub answers `/hub/check` on its own name and each app port | None: go to the phone questions |

### The admin address

On 127.0.0.1:16081, under `/admin/v1/`, for the apps' desktop programs. Every request
carries `Authorization: Bearer <admin token>`. Requests marked A also carry an
administrator's session in `Keep-Admin-Session`.

| Requests | Needs |
|---|---|
| Status: hub version, protocol numbers, each app's state | Admin token |
| Lists: apps, members, grants, devices | Admin token |
| Find the problem: run, results | Admin token |
| Register an app that is already registered (an update) | Admin token |
| First set-up: the first administrator and the household PIN, only while no administrator exists | Admin token |
| Sign in as an administrator, sign out | Admin token, name and password |
| Register a new app, unregister an app | A |
| Members: add, rename, remove, change class, set an administrator's password | A |
| Grants: give, remove | A |
| Pairing codes and guest invites: make, cancel | A |
| Devices: revoke | A |
| Household PIN: set, change | A |
| Names: turn on, turn off, renew now, registration code for the name service | A |

A request marked A without a live session answers 401 `administrator_needed`. The admin
token alone shows that a program runs for a user of this computer. It does not show that
the person is an administrator of the household.

Every app shows the same Phones screen from these requests. The hub has no window of
its own.

### Installing and running

As today's hub (source 1): a Windows service under its own virtual account, never
LocalSystem, restarting on failure; a macOS launch daemon; a data folder only the service
and administrators can use (`%ProgramData%\Keep Hub` on Windows); keys sealed by the
operating system; logs with method, path and status only.

- The hub's data folder holds `hub.json` (public facts), `hub.sqlite` (members, grants,
  devices, apps, the PIN hash, with migrations) and `keys/`.

### How the hub gets onto the computer

The hub is its own release package with its own version, and keep-launcher installs and
updates it. No app's installer carries a copy of the hub.

- **Only on the hub computer.** One computer per household runs the hub. Installing an
  app never installs the hub. Other computers in the home use their apps as clients.
- **In the launcher.** The hub appears in keep-launcher's list as a component, shown as
  "Phone access" with one line saying what it is for. The launcher installs the right
  build, checked against the release's SHA-256 checksums, and updates it like an app.
  It has **Install**, **Update** and **Remove**, and no **Open**: the hub has no window.
- **From an app.** When a person turns on phones in an app and no hub is found on this
  computer, the app asks whether this computer should be the household's hub. On yes,
  it opens keep-launcher at the hub's entry. If keep-launcher is not installed, the app
  shows a link to the hub's download page.
- **Finding the hub.** An app finds the hub by its admin address on this computer and
  the admin token in the hub's data folder. A hub that is installed and stopped counts
  as found: the app offers to start it.
- **After the install,** the app registers itself (Registering an app) and continues to
  the phone setup. The person is not asked to restart the app.
- **Administrator approval.** Installing, updating or removing the hub asks for
  administrator approval once, because it is a service.
- **Updating.** The hub is stopped, replaced and started again. Phones see
  `app_stopped` for the gap and retry. A hub is never replaced by an older version.
- **Removing.** When apps are still registered, Remove says which ones and that their
  phones will stop connecting, and asks again. The data folder is kept unless the
  person also chooses to delete it, so a reinstall keeps the pairings and the name.
- **On a Mac,** until keep-launcher can install there, the hub has its own disk image
  with an installer for the launch daemon, and the app links to it.
- **Without internet,** the hub's setup file can be run directly. It is the same package
  the launcher uses.
- **For development,** keep-launcher's local mirror includes a `keep-hub` checkout
  beside the other apps.

This needs one addition in keep-launcher: a catalog entry for a component that is a
service, with no window to open. That change is specified in keep-launcher's own
repository.

### Where the code lives

A new repository, `keep-hub`, with the hub and a small library apps use to register and
to check `Keep-Hub-Auth`. The name service has its own repository, `keep-name-service`.
The certificate authority, TLS relay, certificate page, PIN hashing and device registry
are copied from ShareKeep's hub and then changed for apps and grants. Each app copies the small library, as the Keep apps
copy from each other, so every app still builds on its own.

## Ledger effect

Non-posting. The hub holds no book and changes none.

## Settings

| Key | Type | Default | Meaning |
|---|---|---|---|
| `names.enabled` | yes / no | no, until the person turns it on | Use a hub name |
| `names.service` | address | `https://names.getmoneykeep.org/v1` | The name service |
| `names.acme` | address | Let's Encrypt production | The certificate authority |
| `names.staging` | yes / no | no | Use both staging services |
| `address.adapter` | text | automatic | Which adapter's address to publish |
| `address.check_minutes` | number | 5 | How often to look for a new address |
| `cert.warn_days` | number | 14 | When to tell the person renewal is failing |
| `pair.code_minutes` | number | 10 | Life of a pairing code |
| `guest.invite_days` | number | 7 | Life of a guest invite |
| `ports.helper` | number | 16080 | Certificate page |
| `ports.admin` | number | 16081 | Admin address |
| `admin.session_minutes` | number | 15 | Life of an administrator's session after its last use |

`hub.json` holds these as nested names: `{"address", "ports": {"helper", "admin"},
"pair": {"code_minutes"}, "guest": {"invite_days"}, ...}`. Until the Addresses part is
built, the address is given at `keep-hub setup`, as in ShareKeep.

## Edge cases

- **Two apps ask for one port.** The second registration is refused and names the app
  that holds it.
- **An app is updated while phones are connected.** Its backend restarts; the hub answers
  `app_stopped` for the gap and phones retry from their outbox.
- **The hub is updated.** Pairings, grants and the certificate survive: the registry has
  migrations, and a registry from a newer hub is refused with a message to update.
- **The household PIN is forgotten.** Any administrator sets a new one on the hub
  computer after signing in. Paired devices keep working.
- **Every administrator has forgotten their password.** `keep-hub reset-administrator`
  with the computer's administrator rights sets a new one.
- **The only administrator leaves the household.** They make another member an
  administrator first. The hub refuses to remove or change the last one.
- **A standard member's program calls an administrator's request.** It has the admin
  token and no session, so the answer is `administrator_needed`.
- **A phone is lost.** An administrator revokes its devices on the hub computer. The PIN need not change,
  because a pairing code is still needed.
- **A guest invite is forwarded to someone else.** It works once. The first person to use
  it holds the device, and it can be revoked.
- **The router blocks the name after setup** (a router update, or a new router). Check 7
  finds it; phones paired by name stop until the exception is added or they are paired
  through the fallback.
- **The name service is gone for good.** Hubs keep their certificates until they end, at
  most 90 days. The fallback keeps working with no outside service.
- **The computer has no internet at home for a long time.** The certificate cannot be
  renewed. The hub warns at 14 days and the fallback remains.
- **A phone uses a VPN or its own private DNS.** The lookup may leave the home network
  and still returns the home address, which the phone can reach only on the home Wi-Fi.
  The phone questions in the troubleshooter cover this.
- **A local program pretends to be the hub to an app's backend.** It lacks the shared
  secret, so the backend refuses it.
- **A phone sends `Keep-Member` itself.** The hub removes it before forwarding.
- **A guest keeps typing wrong codes.** Only that phone's address is paused. The rest of
  the household can still pair.
- **Two adapters, both private** (wired and Wi-Fi). The default route's adapter is used
  unless the person chose one.

## Acceptance tests

1. With two test apps registered on two ports, a request to each port reaches that app's
   backend and never the other's.
2. A device token for app A sent to app B's `/api/` answers 403 `no_access`, and B's
   backend receives nothing.
3. `/api/` without a token answers 401 `not_paired`; a revoked device's token does too.
4. A forwarded `/api/` request carries `Keep-Hub-Auth`, `Keep-Member`, `Keep-Device` and
   the names, and no `Authorization` header. A phone's own `Keep-Member: 1` header is
   removed. A phone's `Keep-Request-Id: req-42` arrives unchanged; one with a space, or
   longer than 128 characters, does not arrive at all.
5. A backend that gets a request without the right `Keep-Hub-Auth` refuses it (tested in
   the small library).
6. Pairing: a code for app A used on app B's port is refused; a good code with a wrong
   PIN five times burns the code; ten wrong tries from one address pause pairing for that
   address while another address can still pair; a hundred wrong tries from many
   addresses pause pairing for all; a good code and PIN return a token that works for
   app A only.
7. Removing a member's grant for an app makes that member's tokens for the app answer
   `no_access` on the next request. The devices still show as paired, not revoked.
   Giving the grant back makes the same tokens work again.
8. Giving a grant without an administrator's session answers `administrator_needed`,
   for an app that declared `money` and for one that did not; with a session it succeeds
   and no PIN is asked.
9. A guest invite pairs without a PIN, once; requests carry `Keep-Guest-Scope`; an expired
   invite is refused; registering an app with both `money` and `guests` is refused.
10. A 12 MB file with `Content-Encoding: br`, `Content-Type: application/wasm` and an
    `ETag` arrives byte for byte with those headers; a second request with `If-None-Match`
    gets 304 with no body; the hub's memory does not grow by the file's size.
11. A plain client's small files and its `Content-Security-Policy` header arrive
    unchanged; the hub adds `nosniff` and `no-referrer`.
12. A download that sends no bytes for 30 seconds is closed; one that keeps sending for 5
    minutes is not.
13. Names, against the staging services: turning on ends in Ready with a certificate for
    the hub's name; the proof record is gone afterwards.
14. With a fake resolver that refuses the name at home and a public one that answers, the
    state is Blocked and the result offers the fallback.
15. A changed address is sent to the name service within one check interval, the
    certificate is unchanged, and a device paired before the change is accepted after it.
16. A certificate with a third of its life left is renewed on the daily check; a failed
    renewal is retried the next day; the warning appears only at 14 days or fewer.
17. A fourth certificate request for the name inside 7 days is not sent.
18. One port, two certificates: a connection that asks for the hub name gets the Let's
    Encrypt certificate; one that asks by address, or for any other name, gets the hub's
    own. A phone paired by name and one paired by address work side by side.
19. An app whose backend is stopped answers 503 `app_stopped` on its port while other
    apps keep working.
20. Find the problem returns the checks in order and stops at the first failure, with a
    fake for the firewall, the resolvers and the network type; Fix recreates a missing
    firewall rule with every registered port.
21. A registry made by this hub opens in a later test hub with one more migration; a
    registry marked newer is refused with the update message.
22. End to end in a headless browser against a real hub with a test WASM client and a
    test plain client: open by name, pair, call `/api/`, go offline, come back.
23. With no hub on the computer, turning on phones in a test app offers the hub and
    opens the launcher's entry (a fake launcher); with a stopped hub, it offers to start
    it and installs nothing.
24. Installing the hub alone, with no app registered, leaves a running service that
    listens on the admin address and the certificate page only.
25. Remove with two apps registered names both and asks again; the data folder is still
    there afterwards, and a reinstall has the same name and pairings.
26. An update to an older version is refused.
27. First set-up makes the first administrator and the household PIN; a second first
    set-up is refused; before it, every other admin request is refused.
28. Signing in with a good name and password gives a session that works for 15 minutes
    after its last use and not after; five wrong passwords pause that administrator's
    sign-in for 10 minutes while another administrator can still sign in.
29. A standard member cannot sign in as an administrator. Each request marked A answers
    `administrator_needed` with the admin token alone, and the lists and status answer
    without a session.
30. The last administrator cannot be removed or made a standard member; with two
    administrators, one can.
31. Removing a member revokes their devices and removes their grants.
32. `keep-hub reset-administrator` sets a new password for a named administrator and
    leaves members, grants and devices as they were; for a standard member's name it
    refuses.
33. A forwarded `/api/` request carries `Keep-Member-Class` with `administrator`,
    `standard` or `guest`; a phone's own `Keep-Member-Class` header is removed.
34. Registering a new app needs a session; registering the same app again does not,
    keeps its devices and grants, and gives a new secret.
35. `POST /hub/unpair` revokes the calling device only.
36. Without a token: `GET /app.js` passes; a `POST`, a `GET` with a body, and paths with
    `..`, an empty segment, a backslash or an encoded `/api` are refused with `bad_path`
    or `method_not_allowed`. A body with `Transfer-Encoding` answers 411.
37. An app may register a port that is not in the table; a port another app holds, one of
    the hub's own, or one below 1024 is refused.
38. A pairing code works for one phone: a second phone using the same code is refused,
    and a new code from an administrator pairs it. No request on an app's port, with an
    administrator's device token, makes a pairing code, a grant or an invite.

39. An answer to a phone that used the hub name with a real certificate carries
    `Strict-Transport-Security: max-age=86400`, on the hub's own answers and on those
    passed on, replacing a backend's own. A phone that came by address gets none, and so
    does one served a staging certificate.
40. Making a pairing code answers with `url`, `url_by_name`, `url_by_address` and
    `certificate_page`. `url` is by name when the name has a real certificate and by
    address otherwise, including with a staging certificate.
41. The certificate page opened with `?app=<id>&pair=<code>` ends with the link that
    pairs for that app; a parameter that is not 8 letters and digits is not shown back; a
    `POST` gets no page; another path is sent to `/`.
42. Turning names off leaves the ports answering by address only and keeps the
    registration and certificate; turning on again needs no code and asks for no new
    certificate while the old one is good.
43. With `names.staging` on and `names.service` the real service, turning on is refused
    and nothing is sent.
44. A backend that sends nothing for 119 seconds and then answers is passed on; the
    hub's `nosniff` and `no-referrer` replace a backend's own headers of those names.

## Open points

- The words keep-launcher shows for the hub, and whether it lists the hub among the apps
  or in a separate place.
- The staging name service's address. `names.service` must hold it for a test hub, and
  neither spec gives it yet.
- The certificate page's steps for Windows and Mac computers are new and need checking
  on a real PC and a real Mac.
- Which program shows the Phones screen when several apps are installed: each app with a
  shared component, or keep-launcher.
- When MoneyKeep and ShareKeep move onto the shared hub, and how their paired phones are
  carried over. Their ports stay the same, so a phone paired by address could keep its
  storage if the certificate authority is carried over too.
- Reaching the hub from outside the home through Cloudflare is a separate spec. The
  request path, grants and headers here are meant to serve it unchanged.
- IPv6 home addresses.
- How phones with private DNS or relay features behave with a name that points to a home
  address. This needs testing on real iPhones and Android phones.

## Clean-room check

- [x] No code, pseudo-code from source, or internal identifiers from any target or prior-art project
- [x] No copied UI wording, layouts or screenshots
- [x] Every claim traceable to a source above
