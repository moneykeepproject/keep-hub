# Stage 6: what was built

Implementer's notes (2026-11-18). This is not a spec: `docs/specs/keep-hub.md` says what the
hub must do. Stage 6 of `AGENTS.md` section 5 is the small library apps copy, with its tests.

## Owner decisions on 2026-11-18

- **The admin token can be read by the computer's users.** The spec says an app's desktop
  program reads the admin token from the hub's data folder, and also that only the service
  and administrators can use that folder. An app runs as the signed-in person, so it
  couldn't read the token. The owner chose to keep the folder locked and give the
  computer's users read access to `admin.token` alone. Anyone signed in to the hub computer
  can then manage the hub, much like today's hubs. Stage 7's installer sets this
  permission. The spec writer should add it to "Installing and running".
- **What the library covers:**
  - finding the hub, registering, and registering again when the version changes;
  - checking `Keep-Hub-Auth` and reading the hub's `Keep-` headers;
  - typed calls for every request the Phones screen makes.
- **The library seals the shared secret** for this computer, with a copy of the hub's
  `seal.rs` (DPAPI on Windows, an owner-only file elsewhere).
- **Its own crate, `crates/keep-hub-app`**, which an app copies as a folder.

## Built: `crates/keep-hub-app`

It depends on serde, serde_json, sha2, zeroize and, on Windows, windows-sys, with the
versions written out. It has no HTTP crate (the admin address is plain HTTP on 127.0.0.1)
and nothing from keep-hub, so the folder builds wherever it is copied. It never logs, and
its errors and `Debug` output hold no secret.

- **The backend's side** (`auth.rs`):
  - `HubAuth` holds only the SHA-256 of the shared secret and compares in constant time.
    `HubAuth::load(app_data)` reads the sealed secret without contacting the hub.
  - `check(headers)` takes a request's headers as pairs (owned, borrowed or references),
    with names in any case. It answers:
    - `Ok(Some(Caller))`: an `/api/` request, with the member, the member's name, the
      device, the device's name, a guest's scope and the request id. Names are
      percent-decoded.
    - `Ok(None)`: from the hub without a phone (the web client's files).
    - `Err(Refused)`: a status and code to answer with.
  - `caller(headers)` is the same for requests that need a phone.
  - The refusals:
    - 403 `not_from_hub`: the secret is missing, wrong or sent twice.
    - 400 `bad_identity`: half an identity, numbers that aren't numbers, or a header
      sent twice.
    - 401 `not_paired`: `caller` with no phone.
  - `listen(port)` binds the backend to 127.0.0.1 only.
- **The desktop program's side** (`client.rs`):
  - `find(data)` answers `NotInstalled`, `NoAccess` (the token can't be read),
    `Stopped` or `Running` with the hub's status. The spec counts an installed, stopped
    hub as found; the app offers to start it.
  - `HubClient` reads the admin port from `hub.json` (16081 when not given) and the
    token from `admin.token`.
  - It has a typed call for each admin request: status, apps, unregister, members,
    grants, devices, pairing codes, invites, the PIN, the name, addresses, Find the
    problem. `request` covers anything not wrapped yet.
  - Refusals come back as `HubError` with the hub's own status, code and words.
  - `Pairing` (a code or invite with its addresses) doesn't print its code in `Debug`.
  - `default_data_folder()` is `%ProgramData%\Keep Hub` on Windows, as the spec says.
    Elsewhere it is `None` until the spec names a folder.
- **Registering** (`register.rs`):
  - `Registration::new(id, title, version, public_port, loopback_port)`, with `.money()`
    and `.guests()`.
  - `ensure_registered(hub, registration, app_data)` registers only when needed: the
    first time, when anything in the registration changed (such as the version), when
    the hub lost the app or its secret, or when the secret here can't be read. The hub
    makes a new secret with every registration.
  - It keeps the secret sealed in `keep-hub-app.secret` and what was registered in
    `keep-hub-app.json` (no secret). Both are owner-only on Unix.
  - It answers whether it registered just now, so a running backend knows to load the
    secret again.
  - A hub that doesn't know the app's protocol gets `hub_too_old`, which says to update
    the hub in keep-launcher.

## Acceptance tests covered

| Spec test | Where |
|---|---|
| 5 | `crates/keep-hub/tests/library.rs`: `at05_a_backend_made_with_the_library_refuses_requests_without_the_right_keep_hub_auth`; and the unit tests in `keep-hub-app/src/auth.rs` |

The tests against a real hub are in keep-hub's tests, not in the library's folder, so the
library copies without them. They use a backend built only from the library and check:
- finding no hub, a stopped hub and a running one;
- registering once per version, again after the secret or the app is lost, and refusals
  in the hub's words (protocol, money with guests, a port taken);
- a paired phone and a guest as the backend sees them, and the old secret refused after
  a new registration;
- every Phones screen request;
- a stopped backend in the status and in Find the problem;
- a wrong admin token, with no token in the error.

To prove acceptance 5 is a real test: with the secret check broken to accept anything,
it fails.

## How an app uses it

1. Copy `crates/keep-hub-app` into the app's repository and add it as a path dependency.
2. In the desktop program, when the person turns on phones:
   - `find(&default_data_folder()?)`, offering to install or start the hub as the spec
     says;
   - then `ensure_registered`, at that time and at each start;
   - the Phones screen uses `HubClient`.
3. In the backend, `listen(loopback_port)` and `HubAuth::load(app_data)`. Check every
   request with `check` (`caller` for `/api/`), answering a refusal with its status and
   code. After `ensure_registered` says `now`, load the secret again.

## Not built here

- The permission on `admin.token` for the computer's users: stage 7's installer.
- The data folder on macOS and Linux: the spec doesn't name it.
- Starting a stopped hub, and opening keep-launcher at the hub's entry: the app does
  these with the system's service tools and keep-launcher.
- Two programs of the same app registering at once would each get a secret, and the
  last one wins. An app registers from its desktop program only.

## For the spec writer

- The permission on `admin.token` (above).
- The hub's data folder on macOS and Linux.
- The status and code a backend answers when `Keep-Hub-Auth` is wrong. The library uses
  403 `not_from_hub`.
