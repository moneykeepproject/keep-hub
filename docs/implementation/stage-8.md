# Stage 8: what was built

Implementer's notes (2026-11-19). This is not a spec: `docs/specs/keep-hub.md` says what the
hub must do.

## Owner decisions on 2026-11-19

- **Revision 2 needed rules that were never built.** The PC's code was stage 7, but the
  spec by then also held the administrator model (acceptance tests 27 to 44, and a changed
  test 8). The owner split the work in two:
  - **stage 8** (this one): the administrator model and the other newer rules, tests 8 and
    27 to 44;
  - **stage 9**: Revision 2 (tests 45 to 53) and Revision 3 (tests 54 and 55).
  Each stage has its own notes and CI report, and the owner sees this report before stage 9
  starts.
- Nothing of Revision 2 or 3 is in this stage. The protocol number stays 1.

## Built

### Administrators and standard members (`crates/keep-hub/src/hub/household.rs`)

- **Classes.** Every member is `administrator`, `standard` or `guest`. The members list
  shows each one's `class` and `password_set`, never the password or its record.
- **Passwords:** 8 to 256 characters, kept only as an Argon2id record in the PIN's form and
  with the PIN's parameters (`pin.rs`).
- **The first set-up:** `POST /admin/v1/setup {name, password, pin}`, only while no
  administrator exists. It makes the first administrator, sets the household PIN, and
  answers with a session.
- **Signing in:** `POST /admin/v1/session {name, password}` answers with a session.
  `DELETE /admin/v1/session` signs out.
- **Sessions:**
  - 32 random bytes, sent in `Keep-Admin-Session`. The hub keeps only their SHA-256, in
    memory.
  - A session lasts `admin.session_minutes` (default 15, in `hub.json` under `admin`) from
    its last use.
  - It ends on sign-out, when the hub restarts, and when its administrator is removed or
    made a standard member.
- **Wrong passwords:** five for one administrator in 10 minutes pause that administrator's
  sign-in for 10 minutes. Others can still sign in.
- **Requests marked A** need a live session, or answer 401 `administrator_needed`. Which
  requests are marked is in `admin.rs`'s header and below.
- **Members:**
  - `POST members {name, class?}` (standard by default);
  - `PUT members/<id> {name}`;
  - `PUT members/<id>/class {class}`;
  - `PUT members/<id>/password {password}`;
  - `DELETE members/<id>`: their phones are revoked (the rows stay, as for any revoked
    phone), their grants go, and so do their pairing codes.
  - The last administrator can't be removed or made a standard member
    (`last_administrator`).
- **The household PIN** is set or changed by an administrator. The old PIN is not needed.
- **Grants** ask for no PIN, money or not. A `pin` field sent by an older program is ignored.
- **The first registration of an app** needs a session. Registering it again needs the
  admin token only, and keeps its phones and grants. Unregistering needs a session.
- **`keep-hub reset-administrator --name <name> [--data <folder>]`** sets a new password
  for a named administrator, read from the standard input. Members, grants and devices
  are left as they were. A standard member's name, or a name nobody has, is refused.

### The registry

- **Migration 2:** each member gets a class and a password column. Existing household
  members become standard members, existing guests become guests. A registry from stage 7
  therefore has no administrator, and the hub asks for the first set-up.
- **`busy_timeout` of 5 seconds**, because `reset-administrator` writes while the hub runs.

### The phone side (`relay.rs`)

- **`Keep-Member-Class`** on every forwarded `/api/` request. A phone's own header of that
  name is removed, as every `Keep-` header is.
- **`/hub/whoami` and the pairing answer** give the member's class; `whoami` also gives
  `hub {version, protocols}` as before.
- **`POST /hub/unpair`** revokes the calling device, and no other.

### The library (`crates/keep-hub-app`)

- **The backend:** `Caller` has `class` and `is_administrator()`. A class the hub never
  sends is refused as an unreadable identity. A hub older than stage 8 sends none, so the
  class is `None`.
- **The desktop program:**
  - `HubClient` keeps an administrator's session in memory, so it goes when the app closes:
    - `set_up` and `sign_in` keep it;
    - `sign_out` and `signed_in`.
  - New: `add_member_as`, `set_class`, `set_password`, `remove_member`.
  - `Member` has `class` and `password_set`.
  - `find` gives `Found::NotSetUp`, and `offer` gives `Offer::SetUp`, for a running hub with
    no administrator.
- **Breaking changes** for an app that copied the stage 6 or 7 library:
  - `give_grant` and `make_pairing_code` no longer take a PIN;
  - `set_pin` no longer takes the old PIN.

### Other

- **A GET with a body and no token** answers 405 `method_not_allowed` (test 36). It was
  400 `bad_request`.
- **The first-byte wait** (120 seconds) is now a hub option, `HubOptions::first_byte`, so
  test 44 can use 2 seconds. The shipped value is checked to be 120.
- **`scripts/ci/windows-install.ps1`, scenario `apps`:**
  - it checks that a new app is refused without a session;
  - it does the first set-up, or signs in on a later run;
  - it runs `reset-administrator` against the installed service and signs in with the new
    password.
- **README:** one line on administrators.

## Readings

1. **Before the first set-up "the hub accepts nothing else"** is read as: every admin
   request but the set-up answers 409 `setup_needed`, the status and lists included (test
   27 says "every other admin request"). The admin token is still checked first. The
   library reads `setup_needed` from the status as "running, not set up". Paired phones of
   a hub upgraded from stage 7 keep working: their requests aren't admin requests.
2. **On a hub upgraded from stage 7,** the first set-up makes a new member as the first
   administrator and replaces the household PIN. There is no way to make an existing
   member the first administrator. (Question 1.)
3. **Administrators have names of their own**, because signing in is by name. Names are
   compared without case or surrounding spaces. Making a second administrator with an
   administrator's name, by adding, renaming or changing class, answers 409 `name_taken`.
   Standard members may share names. (Question 2.)
4. **Sign-in refusals:**
   - 403 `wrong_password` for a wrong password, and for a name nobody has (that one isn't
     counted: there is no administrator to pause);
   - 403 `not_an_administrator` for a standard member's name;
   - 403 `no_password` for an administrator who has none yet;
   - 429 `sign_in_paused` during a pause, even with the right password.
   - The pause starts at the fifth wrong password inside 10 minutes. A good sign-in clears
     the count.
5. **"15 minutes from its last use":** any request that carries a live session is a use,
   lists and status included (owner, question 7).
6. **Made a standard member, an administrator's password is removed.** Made an
   administrator again, they have no password until another administrator sets one. This
   matches Revision 2's wording.
7. **Setting another administrator's password** ends that administrator's sessions. The
   caller's own session goes on.
8. **Guests through `members`:** an administrator removes a guest as any member, and their
   phone is revoked (owner, question 6). Renaming a guest or changing their class answers
   409 `guest_member`.
9. **Two requests are not in the spec's table:**
   - "send the address to the name service again" (`POST names/address`) needs the token
     only;
   - "which adapter's address to use" (`PUT address`) is marked A, because it changes how
     every phone reaches the hub.
   (Question 4.)
10. **`pin_not_set` can no longer happen:** the first set-up always sets a PIN, and no
    request removes one. The checks stay, unreachable for now. (Question 5.)
11. **`/hub/unpair`:**
    - it works without a grant (a phone whose grant was removed can still remove itself);
    - another app's token on this port answers `not_paired` and revokes nothing;
    - a GET answers 404.
12. **`reset-administrator`:**
    - the password comes on the standard input, so it is never on a command line that other
      programs can read. It is visible as it is typed: hiding it would need a new
      dependency;
    - "with the computer's administrator rights" is enforced by the data folder's
      permissions, not by a check in the program;
    - on Windows `--data` defaults to `%ProgramData%\Keep Hub`;
    - it doesn't end sessions or a sign-in pause in a running hub, which are in the hub's
      memory. (Question 8.)
13. **Test 41, "ends with the link that pairs"**, is read as stage 6 read it. The page's
    step 2, after the downloads, is the pairing link. An "Already installed?" list of plain
    app links follows it.
14. **Test 40:** `url_by_name` is null when the name has no real certificate (stage 6's
    reading), so `url` is the address then, as the test asks.
15. **Test 36, a GET with a body:** the spec allows `bad_path` or `method_not_allowed`.
    It is `method_not_allowed`, as for a POST. (Question 9.)

## Earlier tests changed, and why

Each change follows a rule the spec changed. None was loosened to make code pass.

- `hub.rs`:
  - `pairing_needs_a_pin_a_live_code_and_a_name`: no "no PIN yet" state any more, and a new
    PIN needs no old one. It now shows that the old PIN stops pairing.
  - `at08_...`: rewritten as the spec's new test 8, and renamed
    `at08_a_grant_needs_an_administrators_session_and_no_pin`.
  - `at09_...guest...`: finds the guest by `guest_app` (the administrator is first in the
    list now), and checks its class.
  - `the_admin_address_needs_the_admin_token_...`: the list now holds the administrator too.
    It also checks that no password record is ever shown.
  - `only_what_the_hub_checked_reaches_a_backend`: a GET with a body is 405 (test 36).
- `names.rs`, `the_hubs_https_client_...`: it needed any refusal. "No PIN set" can't happen
  now, so it uses a wrong code.
- `relay.rs` unit test: the exact header list has `Keep-Member-Class`, and the phone's own
  is shown dropped.
- `library.rs`, `browser.rs`: the client signs in (or does the first set-up), and uses the
  new calls.
- The test fixture does the first set-up and signs in on start. `Fixture::not_set_up()` is a
  hub without one.

## Acceptance tests covered

| Test | Where |
|---|---|
| 8 | `hub.rs` `at08_a_grant_needs_an_administrators_session_and_no_pin` |
| 27 | `administrators.rs` `at27_first_setup_...`, `at27_a_set_up_hub_stays_set_up_after_a_restart` |
| 28 | `administrators.rs` `at28_a_session_lasts_15_minutes_...`, `at28_the_session_length_is_the_admin_session_minutes_setting`, `at28_five_wrong_passwords_...` |
| 29 | `administrators.rs` `at29_a_standard_member_cant_sign_in_and_a_needs_a_session` (all 19 requests marked A, and 12 token-only ones), and three more `at29_` tests |
| 30 | `administrators.rs` `at30_the_last_administrator_stays_one` |
| 31 | `administrators.rs` `at31_removing_a_member_...` |
| 32 | `administrators.rs` `at32_reset_administrator_...` (the real `keep-hub` program, against a running hub); also in `windows-install.ps1` |
| 33 | `administrators.rs` `at33_...`; `relay.rs` unit test; library `auth.rs` unit tests |
| 34 | `administrators.rs` `at34_...`; also in `windows-install.ps1` |
| 35 | `administrators.rs` `at35_unpair_revokes_the_calling_device_only` |
| 36 | `rules.rs` `at36_...`; also `hub.rs` `only_what_the_hub_checked_reaches_a_backend` |
| 37 | `rules.rs` `at37_...` |
| 38 | `administrators.rs` `at38_...` |
| 39 | `rules.rs` `at39_hsts_...`, `at39_no_hsts_with_a_staging_certificate`; also `fallback.rs` `at18_...` |
| 40 | `rules.rs` `at40_...`; also `fallback.rs` |
| 41 | `rules.rs` `at41_...`; also `fallback.rs` |
| 42 | `rules.rs` `at42_...`; also `fallback.rs` and `names.rs` |
| 43 | `rules.rs` `at43_...`; also `names.rs` |
| 44 | `rules.rs` `at44_...` (2 seconds standing for 120; the shipped 120 is checked) |

Tests 1 to 26 still pass. The registry's migration from stage 7 has its own unit test
(`a_registry_from_before_classes_gets_them_and_no_administrator`).

## Not checked here

- **The browser test** (`browser.rs`, `the_browser_part_against_a_local_hub`, ignored by
  default) can't run in this sandbox now. Chrome's connections are reset before reaching
  the hub. Stage 7's code fails the same way here today, although it passed here during
  stage 7, so the sandbox changed, not the hub. To run it on your PC:
  `cargo test -p keep-hub --test browser the_browser_part_against_a_local_hub -- --ignored`
- **`windows-install.ps1`'s new steps** haven't run: there is no PowerShell here. They run
  in the Windows workflow, or from an administrator PowerShell, as in stage 7.
- **Windows-only Rust code:** nothing Windows-only changed in this stage.
  `reset-administrator`'s Windows default folder uses `cfg!`, so both branches are compiled
  here.
- **Tests 13 and 22 against the staging services** are still not run, as in stage 7.

## Owner answers (2026-11-19)

The questions of this report, answered:

1. **An upgraded hub's first administrator:** as built. The first set-up makes a new member
   and sets a new PIN.
2. **Administrator names:** stay unique (`name_taken`).
3. **The status before the first set-up:** refused, as built.
4. **The two requests not in the table:** as built. Choosing the adapter is marked A;
   re-sending the address needs the token only.
5. **`pin_not_set`:** stays as an unreachable check; stage 9 meets it again.
6. **Guests:** an administrator can remove a guest as a member. Changed after the
   report: `DELETE members/<id>` takes a guest too
   (`at31_a_guest_is_removed_as_a_member_too`).
7. **What extends a session:** any request that carries it. Changed after the report
   (`at28_a_session_lasts_15_minutes_from_its_last_use`).
8. **`reset-administrator` and a running hub's sessions and pauses:** enough as built.
9. **Test 36's GET with a body:** 405 `method_not_allowed`, as built.

After the two changes, `cargo xtask ci` passed again: 196 tests, 3 ignored (tests 13 and
22, as before).
