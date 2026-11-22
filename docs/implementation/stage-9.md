# Stage 9: what was built

Implementer's notes (2026-11-22). This is not a spec: `docs/specs/keep-hub.md` says what the
hub must do. Stage 9 of `AGENTS.md` section 5 is Revisions 2 and 3, acceptance tests 45 to
55. The protocol number stays 1: Revision 2 A says so, and Revision 3 does not touch it.

## Before the stage: a stage 8 test that failed on the working tree

`cargo xtask ci` on the tree as handed over failed:
`administrators.rs` `at31_a_guest_is_removed_as_a_member_too` (the owner's stage 8 answer 6).
`Registry::remove_member` still deleted only `WHERE id = ?1 AND guest_app IS NULL`, so the
guest's row stayed in the list. The stage 8 report says CI passed after that change, so the
file on disk is older than the one that was tested. The guest condition is gone now, and the
doc comment says "a member, of the household or a guest". With that one change the baseline
was 196 passed and 3 ignored, as the stage 8 report says. No test was changed.

## Built

### Revision 2 A: an app chooses how its phones pair

- **Registering** takes `pairing`: `code_and_pin` or `code`. Left out, it is `code_and_pin`.
  Any other value is refused with 400 `bad_registration`.
- **The registry, migration 3:** `apps.pairing`, default `code_and_pin`, so every app
  registered before keeps pairing with the PIN. `Registry::read_apps` (the uninstaller's
  read-only look) works on a registry no hub has migrated yet.
- **The registration answer, the status and the apps list** carry `pairing`.
- **`POST /hub/pair` on a `code` app's port** (`hub.rs`, `Hub::pair`):
  - it takes `{"code", "device"}`;
  - a `pin` in the body is ignored and never checked;
  - `pin_not_set` is never answered;
  - a wrong, used or expired code is a wrong try, counted and paused as before (ten from
    one address, a hundred from all).
- **Making a code for a `code` app** needs no household PIN.
- **Changing `pairing`** on a later registration needs what a first registration needs.
  Keeping the same value needs the admin token only, as before.
- **A `code_and_pin` app** is unchanged: the PIN is asked, and five wrong PINs burn the code.

### Revision 2 B: a household where the computer's sign-in is enough

All in `crates/keep-hub/src/hub/household.rs` unless named.

- **`POST /admin/v1/setup`** takes either form.
  - **Today's form** `{name, password, pin}` answers as before, plus
    `"household": "secured"`.
  - **The open form** `{name, sign_in_is_enough: true}` makes the first administrator with no
    password and no PIN. It answers `{member, "household": "open"}`, with no session.
- **`hub.sqlite` records an open household** as `household = open` in the `kv` table
  (`registry::HOUSEHOLD_KEY`).
- **The status** answers `"household": "open"` or `"secured"`.
- **In an open household** (`Hub::acting_administrator`):
  - every request marked A is accepted with the admin token alone;
  - `POST /admin/v1/session` answers 409 `sign_in_not_used`.
- **`POST /admin/v1/secure` {name, password, pin}** needs the admin token and works in an
  open household only.
  - It sets the named administrator's password and the household PIN, and removes the open
    mark, in one transaction (`Registry::secure`).
  - It answers with a session for that administrator.
  - From then on every rule of "Administrators and standard members" applies. Paired phones
    are untouched.
- **Registering a `code_and_pin` app for the first time in an open household** answers 409
  `household_not_secured`, with the message to set a password and PIN first.
- **`keep-hub reset-administrator` in an open household** says that there is nothing to
  reset, and changes nothing.

### Revision 2 C: ports and names

- The hub never held apps to the port table, so nothing in the hub changed.
- The library has the table as `keep_hub_app::ports` (`MONEYKEEP_EZ` is 14444), so an app
  that copies it has the numbers.
- Turning names on still needs a registration code the first time, in an open household
  too. Nothing in the names code changed for that.

### Revision 3: `names.code_page` and `code_needed`

- **`names.code_page`** is in `hub.json` (`config.rs`). Its default is
  `https://getmoneykeep.org/phone-access/`.
- **`config::check_code_page`** accepts only an `https://` address of at most 200
  characters (reading 11).
- **`PUT /admin/v1/names/code-page` {code_page}** (A) changes the setting. A page the rules
  refuse answers 400 `bad_code_page`, and the old value stays.
- **`GET /admin/v1/names` and `GET /admin/v1/status`** carry `code_page` and
  `code_needed`.
  - `code_needed` is yes while the hub has never registered with the name service in use.
  - It is no afterwards, also after names are turned off and on.
- The hub never opens the page and sends nothing to it.

### The library (`crates/keep-hub-app`)

- **`Registration`:**
  - new field `pairing` (`CODE_AND_PIN` by default; a record saved before reads as that);
  - `Registration::by_code_alone()`.
- **`ensure_registered`** with `code` refuses with `hub_too_old` when the hub doesn't say how
  an app pairs, so the app must not offer pairing. The hub may say nothing in two places:
  - in the status, when it lists apps without `pairing`, the app doesn't register;
  - in the registration's answer, when it has none. The new secret is kept all the same,
    so the backend still checks what the hub forwards.
- **`HubApp.pairing`** is an `Option`: `None` comes from an older hub.
- **`HubStatus`:**
  - `household`, `code_page` and `code_needed`, all `Option`s for older hubs;
  - `household_is_open()`.
- **`HubClient`:** `set_up_open(name)`, `secure(name, password, pin)` (it keeps the session
  it answers) and `set_code_page(page)`.
- **`ports`:** the port table.
- **Changes for an app that copied the stage 8 library:**
  - `Registration` and `HubApp` have new fields, so building either with a struct literal
    needs `pairing` (use `Registration::new`);
  - nothing that already worked changed behaviour.

### Other

- README: one line on open households and pairing by code alone.

## Readings

1. **Changing `pairing` to `code_and_pin` in an open household** is refused with
   `household_not_secured`, as a first registration of such an app would be. Revision 2 B
   names only "for the first time". An update that keeps `code_and_pin` is let through
   (reading 2). (Question 1.)
2. **Where `pin_not_set` is met again** (stage 8 answer 5).
   - A hub upgraded from stage 7 has apps that were registered before any administrator
     existed, so they keep `code_and_pin`. If its first set-up is the open form, those
     apps have no PIN to pair with.
   - Their pairing codes and `/hub/pair` then answer 409 `pin_not_set`. The message now says
     to set a password and PIN for the household.
   - Updating such an app with the same `pairing` still needs only the admin token.
   - Test: `pin_not_set_is_answered_for_a_pin_app_in_an_open_household`.
3. **The open form on an upgraded hub removes a stage 7 PIN**, because "there is no
   household PIN" in an open household.
4. **The first set-up's refusals:**
   - `sign_in_is_enough` together with a password or a PIN answers 400 `bad_setup`;
   - neither form complete answers 400 `bad_setup`. It was 400 `bad_request` from the JSON
     reader; the same status, a clearer code.
5. **The open form answers with no session,** since none is used. The library's
   `set_up_open` gives the member.
6. **Passwords and the PIN in an open household.** `PUT members/<id>/password` and
   `PUT pin` answer 409 `household_not_secured`.
   - `secure` sets both together, so a household is never half secured.
   - "Members added are ... none with a password" is read as: no password can be set until
     the household is secured.
   - Signing out answers ok, with nothing to end. (Question 2.)
7. **`secure` names an administrator who exists:**
   - a standard member's name answers 409 `not_an_administrator`;
   - a name nobody has answers 404 `no_such_member`;
   - the password and PIN rules are the first set-up's;
   - it answers with a session, so the program can go on (test 50 registers with it).
   (Question 3.)
8. **`secure` in a secured household**, made so at the first set-up or by an earlier
   `secure`, answers 409 `already_secured`. A first set-up in either form after it answers
   `already_set_up`.
9. **Administrator names stay unique in an open household too** (`name_taken`), because
   signing in by name starts once it is secured.
10. **`code_page` and `code_needed` in "the names part of the status"** are in both
    `GET /admin/v1/names` (the names status) and `GET /admin/v1/status`, at the top level.
    The status's `names` field stays the state string, because the stage 8 library reads it
    as one. (Question 4.)
11. **How the setting is changed.** The spec gives no request, so it is
    `PUT /admin/v1/names/code-page`.
    - It is marked A, as choosing the adapter is, since it changes what every app's Phones
      screen links to. (Question 5.)
    - "An `https://` address" is read as also needing a host, with no spaces, no control
      characters and no `user@`.
    - A `hub.json` edited by hand with a page the rules refuse is shown as the default.
12. **`code_needed` is yes again with a different `names.service`**, because a name belongs to
    its name service and turning on there needs a new code (the existing rule).

## Earlier tests changed, and why

- `library.rs` `an_app_finds_no_hub_a_stopped_hub_and_a_running_one` and
  `at23_no_hub_offers_the_launchers_entry_and_a_stopped_hub_is_offered_a_start` (stage 7)
  failed on Windows, their first run there.
  - On Windows, `find` believes a hub folder only when the administrators, SYSTEM or a
    service own it (stage 7's rule against a planted folder). A test's temporary folder is
    the person's own, so `find` rightly answered `not_the_hubs_folder`.
  - The rule is right, so the tests now check it: on Windows they expect that refusal (from
    `find` and from `offer`), and test the running and stopped hub through
    `HubClient::open`, the step after the owner check.
  - Elsewhere they are as before. The shipped code is unchanged, with no bypass for tests.
  - `Ready` and `StartHub` from `offer` are therefore checked on Linux and macOS only.
    Making an administrator-owned folder in a test would need elevation.
- `keep-hub-app` `client.rs` unit tests
  `a_missing_folder_is_not_installed_and_an_unreadable_token_says_so` and
  `a_hub_that_doesnt_answer_is_stopped_and_the_port_comes_from_hub_json` (stage 7) failed
  on Windows for the same reason.
  - `find` now calls a private `find_with(data, owner check)`. The unit tests give it a check
    that passes, and on Windows they also assert that the real `find` refuses their folder.
  - Being private, it isn't something an app can call.
- The stage 8 fix above was in the code, not in a test.

## Acceptance tests covered

| Test | Where |
|---|---|
| 45 | `revisions.rs` `at45_a_code_app_pairs_without_a_pin_and_its_token_works_for_it_only`, `at45_the_same_body_on_a_code_and_pin_apps_port_is_refused`; library `an_open_household_and_a_code_app_through_the_library` |
| 46 | `revisions.rs` `at46_a_wrong_code_on_a_code_apps_port_is_a_wrong_try` |
| 47 | `revisions.rs` `at47_pairing_is_code_and_pin_unless_said_and_shown_everywhere`; `registry.rs` `a_registry_from_before_pairing_choices_keeps_code_and_pin`; library `register.rs` `an_older_record_pairs_with_the_pin`, `a_code_app_on_an_older_hub_is_told_to_update_it` |
| 48 | `revisions.rs` `at48_changing_pairing_needs_an_administrator_keeping_it_doesnt` |
| 49 | `revisions.rs` `at49_an_open_household_takes_the_admin_token_as_an_administrator`, `at49_reset_administrator_in_an_open_household_has_nothing_to_reset` |
| 50 | `revisions.rs` `at50_a_code_and_pin_app_needs_a_secured_household`, `at50_secure_names_an_administrator_and_checks_the_password_and_pin` |
| 51 | `revisions.rs` `at51_a_secured_household_stays_secured` |
| 52 | `revisions.rs` `at52_phones_paired_before_secure_work_after_it` |
| 53 | `revisions.rs` `at53_todays_first_set_up_makes_a_secured_household`; tests 27 to 32 in `administrators.rs`, unchanged and passing |
| 54 | `revisions.rs` `at54_the_status_shows_the_code_page_and_whether_a_code_is_needed` (fake name service) |
| 55 | `revisions.rs` `at55_a_code_page_that_isnt_https_or_is_too_long_is_refused`; `config.rs` `the_code_page_is_an_https_address_of_200_characters_at_most`; library `the_code_page_through_the_library` |

Tests 1 to 44 still pass.

`cargo xtask ci` on Linux (rustc 1.97.0) passed: fmt, clippy `-D warnings`, 217 tests with
3 ignored, workflows, guards. The 3 ignored are the same as before: tests 13 and 22 need the
staging services, and the browser test needs Playwright.

## Not checked here

- **Windows and macOS:** nothing platform-only changed in this stage. The Windows service
  code was not compiled here, as in stages 7 and 8. `cargo xtask ci` on Windows compiles it.
- **`scripts/ci/windows-install.ps1`** is unchanged and was not run (no PowerShell here). Its
  `apps` scenario uses today's first set-up, which is unchanged.
- **Tests 13 and 22** against the staging services, and the browser test, are still not run.

## For the spec writer

The questions of this report:

1. Should changing an app to `code_and_pin` in an open household be refused, as built
   (reading 1)?
2. In an open household, should setting a password or a PIN on its own be refused (as
   built), with `secure` the only way to get them (reading 6)?
3. Should `secure` take the name of an administrator who already exists, as built, and
   answer with a session (reading 7)?
4. Should `code_page` and `code_needed` go in both the names status and the status, as built
   (reading 10)?
5. Should the code page be changed with `PUT /admin/v1/names/code-page`, marked A, as built
   (reading 11)? The admin address table could list it.

Also:

- The admin address table could list `POST /admin/v1/secure` by its path, and `PUT
  /admin/v1/names/code-page`.
- `bad_setup`, `already_secured`, `sign_in_not_used`, `household_not_secured` and
  `bad_code_page` are the codes used. The spec names the third and fourth.

## Stage 10: open points to settle first

Revision 4 leaves two open points that the brief asks me to raise before building part D:

1. **`admin.token` on Linux:**
   - group-readable: group `keep-hub`, mode 0640, with the installing user (and others
     chosen) added to the group by `postinst`;
   - or world-readable: 0644, which matches the Windows rule "the computer's users may read
     it" most closely.
2. **Key sealing on Linux:**
   - Without a new dependency, what I can meet is a file readable by the service user only:
     `keys/` mode 0700 under `/var/lib/keep-hub`, owned by `keep-hub`, with
     `ProtectHome=yes`.
   - The desktop keyring (Secret Service) needs a signed-in person's session, which a
     system service doesn't have.
   - The kernel keyring (`keyctl`) is memory only, so keys would be lost at a reboot.
   - Either would need a new dependency, which I'd propose first.
   - The status words would be "Keys are protected by file permissions only."

Parts A to C need neither answer.
