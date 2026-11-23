# Stage 11: what was built

Implementer's notes (2026-11-23). This is not a spec: `docs/specs/keep-hub.md` says what the
hub must do. Stage 11 is Revision 5 (other programs on this computer; fixes from the code
review `claude/keep-hub-code-review-2026-11-23.md`), acceptance tests 66 to 79. The spec
says `AGENTS.md`'s build order gains it as stage 11; `AGENTS.md` itself isn't changed here
(it isn't mine to edit).

The revised spec also amends Revision 4 with the owner's stage 10 answers. All of that was
already built in stage 10. Its two new test numbers are given to tests that existed: 64 is
`tunnel.rs`'s `at64_…` pair (wrong tries counted per visitor), 65 is `linux.rs`'s
`at65_…` and the library's `at65_the_library_gives_the_firewall_words` (new).

`cargo xtask ci` passes on Linux: 278 tests, 5 ignored. The protocol number is now 2; the
hub accepts 1 and 2.

## Owner decisions on 2026-11-23

- **Revision 5 B on a Mac (an open point of the revision):** not checked yet. On a Mac the
  library sends as before. The Mac is unprotected against B's threat until the Mac hub is
  revisited.
- **A new direct dependency, `libc` 0.2** (MIT OR Apache-2.0), on Linux and Mac only. It was
  already built as a dependency of ring and getrandom. It lets an accept loop wait on its
  socket with `poll` (below, H). Windows uses `WSAPoll` from `windows-sys`, which the hub
  already had; only a feature was added.

## Built

### H first: the review's two defects

- **Ports come back (finding 1, test 73).** An accept loop no longer needs a connection to
  its own port to stop. Each loop waits on its socket with the system's poll for up to 100
  ms, then looks at its stop flag (`relay::next_connection`), so closing works when the
  address has already gone. A connection that comes is taken at once, not at the end of
  the wait: the 40-file test still takes about 0.4 s. (A first try that polled `accept`
  every 50 ms took 2 s there. The test says why that was ruled out before.)
- At every look that finds the home address unchanged, the hub opens any app port or the
  certificate page that should be open and isn't (`Hub::reopen_missing`). A port that still
  can't be opened is logged once per reason, not at every look.
- A port's connection count is now given back by a guard however its thread ends
  (`relay::Counted`), for the review's smaller point about panics.
- **Member ids are never used twice (finding 2, test 74).** Registry migration 4 makes
  `members` again with `AUTOINCREMENT`. Its counter starts above every id a member, a
  device or a grant has ever had, so a registry from before can't give a removed member's
  id either. The same migration adds each member's `epoch` (E).

### A. Protocol 2: the backend proves it holds the secret (`proof.rs`, `relay.rs`, `problems.rs`; the library's `auth.rs`)

- **For a protocol 2 app, each forwarded request starts with the hello.** The hub sends
  `GET /_keep-hub/hello` with its challenge (32 random bytes in hexadecimal) and nothing
  from the phone.
- **The backend answers 204** with `Keep-Hub-Proof` (hexadecimal HMAC-SHA256, keyed with
  the shared secret, of `keep-hub app proof 2`, a line feed and the hub's challenge), its
  own challenge, and `Connection: keep-alive`.
- **The hub checks the proof with ring's `hmac::verify`** (constant time).
  - A wrong, missing or late (5 s) proof closes the connection.
  - The hub logs one line, `app <id>: a program that is not <title> answered on its port`,
    without the challenge or the proof.
  - The phone gets 502 `app_unverified`.
  - An answer with anything after the 204's head is refused too: those bytes would have
    been read as the request's answer.
- **Then, on the same connection,** the phone's request goes as before, with
  `Keep-Hub-Auth: 2 <proof>` for the backend's challenge.
- **Check 9** runs the same hello for a protocol 2 app, and fails as `app_unverified`
  with the spec's words.
- **Protocol 1 apps** get the secret as before, with no hello.
- **The status and `/hub/whoami`** list `protocols: [1, 2]`.
- **The library's side** (`keep-hub-app`, `PROTOCOL` now 2):
  - `HubAuth::hello(peer, path, headers)` answers the hello.
  - `HubAuth::check_from(peer, headers)` accepts the hub's proof once, only on the
    connection that issued the challenge. A connection is known by its remote address
    (`peer`), which every server gives, so the library works with any HTTP server.
  - A challenge is used up by the first request on its connection, right or wrong, and
    lives 30 seconds at most. At most 256 wait at once.
  - `HubAuth` remembers the protocol it was registered with (`with_protocol`; `load` reads
    it from `keep-hub-app.json`).
  - At protocol 2 the secret itself is refused, by `check_from` and by the old `check`.
  - `proofs::app` and `proofs::hub` give the two proofs, for tests.
  - The library now depends on `ring` 0.17, as the spec says (HMAC "from ring, which the
    family already uses").
- **An app whose library speaks 2 on a hub that knows only 1** registers with 1, as before
  protocol 2. Once the hub is updated, it registers again with 2: an upward change needs the
  token alone (C). (For the spec writer, below.)

### B. The library checks who listens on the admin address (`keep-hub-app/src/listener.rs`)

- **Before anything is sent** on a connection to the admin address (every request carries
  the admin token), the library checks who accepted it:
  - **Windows:** every socket listening where 127.0.0.1:<port> can arrive (127.0.0.1,
    0.0.0.0, `::`, `::ffff:127.0.0.1`; `GetExtendedTcpTable`, IPv4 and IPv6) must belong to
    the process the service manager reports for `KeepHub` (`QueryServiceStatusEx`);
  - **Linux:** those sockets in `/proc/net/tcp` and `tcp6` must belong to user `keep-hub`,
    whose uid comes from `/etc/passwd`;
  - **a Mac:** not checked (owner decision above).
- **A failed or impossible check sends nothing.** The answer is `hub_not_confirmed` with the
  spec's words: "Can't confirm that the program on this computer's port 16081 is Keep Hub."
  (with the client's real port). `find` takes it as a stopped hub, as the spec's "check 1
  failing" asks.
- **Tests and development:** `Listener::ThisAccount` expects the account this program runs
  as.
  - On Linux that is the owner of `/proc/self`; on Windows, the user SID of the listening
    process's token.
  - It is given per client (`HubClient::expecting`) or for the whole program
    (`expect_this_account()`).
  - Both exist only in a debug build (`cfg(debug_assertions)`), so an app's release build
    can't offer them.
  - The hub's own test files that use the library call `expect_this_account()` first.

### C. Registering again (`hub.rs` `register`)

- **A registration needs what a first registration needs** (an administrator) when it
  changes any of these: `public_port`, `loopback_port`, `money`, `guests`, `pairing`, or a
  lower protocol. Otherwise it answers 401 `administrator_needed` and changes nothing.
- **A change of `title`, `version` and a higher protocol** needs the token alone, as
  before.
- **`household_not_secured`** still applies only to a new app or a change of pairing, as
  in Revision 2.

### D. The home address and its authority (`ca.rs` `switch_authority`, `hub.rs`)

- **One authority per address.**
  - Before the home address changes, the authority in use (`hub-ca.crt`, `hub-ca.json`,
    `hub-server.crt`) is copied to `authorities/<address>/`.
  - Its two keys are kept sealed in `keys/` as `hub-ca-key-<a-b-c-d>` and
    `hub-tls-key-<a-b-c-d>`.
  - An address used before has its authority put back. Only a new address gets a new
    one, as before.
  - `authorities/authorities.json` lists the addresses, the most recently used first. Four
    are kept, the one in use included: a fifth address deletes the oldest's folder and
    keys.
  - The same happens when the hub starts after moving while it was stopped.
- **On Windows a Public network isn't home.**
  - A new address on a network Windows calls Public is not taken: the hub keeps its last
    home address and sends nothing to the name service. It says so in the log once.
  - Check 3 now looks at the address the computer is on now, not the one kept, so it
    fails as `network_public` as before.
  - On Linux and a Mac every private address counts.

### E. Administrator sessions (`hub/household.rs`)

- **A session ends `admin.session_max_hours` (12) after sign-in**, however often it is used.
  The 15 minutes after last use still apply.
- **`keep-hub reset-administrator` raises that administrator's `epoch`** with the new
  password, in one write.
  - A session from before the reset answers `administrator_needed` at its next use, with the
    hub running throughout.
  - Their sign-in pause is cleared the same way: the wrong-password count is kept per epoch.
- **Setting a password at the admin address** already ended that administrator's other
  sessions, keeping the caller's own (stage 8). Test 75's companion test shows it.

### F. Wrong pairing tries through the tunnel (`hub.rs` `throttle`)

- **Every wrong try is recorded with the listener it arrived on**: the home address, or the
  tunnel's loopback listener.
- **The hundred-in-10-minutes pause counts each listener's tries apart.** A hundred through
  the tunnel pause pairing through the tunnel only, and the reverse.
- **Ten from one visitor still pause that visitor.**

### G. A code-alone app on the certificate page (`hub.rs` `open_addresses`, `page.rs`)

- **For an app registered with `pairing: code`:**
  - a pairing code's `certificate_page` is `/?app=<id>`, with no code;
  - the page ignores `pair=` for that app. Its step 2 opens the app with no code and asks
    the person to type the code shown on the hub computer.
- **Unchanged:** guest invites, the HTTPS addresses (the code after `#`) and apps that pair
  with the PIN.

### H. The rest

- **A failed start is restarted on Windows.**
  - `keep-hub install-service` now runs `sc failureflag KeepHub 1`, so a start that reports
    stopped with an error counts as a failure.
  - The failure actions are now 30 seconds each, the last repeating for every later
    failure. They were 5 s, 5 s and 60 s. The spec says "(30 seconds)", and a minute
    between tries could miss test 79's minute.
- **The Windows data folder is locked before anything is written in it.**
  - `install-service` makes the folder and runs `service::windows_lock` before setup
    writes a key or the token: owned by the administrators, with only SYSTEM and the
    administrators in it.
  - The service's own account doesn't exist until the service is made, so it is let in
    afterwards, by the same steps as before.
- **Linux: `UMask=0077`.** `hub.sqlite`, `hub.log`, `hub.json` and `keys/` are the service
  user's alone. `admin.token` stays 0640 for the group, and the folder stays 0750.
- **The hub's outgoing requests try each address** a name resolves to, in order
  (`client.rs` `connect_any`).
- **A release is built only after the tests pass, and only for its own version.**
  `release.yml` has two new jobs that run first:
  - `version` checks that the tag is `v` plus what `keep-hub version` reports (a new
    command);
  - `tests` runs `cargo xtask ci` on Windows and Linux.
  - The Windows, Linux and Mac builds need both.
- **`CAP_NET_ADMIN`** is unchanged: the spec now records it as an accepted cost.

## Acceptance tests

| Spec test | Test |
|---|---|
| 64 | `tunnel.rs`: `at64_through_the_tunnel_wrong_pairing_tries_are_counted_per_visitor`, `at64_on_the_home_address_the_header_doesnt_move_the_count` |
| 65 | `linux.rs`: `at65_on_linux_registering_says_when_the_firewall_keeps_the_port_closed`; `library.rs`: `at65_the_library_gives_the_firewall_words` |
| 66 | `revision5.rs`: `at66_a_program_without_the_secret_gets_the_hello_and_nothing_else`; `proof.rs` unit tests |
| 67 | `keep-hub-app` `auth.rs`: `at67_a_proof_counts_once_on_its_own_connection`, `the_hello_is_answered_with_a_proof_and_a_challenge` |
| 68 | `revision5.rs`: `at68_protocol_1_works_as_before_and_going_down_needs_an_administrator` |
| 69 | `revision5.rs`: `at69_the_library_sends_nothing_to_a_program_that_isnt_the_hubs_service` (Windows and Linux); `listener.rs` unit tests |
| 70 | `revision5.rs`: `at70_moving_an_apps_ports_or_flags_needs_an_administrator` |
| 71 | `addresses.rs`: `at71_an_address_used_before_gets_its_authority_back` |
| 72 | `addresses.rs`: `at72_on_windows_a_public_network_isnt_home` |
| 73 | `addresses.rs`: `at73_ports_and_the_page_come_back_with_the_address`; `relay.rs`: `a_stopped_loop_ends_without_a_connection` |
| 74 | `registry.rs`: `at74_a_removed_members_id_is_never_given_again`, `a_registry_from_before_revision_5_never_gives_a_removed_id_again` |
| 75 | `revision5.rs`: `at75_a_reset_ends_the_session_and_a_session_lasts_at_most_12_hours`, `setting_a_password_ends_that_administrators_other_sessions` |
| 76 | `revision5.rs`: `at76_the_tunnels_wrong_tries_and_the_homes_are_counted_apart` |
| 77 | `revision5.rs`: `at77_a_code_alone_apps_code_stays_off_the_certificate_page`; `page.rs` unit test |
| 78 | `linux.rs`: `at62_at78_the_deb_installs_…` (end to end, ignored; `linux.yml` runs it); `service.rs` unit test for `UMask=0077` |
| 79 | `service.rs`: `at79_a_failed_start_is_started_again_once_the_port_is_free` (Windows, end to end, ignored; `windows.yml` now runs it after the setup); `service.rs` unit test for the steps' order |

## Not checked here

- **Windows-only code wasn't compiled here** (this environment builds for Linux only).
  That is the library's Windows listener check, the hub's `WSAPoll`, the service steps and
  test 79. I checked each call against `windows-sys` 0.61's own declarations. The Windows CI
  job and the Windows setup workflow are the first compile and run.
- **Tests 76, 71, 72 and at64's home half need 127.0.0.2,** so they don't run on a Mac.
  The Mac isn't in CI any more.
- **Tests 78 and 79 are end to end.** They run in `linux.yml` and `windows.yml` on the next
  push. Neither has run yet.
- **Finding 1 on real hardware:** the old failure needed an address that really goes away.
  The tests show that a loop ends without a connection and that a port comes back once it
  can be opened. Turning the Wi-Fi off for 30 seconds and on again on the Windows PC is
  still worth doing once.

## For the spec writer

1. **A connection is known by its remote address.** The library recognises "the connection
   that issued that challenge" by the connection's remote address and port, which every
   server gives, rather than by a handle into the server.
2. **The HMAC key.** The key is the secret as the hub gives it: its hexadecimal text as
   bytes, not the decoded bytes.
3. **Falling back to protocol 1.** An app whose library speaks 2 registers with 1 on a hub
   that knows only 1, then again with 2 after the hub is updated. The spec doesn't say what
   the library does on an older hub.
4. **The hello is refused when bytes follow the 204's head.** They would otherwise be read
   as the request's answer.
5. **"Can't confirm … port 16081"** gives the client's real admin port, which is 16081
   except in tests.
6. **B's error code is `hub_not_confirmed`.** The spec gives only the words.
7. **Four authorities are kept, the one in use included,** and the order is by most recent
   use. Going back to an address makes it the newest again. Test 71 is written that way:
   after A, B, A, B, C, D and E, A's authority is gone.
8. **The Windows failure actions changed from 5, 5 and 60 seconds to 30 seconds each**
   (H's "(30 seconds)").
9. **Revision 5's other open points** (guest invites on the certificate page; the sign-in
   pause any token holder can keep up) aren't built. They need the owner's answer.
10. **`keep-hub version`** is a new command, for the release check.
