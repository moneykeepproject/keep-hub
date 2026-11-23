# Stage 10: what was built

Implementer's notes (2026-11-22). This is not a spec: `docs/specs/keep-hub.md` says what the
hub must do. Stage 10 of `AGENTS.md` section 5 is Revision 4, acceptance tests 56 to 63:
the probe, the tunnel hostname, Fix as an admin request, and the Linux service with its
`.deb`. The protocol number stays 1.

## Owner decisions on 2026-11-22

- **Stage 9's five questions:** as built.
- **`admin.token` on Linux:** group `keep-hub`, mode 0640. The installing person is added to
  the group.
- **Sealing keys on Linux:** systemd credentials, with keys readable by the service user only
  as the fallback. No new dependency.
- **The Linux firewall (option 1 of three I put to the owner).** The spec's
  `AmbientCapabilities=CAP_NET_ADMIN` doesn't let the service change ufw (which refuses
  anyone but root) or firewalld (whose polkit policy refuses a service user). So:
  - the package opens the certificate page's port at install, as root;
  - ServicesKeep does Fix on Linux;
  - the hub's `POST /admin/v1/problems/fix` on Linux answers 409 `fix_in_serviceskeep`;
  - the capability stays, and is now used only to read the rules for check 4.

## Built

### A. The probe (`probe.rs`, `relay.rs`, `page.rs`, `hub.rs`)

- **`GET /_probe/<nonce>`** on every app port and on the certificate page's port.
  - It answers 204 with no body and no `Content-Length`, and is never forwarded.
  - The nonce is 16 to 64 letters and digits. Anything else is 404 with nothing recorded.
  - Other methods are 404.
- **Rate limit:** one request a second from one address. Above that, 429 and nothing is
  kept.
- **Recording:**
  - a nonce the hub issued is recorded the first time it is seen, with the time and the
    source;
  - an unknown nonce of the right shape answers 204, is counted and isn't kept;
  - the thousandth in an hour logs one line, with no nonce in it;
  - log lines show the path as `/_probe/-`.
- **Source:**
  - `tunnel`: Cloudflare's `CF-Connecting-IP` header on the loopback listener;
  - `this_computer`: a loopback address or the hub's own home address;
  - `home`: a private or link-local address;
  - `outside`: anything else (reading 3).
- **The loopback listener.** The tunnel's ingress points at `https://127.0.0.1:<app port>`
  (`cloudflare-tunnel.md`, step 4), so each app port now also listens on 127.0.0.1.
  - Only that listener believes Cloudflare's header.
  - Its address is `HubOptions::tunnel_listen`.
  - When the home address is that address, as in the tests' hubs, there is one listener,
    and it is the loopback one.
- **On the certificate page's port**, the front now reads the request line before passing
  bytes to the page. A probe is answered there, where the visitor's address is known.
  Anything else goes on to the page with the line it read.
- **`POST /admin/v1/probe`** (A) answers `{nonce, url, expires, minutes}`.
  - `url` is `https://<name>:<first app port>/_probe/<nonce>` when names serve a
    certificate and an app is registered.
  - Otherwise it is `http://<address>:16080/_probe/<nonce>`, or null with no home address.
- **`GET /admin/v1/probe/<nonce>`** (token only) answers `{seen: false}` or
  `{seen: true, when, source}`. A nonce the hub doesn't hold answers 404 `no_such_probe`.
- **`probe.minutes`** (default 10) is in `hub.json`.
- **`/hub/check`** now answers
  `{"hub", "ok", "probe": "/_probe/<nonce>", "tunnel_hostname"}`.

### B. The tunnel hostname (`config.rs`, `hub.rs`, `names.rs`, `nameservice.rs`)

- **`tunnel.hostname`** is in `hub.json`.
  - It is set with `PUT /admin/v1/tunnel {hostname}` (A) and cleared with
    `DELETE /admin/v1/tunnel` (A).
  - It must be empty, or at most 253 characters of labels made of letters, digits and
    hyphens. It is kept in lower case, without a final dot.
  - A refused name answers 400 `bad_hostname` and the setting stays.
- **The status** has `"tunnel": {"hostname"}`, and `/hub/check` has `tunnel_hostname`.
- **`PUT /admin/v1/tunnel/moneykeep-name`** (A) calls the name service's Make tunnel,
  `POST /hubs/<id>/tunnel {port}`, with the first registered app's port.
  - It answers `{hostname, port, token}` and sets the hostname to the away name the service
    answered.
  - The token is in that answer and nowhere else: not in any file, not in any log, not in
    `Debug`.
  - A repeat answers the token again.
  - A refusal answers 502 `name_service_refused`, with the service's own words.
- **`DELETE /admin/v1/tunnel/moneykeep-name`** (A) calls Remove tunnel, then clears the
  hostname.
- **Both routes answer 404** unless names are on, the hub is registered, and the name service
  has taken its address.

### C. Fix as an admin request (`problems.rs`, `machine.rs`)

- **`POST /admin/v1/problems/fix {check: 4}`** (A) runs Fix inside the service, then answers
  `{check: <check 4's new result>, done: [...]}`.
- **The firewall rule** now carries `ports`: every registered app port and the certificate
  page's. Windows' rule names the program and covers any port, as before. The ports are
  there for firewalls that can't name a program.
- **Any other check** answers 400 `no_fix`, with that check's action in words. A number that
  isn't 1 to 10 answers 400 `bad_request`. On Linux the request answers 409
  `fix_in_serviceskeep`.
- **Check 4's action** now also gives `method`, `path` and `body` for this request.
  `command` (`keep-hub fix-firewall`) stays for today's apps.
- **The `Machine` trait** gained `os()`, so a fake can play Linux. The tests' fake machine
  plays Windows unless a test says otherwise, as before.

### D. The Linux service

- **`installer/linux/`:**
  - `keep-hub.service`:
    - runs as user and group `keep-hub`, with `StateDirectory=keep-hub` (mode 0750) and
      `UMask=0027`;
    - `AmbientCapabilities=CAP_NET_ADMIN` and `CapabilityBoundingSet=CAP_NET_ADMIN`;
    - `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`;
    - `Restart=on-failure` after 30 seconds, started at boot;
  - `keep-hub.sysusers`: the `keep-hub` user and group;
  - `postinst`, `prerm`, `postrm`.
- **`keep-hub install-service` on Linux** runs as root from `postinst`:
  - It seals a random 32-byte master key with
    `systemd-creds encrypt --with-key=auto` into
    `/etc/credstore.encrypted/keep-hub-master` (mode 0600). That uses the TPM when there is
    one, otherwise systemd's own key for this computer.
  - It writes a drop-in that gives the key to the service with `LoadCredentialEncrypted=`.
    The drop-in is written only when the key was made, so a system without `systemd-creds`
    still starts the service, with keys protected by file permissions only.
  - It runs `systemd-sysusers`, and `usermod -aG keep-hub <person>` for `SUDO_USER` or
    `PKEXEC_UID` (never root).
  - It opens 16080 in ufw (comment "Keep Hub") or firewalld. Plain nftables is left alone:
    a rule added at run time is gone after a reboot.
  - It finishes with `daemon-reload`, `enable` and `restart`.
  - A firewall or `usermod` step that fails doesn't stop the install. The exit codes are
    Windows' `Exit` codes.
- **`keep-hub remove-service`** on Linux runs `systemctl disable --now`.
  - `prerm` runs it on remove, and only stops the service on upgrade.
  - `dpkg -r` keeps `/var/lib/keep-hub` and the credential, so a reinstall's keys still
    open.
  - `dpkg -P` deletes the folder, the credential and the drop-in, and asks nothing.
- **`keep-hub service-run` on Linux** is what the unit runs. It refuses to start outside
  systemd (no `INVOCATION_ID`), so running it by hand can't set a hub up.
  1. It takes the master key from `$CREDENTIALS_DIRECTORY`.
  2. It sets the hub up at the first start (no home network: it logs the reason, exits,
     and systemd tries again in 30 seconds).
  3. It makes `admin.token` 0640 and the folder 0750.
  4. It logs to `hub.log`.
- **Sealing (`seal.rs`).** With the master key, every key file is sealed with AES-256-GCM
  (ring), behind the marker `KHL1`, with a fresh nonce each time.
  - Plain key files from before are sealed the first time they are read, as on Windows.
  - The status has `"keys": {"sealed", "words"}`. The words are "Keys are sealed by
    systemd for this computer." or "Keys are protected by file permissions only."
- **Check 3 on Linux** passes with "Not needed on this system."
- **Check 4 on Linux** (`linuxfw.rs`):
  - **Which firewall is on:**
    - ufw, when `/etc/ufw/ufw.conf` says `ENABLED=yes`;
    - firewalld, when `systemctl is-active firewalld` says so;
    - plain nftables, when an input chain drops by default or has a drop or reject rule;
    - otherwise none: it passes with "No firewall is on."
  - **Which ports are open:** ports and ranges accepted by a `tcp dport` rule in
    `nft -j list ruleset`, which the service may read with `CAP_NET_ADMIN`. ufw (through
    iptables-nft) and firewalld both keep their rules there.
  - **A closed port** fails as `firewall_ports_closed`, naming the firewall and the ports.
    The action is `{kind: "serviceskeep", ports, firewall}`.
  - If nft can't be asked, the check is `unknown`.
- **`cargo xtask deb`** (`xtask/src/deb.rs`) builds `dist/keep-hub_<version>_<arch>.deb` and
  its `.sha256`.
  - It holds the program, the unit, the sysusers file, the scripts, and the licences with
    `THIRD-PARTY-LICENSES.txt` (84 crates).
  - It is made with `dpkg-deb --root-owner-group`.
  - A pre-release is written with `~` (`0.2.0~alpha.1`).
  - The maintainer is `KH_DEB_MAINTAINER`, or a placeholder `MoneyKeep Project
    <maintainer@example.invalid>` (question 5).
- **`cargo xtask guards`** now also checks the line endings of everything in
  `installer/linux/`, and `.gitattributes` keeps that folder LF. A shell script with CRLF
  doesn't run.

### The library (`crates/keep-hub-app`)

- **New calls on `HubClient`:**
  - `probe()` and `probe_seen(nonce)`;
  - `set_tunnel_hostname` and `clear_tunnel_hostname`;
  - `make_moneykeep_tunnel()`, which answers `MoneyKeepTunnel`. Its token is
    `Zeroizing` and never in `Debug`;
  - `remove_moneykeep_tunnel()`;
  - `fix(check)`.
- **`HubStatus.tunnel`.**
- **On Linux:**
  - `default_data_folder()` is `/var/lib/keep-hub`;
  - `start_command()` is `systemctl start keep-hub.service`, which the app runs with the
    system's permission prompt.

### Also fixed

- **`util::write_private` used one temporary name per file.** Two threads writing
  `names.json` at once (the names engine, and turning names on or off) could make one of
  them fail with "No such file or directory".
  - Stage 9's test 54 met it about one run in ten here.
  - Each write now has its own temporary file. Test:
    `writes_of_one_file_at_once_all_succeed`.
  - The writes still don't merge: the later one wins (question 6).

### Found by the first Windows run (2026-11-22)

`cargo xtask ci` on the owner's Windows PC passed after two fixes:

- **`seal.rs`:** `seal_with` (Linux sealing) is used only by the tests on Windows, where
  DPAPI seals, so clippy failed on dead code. It is now allowed on Windows only.
- **`page.rs`:** a probe on 16080 was answered after reading the request line only, and the
  connection was closed with the rest of the request unread. Windows then resets the
  connection, and the visitor can lose the 204. A real phone could have too.
  - The front now reads and drops the rest of the request (at most 16 KB and 2 seconds)
    before closing.
  - `the_probe_the_tunnel_hostname_and_fix_through_the_library` found it.

## Readings

1. **"Reads no header but the request line"** and "`tunnel` when it carried Cloudflare's
   header" can't both hold literally. Read as: on the home address and the certificate page,
   nothing but the request line is read; on the loopback listener, only whether
   `CF-Connecting-IP` is present (never its value).
2. **The loopback listener** is every app port on 127.0.0.1, beside the home address.
   Revision 4 B's "does not change which listeners it has" is read as being about the
   hostname setting only.
3. **A source that is none of the three** is recorded as `outside`: a public address on the
   home listener, as from a forwarded port. The spec's three values can't describe it
   truthfully. (Question 1.)
4. **A nonce seen twice keeps its first sighting.** ServicesKeep asks "did the tunnel reach
   it", and a later look from home shouldn't change the answer.
5. **The probe address "when names are on"** is read as "when the hub serves its name's
   certificate and an app is registered". Without an app there is no app port to name.
6. **"The hub's first registered app port"** is the app registered earliest (ties broken by
   port).
   - With no app registered, Make tunnel answers 409 `no_apps`.
   - `name-service.md` also allows 16080, but the ingress is `https` and 16080 is plain
     HTTP, so it isn't sent.
7. **"Only when the hub has set an address"** is read as: the name service accepted the
   address (`names.json`'s `address_sent`).
8. **The probe and the tunnel requests are marked A** where the spec marks them A.
   `GET probe/<nonce>` takes the token only, as the spec says.
9. **The admin log** shows `/admin/v1/probe/-`, as it does pairing codes.
10. **Check 4 on Linux decides "open" from the nftables ruleset alone**, not from ufw's or
    firewalld's own tools, which need root. It doesn't follow rule order: a port with an
    accept rule counts as open even if an earlier rule drops it.
11. **Fix on Linux** answers 409, the owner's option 1. Test 63's "Fix adds exactly that
    port's rule commented Keep Hub" is now ServicesKeep's to meet. The hub's part of it is
    check 4 naming exactly that port in its action.
12. **The hardening in the unit** (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`,
    `PrivateTmp`, a bounding set of one capability) takes rights away. It is read as within
    "nothing more" than `CAP_NET_ADMIN`.

## Earlier tests changed, and why

- **`hub.rs` `only_what_the_hub_checked_reaches_a_backend` and `names.rs`
  `the_hubs_https_client_...`** expected `/hub/check` to answer exactly `{"hub", "ok"}`.
  Revision 4 adds `probe` and `tunnel_hostname` (the later revision wins). Both now expect the
  new answer.
- **`addresses.rs` `at15_...`** checked that 127.0.0.1 stops answering after the home address
  moves to 127.0.0.2. 127.0.0.1 is now also the tunnel's loopback listener, so it keeps
  answering there. The test now checks that it does, and that the home port is on the new
  address only.
- **`service.rs`:** two stage 7 tests said `install-service` and `service-run` are for
  Windows only. Revision 4 D gives them Linux forms.
  - The tests now check that a test can't install anything (not root, or root without the
    package's unit).
  - They check that `service-run` outside systemd refuses and sets nothing up.
- **`keep-hub-app` `starting_names_the_hubs_service`** and
  **`the_spec_puts_the_data_folder_in_programdata_on_windows`** now include Linux.

## Acceptance tests covered

| Test | Where |
|---|---|
| 56 | `tunnel.rs` `at56_a_probe_answers_204_records_its_source_and_reaches_no_backend`, `at56_issuing_a_probe_needs_an_administrator_and_asking_after_it_doesnt`, `at56_with_names_on_the_probe_address_is_by_name_on_the_first_app_port`; `probe.rs` `the_source_is_home_tunnel_or_this_computer` (the `home` source), `a_nonce_is_16_to_64_letters_and_digits`, `unknown_and_badly_shaped_nonces_keep_nothing`; library `the_probe_the_tunnel_hostname_and_fix_through_the_library` |
| 57 | `tunnel.rs` `at57_one_probe_a_second_from_an_address_and_a_nonce_lives_probe_minutes`; `probe.rs` `a_nonce_is_recorded_once_and_kept_for_its_life` |
| 58 | `tunnel.rs` `at58_cloudflares_header_on_the_home_address_is_ignored` (Windows and Linux: it needs 127.0.0.2); `probe.rs` `the_source_is_home_tunnel_or_this_computer` |
| 59 | `tunnel.rs` `at59_the_tunnel_hostname_is_checked_shown_and_removed`; `config.rs` `a_tunnel_hostname_is_labels_of_letters_digits_and_hyphens` |
| 60 | `tunnel.rs` `at60_a_tunnel_from_the_name_service_passes_its_token_once_and_keeps_none`, `at60_with_names_never_turned_on_the_moneykeep_name_routes_are_404` (fake name service) |
| 61 | `tunnel.rs` `at61_fix_for_check_4_puts_the_rule_back_from_the_service`, `at61_any_other_check_has_no_fix`, `at61_on_linux_fix_is_for_serviceskeep` |
| 62 | `linux.rs` `at62_the_deb_installs_a_service_as_keep_hub_and_dpkg_r_keeps_the_data`: end to end, **ignored by default** (needs root, systemd, a home network and the built `.deb`); `service.rs` unit tests for the unit, the steps, the person, the token's mode and the credential; `xtask` `deb.rs` tests |
| 63 | `linux.rs` `at63_on_linux_check_3_isnt_needed_and_check_4_reads_the_firewall_that_is_on`; `linuxfw.rs` `ufws_rules_read_as_the_ports_it_accepts`, `which_firewall_is_on` |

Tests 1 to 55 still pass. `linux.rs` `the_status_says_how_keys_are_kept` covers the
status words.

`cargo xtask ci` on Linux (rustc 1.97.0) passed: fmt, clippy `-D warnings`, 249 tests with
4 ignored (tests 13, 22 and 62, and the browser test), workflows, guards.

## Checked here by hand

- **`cargo xtask deb`** built `keep-hub_0.1.0_amd64.deb`. `dpkg-deb -c` shows root-owned
  files with the modes above.
- **Installed in this sandbox, which has no systemd running:**
  - `postinst` made the `keep-hub` user and group;
  - it sealed the credential (32 bytes back from `systemd-creds decrypt`, file mode 0600);
  - it wrote the drop-in;
  - it then stopped at `systemctl daemon-reload` with exit code 14 (`ServiceDidntStart`), as
    it should without systemd.
- **`service-run` as `keep-hub`, with the decrypted credential:** it logged "Keys are sealed
  by systemd for this computer.", then stopped with the no-home-network message. This
  sandbox's address is 192.0.2.2, which is not private.
- **`dpkg -r`** kept `/var/lib/keep-hub` and the credential. **`dpkg -P`** removed both and
  the drop-in.
- **`systemd-analyze verify`** accepts the unit (also a unit test, skipped where the tool
  isn't installed).

## Not checked here

- **Test 62 end to end** needs a Linux computer with systemd and a home network:
  `sudo cargo test -p keep-hub --test linux at62 -- --ignored`, after `cargo xtask deb`.
  - Reaching 16080 and the app ports from another computer is to be checked by hand.
  - The service starting with the credential, the keys being written sealed, and
    `admin.token` being 0640 for the group all happen only under systemd.
- **Check 4's parsing against a real ufw and firewalld ruleset.** The test rulesets are
  written from nftables' JSON format, not captured from a machine. Capturing
  `sudo nft -j list ruleset` on Ubuntu with ufw on, and on Fedora with firewalld, would
  settle it.
- **Windows:** `cargo xtask ci` passed on the owner's PC after the two fixes above.
  - Whether `NT SERVICE\KeepHub` may change its own firewall rule, as Revision 4 C says,
    isn't something I can check here, and I doubt it. Windows normally lets only
    administrators change firewall rules, so `POST problems/fix` may answer `fix_failed`
    from the service. `scripts/ci/windows-install.ps1` could try it. (Question 3.)
- **macOS:** test 58 doesn't run there (no 127.0.0.2).
- **Tests 13 and 22 against the staging services**, and the browser test, are still not run.

## For the spec writer

The questions of this report:

1. **A probe from an address that is neither private nor this computer's** is recorded as
   `outside` (reading 3). Should the spec name a fourth source, or should the hub not
   record such a request?
2. **Tunnel phones share one address.** Every request through the tunnel comes from
   127.0.0.1. The limits keyed on an address then apply to everyone away from home
   together: 8 connections per address, and wrong pairing tries pausing "that address".
   One guest's wrong codes would pause pairing for every phone using the tunnel. Should
   the loopback listener key those limits on `CF-Connecting-IP`? That would be a change to
   the request path, which Revision 4 says it doesn't make.
3. **Fix inside the Windows service:** see "Not checked here". If the service account can't
   change the rule, `POST problems/fix` on Windows needs another way, or the same answer as
   Linux.
4. **PowerShell.** The brief's rule is "No PowerShell on Windows". The firewall check and
   Fix in `machine.rs` (from stage 5, MoneyKeep's code) and the address list still run
   PowerShell scripts. Stage 7's install uses `netsh` only. I didn't change stage 5's code
   in this stage. Should check 4 and Fix move to `netsh advfirewall`?
5. **The `.deb`'s maintainer field** needs a real name and address. It is
   `KH_DEB_MAINTAINER`, with an `.invalid` placeholder until one is chosen.
6. **`names.json` written by two threads:** each write now succeeds, but the later wins, so
   a change made by one can be lost when the other writes. I have not seen that happen in a
   test. Should the names state get one writer?
7. **App ports and the Linux firewall:** `postinst` opens 16080 only, because app ports are
   registered later. Until ServicesKeep opens an app's port, check 4 fails and names it.
   Should registering an app on Linux say so in its answer?

Also:

- **There is no `.github` folder** in the working tree, although the stage 7 report and the
  README describe `ci.yml`, `windows.yml` and `release.yml`. Either they were never written
  to disk or they were lost. The stage 9 and stage 10 checks were run by hand.
- **Revision 4's admin address table** could list the new requests:
  - `POST probe` and `GET probe/<nonce>`;
  - `PUT` and `DELETE tunnel`;
  - `PUT` and `DELETE tunnel/moneykeep-name`;
  - `POST problems/fix`.
- **Codes used:** `no_such_probe`, `bad_hostname`, `no_apps`, `name_service_refused`,
  `no_fix`, `fix_failed`, `fix_in_serviceskeep`, `firewall_ports_closed`.

## Owner answers (2026-11-22)

The questions of this report, answered. Where an answer changed what is described above,
this section is the one that holds. `cargo xtask ci` on Linux then passed: 253 tests, with 4
ignored.

1. **A probe from an address that is neither private nor this computer's:** recorded as
   `outside`, as built. The spec should name it as a fourth source.
2. **Tunnel phones share one address:** count them by the visitor's address. Changed after
   the report (`relay.rs`, `relay::visitor`).
   - On the loopback listener the limits are counted by `CF-Connecting-IP` when it is a
     valid address, and by the connection's own address otherwise. On the home address the
     header is never believed.
   - That covers the 8 connections per address (taken once the head is read, answering 503
     `busy` above that), the wrong pairing tries, the waiting places for a body, and the
     probe's one-a-second limit. The probe's source still comes from the connection (loopback
     with the header is `tunnel`).
   - The total of 64 connections per port is unchanged.
   - Tests: `tunnel.rs` `through_the_tunnel_wrong_pairing_tries_are_counted_per_visitor` and
     `on_the_home_address_the_header_doesnt_move_the_count`.
   - A program on this computer could send the header to spread its wrong tries over made-up
     addresses. The hundred-from-everyone limit still holds.
   - This is a change to the request path: the spec writer should add it to Revision 4.
3. **Fix inside the Windows service:** Windows' permission prompt is needed. Changed after
   the report.
   - `POST /admin/v1/problems/fix {check: 4}` now changes nothing on any system. On Windows it
     answers 409 `permission_needed`: the app runs `keep-hub fix-firewall` with Windows'
     prompt, as check 4's action says. On Linux it answers 409 `fix_in_serviceskeep`. Where
     the hub manages no firewall (a Mac) it answers check 4's result.
   - Check 4's action no longer offers the admin request: `method`, `path` and `body` are
     gone.
   - The firewall rule's `ports` (added above) are gone too, with nothing left to use them.
   - Tests: `tunnel.rs` `at61_on_windows_fix_needs_windows_permission_prompt`,
     `at61_with_no_firewall_to_manage_fix_answers_check_4`, `at61_on_linux_...`,
     `at61_any_other_check_has_no_fix`.
   - The spec writer should change Revision 4 C to say this.
4. **PowerShell:** move check 4, Fix and the address list to `netsh` and the Windows API, as
   a task of its own. Not done in this stage.
   - Two parts need care. `netsh`'s output is in the computer's language, so it can't be read
     by its labels. A network's profile (Public or Private, for check 3) isn't in `netsh`:
     it is in the registry or the Network List Manager.
   - A first look is in "For the next task" below.
5. **The `.deb`'s maintainer:** `MoneyKeep Project <maintainer@getmoneykeep.org>`, the default
   now. `KH_DEB_MAINTAINER` still overrides it.
6. **`names.json` written by two threads:** one writer. Changed after the report.
   - The names engine is now the only writer of `names.json`. Turning names on, a new address
     and "Update the name" leave their change for the engine (`Asks` in `names.rs`), which
     writes it at the start of its next run (at once: they wake it).
   - `hub.json` is changed through `HubConfig::update`, one change at a time.
   - The names and address tests pass as before.
7. **App ports and the Linux firewall:** registering says so. Changed after the report.
   - On Linux, when the firewall that is on doesn't let the app's port in, the registration's
     answer has `"firewall": {"open": false, "words"}`. The words point to Fix in
     ServicesKeep.
   - The library gives the words in `Registered::firewall`.
   - Test: `linux.rs` `on_linux_registering_says_when_the_firewall_keeps_the_port_closed`.

## For the next task: Windows without PowerShell

What uses PowerShell today, all in `machine.rs` (stage 5):

- **The firewall scan:** the rule named "Keep Hub" and the Block rules naming `keep-hub.exe`.
- **Fix:** putting the rule back and removing those Block rules.
- **The address list:** adapters, MAC addresses, DHCP, and each network's profile.

A way without it:

- **The firewall:** `netsh advfirewall firewall show rule name="Keep Hub" verbose` and
  `... add rule` / `delete rule`.
  - `show rule` labels its fields in the computer's language, so it would be read by position
    and checked on an English and a German Windows.
  - The Windows Firewall COM interface (`INetFwPolicy2`) avoids that. windows-sys has no COM,
    so that would need the `windows` crate, a new dependency to propose.
- **Addresses:** `GetAdaptersAddresses` from windows-sys gives adapters, addresses, MAC
  addresses and DHCP.
- **The profile for check 3:** the Network List Manager (COM again), or the registry's
  `NetworkList\Profiles\{guid}\Category`, matched to the adapter through its network's
  signature, which takes more care.
