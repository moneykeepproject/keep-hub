# Stage 5: what was built

Implementer's notes (2026-11-18). This is not a spec: `docs/specs/keep-hub.md` says what the
hub must do. Stage 5 of `AGENTS.md` section 5 is addresses and Find the problem.

## Owner decisions on 2026-11-18

- **One firewall rule for the hub program, any port.** The spec says "the firewall rule
  exists for every app port". The owner chose one inbound rule named "Keep Hub", limited
  to `keep-hub.exe`, on Private and Domain networks only. It covers every app port,
  including ports registered later, without changing the firewall again. The spec writer
  should change check 4 and acceptance test 20 ("with every registered port") to match.
- **Cheap address check every 15 seconds.** The spec says the hub looks again "when the
  system reports a network change, and every 5 minutes". Instead of listening for the
  system's network events, the hub asks which address the default route uses every 15
  seconds. This asks the system only; nothing is sent. The chosen adapter's full list is
  read every `address.check_minutes` (5).

## Built

- **The home address** (`machine.rs`). It is the IPv4 address the default route uses,
  found by connecting a UDP socket to 203.0.113.1:9 (TEST-NET-3, RFC 5737). Nothing is
  sent. Only private addresses count. The setting `address.adapter` (default
  `automatic`) can name an adapter instead. On Windows the adapters and their network
  profiles come from a read-only PowerShell script. On Linux they come from `ip addr`,
  and on macOS from `ifconfig`.
- **Settings.** `hub.json`'s `address` is now `{current, adapter, check_minutes}`. The
  stage 1 to 4 form, a plain address, still loads.
- **Following the address** (`Hub::move_to`). When the address changes, the hub:
  - makes a new certificate authority for phones that connect by address (the spec:
    they install it again);
  - closes every app port and the certificate page, and opens them again on the new
    address;
  - saves the new address in `hub.json`;
  - sends the address to the name service at once (`Names::set_address`, which also
    clears any wait before retrying), and tests the name again.

  The name's certificate is not touched. Paired devices keep their pairing.
- **Away from a home network.** Every app port and the certificate page are closed. Names
  are Waiting with "not on a home network". The admin address keeps working. Apps can
  still register; their ports open when an address comes. Before stage 5 registering
  needed the port open at once.
- **The firewall** (`machine.rs`, copied and adapted from MoneyKeep's
  `apps/moneykeep-server/src/services.rs`). The hub reads Windows' firewall with
  read-only PowerShell: its own rule by name, and any rule for `keep-hub.exe`.
  - The check fails when the rule is missing or off, or when a Block rule names the
    hub. Windows makes such a Block rule when its "allow access" pop-up is closed.
  - The hub service runs without administrator rights, so it never changes the firewall
    itself. Fix is a command, `keep-hub fix-firewall`. The app's desktop program runs it
    with Windows' permission prompt. It puts the rule back and removes the Block rules.
  - PowerShell runs hidden, without the user's profile or modules.
  - Other systems' firewalls are not managed. The check passes with a note saying so.
- **Find the problem** (`problems.rs`): checks 1 to 10 in the spec's order, stopping at
  the first failure.
  - Each check has a number, a code, a status (`ok`, `failed`, `skipped` or `unknown`),
    plain words and at most one action.
  - Checks 5 to 8 are skipped while names are off.
  - A check that couldn't be made (for example PowerShell is blocked) is `unknown`, and
    the run goes on.
  - The last results are kept for any app that asks.
  - Some wording comes from MoneyKeep's Wi-Fi capture checks.

  Details of the checks:
  - **1** is answered by the hub itself. The spec has the app ask, since a stopped hub
    can't answer.
  - **5** counts any HTTP answer from the name service as "reached". The spec gives the
    service no route for asking only that.
  - **6** asks public DNS (DNS over HTTPS). **7** asks this computer's resolver.
  - **8** warns at 14 days (`names.warn_days`).
  - **9** connects to each app's loopback port.
  - **10** makes a TLS request for `/hub/check` on each app port, by address and, with a
    real certificate, by name. It accepts exactly the certificate the hub should answer
    with.
- **Admin address**:
  - `POST`/`GET /admin/v1/problems`;
  - `POST /admin/v1/names/address` (Update the name: send the address again);
  - `GET /admin/v1/addresses` (the current address, the adapter setting, every adapter
    with its address and profile);
  - `PUT /admin/v1/address {adapter}`.
- **The program**:
  - `keep-hub setup --address auto` (also the default when `--address` is left out);
  - `keep-hub addresses`;
  - `keep-hub fix-firewall`.

### Actions offered

| Check | Action |
|---|---|
| 2 | `open`: the system's network settings |
| 3 | `open`: `ms-settings:network-status` |
| 4 | `fix`: the command to run, and the line about Windows asking for permission |
| 5 | `retry` |
| 6 | `admin`: `POST /admin/v1/names/address` |
| 7 | `fallback`: the certificate page |
| 8 | `admin`: `POST /admin/v1/names/renew` |
| 9 | `start_app` with the app's id |
| 10 | none: the app goes on to the phone questions |

## Acceptance tests covered

| Spec test | Where (`tests/addresses.rs`) |
|---|---|
| 15 | `at15_a_new_address_reaches_the_name_service_keeps_the_name_certificate_and_makes_a_new_authority` |
| 20 | `at20_the_checks_run_in_order_and_stop_at_the_first_failure` and `at20_with_names_on_checks_5_to_8_and_10_by_name` |

Also tested:
- with no home address, ports close and names wait, then both recover;
- a hub started away from home;
- a chosen adapter, including one that isn't there;
- the results hold no secrets;
- (unit tests in `machine.rs`) the firewall check, the scripts and the address parsers.

The tests use a fake computer (`tests/support/machine.rs`). It holds the address, the
adapters and their profiles, and a Windows-like firewall that records what Fix does.
Addresses 127.0.0.x stand in for home addresses. `named_hub` moved from `fallback.rs`
to `tests/support/mod.rs` so both test files use it.

## Not built here

- Listening for the system's network change events: the 15-second check stands in.
- Running the hub under a service account with the rule installed by the installer:
  stage 7. The installer should make the "Keep Hub" rule, so Fix is needed only when
  something removed it.
- The phone questions after check 10: they belong to the apps' Phones screen.
- IPv6 home addresses (an open point in the spec).

## For the spec writer

- Check 4 and acceptance test 20: one rule for the hub program (above).
- The address check: every 15 seconds, instead of system events (above).
- Check 1 is answered by the hub when it is running. A stopped hub is found by the app.
- Check 5 needs a route on the name service, or the spec should say any answer counts.
- Registering an app away from a home network: accepted, with the port opened later.
