# Stage 4: what was built

Implementer's notes (2026-11-18). This is not a spec: `docs/specs/keep-hub.md` says what the
hub must do. Stage 4 of `AGENTS.md` section 5 is the fallback certificate authority and the
certificate page, and both certificates on one port.

## Owner decision on 2026-11-18

**HSTS is `Strict-Transport-Security: max-age=86400`** (one day), without
`includeSubDomains`. The spec says when to send it but not for how long. A short value means
little lock-in if the name's certificate ever lapses; it can be raised later. The spec
writer should add the value.

## Built

- **Both certificates on every app port** (`ca::Resolver`). A phone that asks for the hub
  name (Server Name Indication) gets the name's certificate; one that asks by address
  sends no name and gets the hub's own, as does one asking for any other name.
- **The name's certificate follows the names engine.** After every run the hub gives the
  ports the certificate in use (`Hub::refresh_name`). Renewing swaps it without dropping
  phones: a connection keeps the certificate it started with. Turning names off leaves the
  ports answering by address only.
- **HSTS** on every answer to a phone that used the hub name with a real certificate: the
  hub's own answers and those passed on from an app (a backend's own HSTS is replaced).
- **A staging certificate is served by name but never as trusted:** no HSTS, and pairing
  codes keep to the address.
- **Pairing codes and invites give three addresses:** `url` (by name when the name has a
  real certificate, else by address), `url_by_name`, `url_by_address`, and
  `certificate_page` (`http://<address>:16080/?app=<id>&pair=<code>`).
- **The certificate page** (`page.rs`) on `ports.helper` (16080): the fingerprint, the
  `.crt` and `.mobileconfig` downloads, the steps for the device that asked first, then
  the others, and a link to each registered app. Opened from a pairing code it ends with
  the link that pairs. Behind a front with ShareKeep's limits (32 connections, 8 from one
  address, 15 s idle). Anything else redirects to `/`; only GET and HEAD are answered.

Copied from ShareKeep: the page, the iPhone profile, the front, and the iPhone and
Android steps from `sk-view`'s `phone.rs`. Changed: "Keep Hub CA" and `keep-hub-ca.crt`;
the fingerprint is compared with "the Phones screen of an app"; a link per app instead of
one; the profile's identifier is `org.getmoneykeep.keephub.ca.<id>`.

**New: steps for computers** (Windows and Mac), which the spec asks for and ShareKeep's
page didn't have. Written from Windows' certificate import dialog and macOS's Keychain
Access, not copied from anywhere. They should be checked on a real Windows PC and Mac.

The front waits in `accept` and is woken on stop, like the app ports since stage 2.

## Acceptance tests covered

| Spec test | Where (`tests/fallback.rs`) |
|---|---|
| 18 | `at18_one_port_answers_with_the_name_certificate_by_name_…` and `at18_a_phone_paired_by_name_and_one_paired_by_address_work_side_by_side` |
| 24 (the page part) | `at24_a_hub_with_no_app_registered_answers_on_the_certificate_page` |

Also tested: staging certificates; turning names off and on; a renewal while a phone is
downloading by name; the page's downloads (a phone that installs the `.crt` reaches the
app port), the pairing step, parameters that aren't codes not echoed, the redirect.

To get the test hub to Ready on 127.0.0.1, the fake name service has a switch that also
takes loopback addresses (`World::allow_loopback`). The real service, and the fake by
default, take home addresses only.

## Readings of the spec to confirm

1. **The page's step 2** is reached with `?app=<id>&pair=<code>` (or `invite=`), since
   there are several apps. A code is used only if it is 8 letters and digits.
2. **HSTS is left out for a staging certificate**, so a phone that doesn't trust it can
   still be told to continue for testing.
3. **The hub's own certificate is also served for any name other than the hub name.**

## Not built

- Moving a phone between paired-by-name and paired-by-address (a different installed app,
  per the spec): nothing for the hub to do; it pairs each on its own.
- A changed address still means a new authority (spec): stage 5 finds address changes.
