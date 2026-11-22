# Instructions for the keep-hub implementer (stages 9 and 10)

Paste this, or point the coding session at it, when starting work in `C:\dev\keep-hub`.

---

You are the **implementer** for keep-hub, in the clean-room sense defined in `AGENTS.md`
section 1. State that role at the start of your first reply. You write code, tests and
`docs/implementation/stage-N.md`. You do not edit anything under `docs/specs/`; when the
spec is unclear, wrong, or you need an "Open point" decided, stop and ask the owner before
building on it.

## Where the repository stands

- Stages 1–8 of `AGENTS.md` section 5 are built. `cargo xtask ci` last passed with 196
  tests, 3 ignored (tests 13 and 22 need the staging services; the browser test needs
  Playwright).
- Stage 8 is on disk but **not committed**: the last commit is stage 7. Do not commit; the
  owner does. Treat the working tree as the truth.
- `docs/specs/keep-hub.md` is at **revision 4** (2026-11-22). Revisions 2 and 3 (stage 9)
  and revision 4 (stage 10) are specified and not built.

## Read first, in this order

1. `AGENTS.md` — all of it.
2. `docs/specs/keep-hub.md` — all of it, including Revisions 2, 3 and 4 at the end.
3. `docs/implementation/stage-7.md` and `stage-8.md` — how the service, installer,
   administrator model and sessions were built, and the owner's answers to the stage 8
   questions. They show the family's habits: no PowerShell, one elevated command,
   `[ignored]` for tests that need the network, honest "Not checked here" sections.
4. `C:\dev\keep-name-service\docs\specs\name-service.md` — the name service the hub talks
   to, now at revision 1 (the tunnel routes stage 10 calls).
5. `C:\dev\serviceskeep\docs\specs\serviceskeep.md` and `cloudflare-tunnel.md` — the
   program that will call what stage 10 adds. Read for intent only; nothing from them is
   built here.

Do not read any proprietary product or anything under "Prior art" in MoneyKeep's
`docs/clean-room.md`. Code may be copied from the other MoneyKeep Apps.

## Stage 9: Revisions 2 and 3

Spec acceptance tests **45 to 55**.

- **Revision 2 A — an app chooses how its phones pair.** Pairing by code alone, with no
  PIN, for an app that declares it. Where `pin_not_set` is checked today (stage 8 left it
  "unreachable; stage 9 meets it again") is the seam.
- **Revision 2 B — a household where the computer's sign-in is enough.** No administrator
  password and no PIN. The admin address's sign-in and first set-up change for such a
  household; read the revision for exactly which requests still need a session.
- **Revision 2 C — ports and names**, including MoneyKeep EZ's port 14444.
- **Revision 3 — `names.code_page` and `code_needed`** in the status; the setting's
  validation (https, ≤ 200 characters); test 54 and 55.
- Bump the protocol number only if the revision says so; stage 8 kept it at 1.
- End with `docs/implementation/stage-9.md`, `cargo xtask ci` green, and stop. The owner
  reads the report before stage 10.

## Stage 10: Revision 4

Spec acceptance tests **56 to 63**. Four parts; build and test them in this order, because
ServicesKeep's own stage 2 waits on part A.

**A. The probe.** `GET /_probe/<nonce>` on every app port and on 16080, answering 204 and
recording nonce, time and source (`home` / `tunnel` / `this_computer`), with the rate limit
and the rules on unknown nonces. `POST /admin/v1/probe` (A) issues a nonce and the address
a phone should open; `GET /admin/v1/probe/<nonce>` (admin token) reports it. Cloudflare's
connecting-address header is trusted only on the loopback listener. Tests 56–58.

**B. The tunnel hostname.** `tunnel.hostname` setting; `PUT`/`DELETE /admin/v1/tunnel`
(A) with the validation in the revision; the hostname in the status and in `/hub/check`.
`PUT`/`DELETE /admin/v1/tunnel/moneykeep-name` (A) call the name service's revision 1
routes (`POST`/`DELETE /hubs/<id>/tunnel`) with the hub's first registered app port, pass
the tunnel token through **once in the response body**, store nothing of it, log nothing
of it, and set the hostname to the **away name** the service answered. These exist only
when names are on and an address is set. Tests 59–60. Use a fake name service; never the
real one.

**C. Fix as an admin request.** `POST /admin/v1/problems/fix {check: 4}` (A) recreates the
firewall rule from inside the service and answers check 4's new result; any other check
answers 400 `no_fix`. `keep-hub fix-firewall` stays. Test 61.

**D. The Linux service.** `keep-hub.service` under a `keep-hub` system user with
`StateDirectory=keep-hub`, a sysusers file, `AmbientCapabilities=CAP_NET_ADMIN` and
nothing more; check 3 passes with "not needed on this system"; check 4 looks in ufw,
firewalld or plain nftables and passes with "no firewall is on" when none is active; Fix
adds rules commented "Keep Hub". A `.deb` via `cargo xtask deb` (or a documented script)
with `postinst` enabling and starting the service; `dpkg -r` keeps `/var/lib/keep-hub`.
Tests 62–63. Test 62 is end-to-end on the Linux runner and may be ignored by default;
say so.

Before building D, **ask the owner** the two open points the revision leaves: whether
`admin.token` on Linux is group-readable or world-readable, and which key sealing you can
meet on Linux. Build A–C while waiting if you have no answer.

End with `docs/implementation/stage-10.md`, `cargo xtask ci` green, and stop.

## Rules that bite most often

- **Fakes, not the network.** Name service, Cloudflare, resolvers, firewall, network type:
  all faked unless a test is marked end-to-end and ignored by default.
- **Secrets stay out of logs, errors, fixtures and commits.** The tunnel token in stage 10
  B is the new one: it crosses the hub once, in a response body, and nowhere else. Test 60
  greps the data folder and the log for it.
- **The hub holds no app's books and no app's rules.** The probe handler reads nothing
  but the request line and forwards to no backend.
- **No PowerShell on Windows.** `sc.exe`, `netsh.exe`, `icacls.exe` and the Windows API.
- **No panics in shipped code.** Plain-language errors. Tests may unwrap.
- **Propose a dependency before adding it** — crate, version, licence, why.
- **Every acceptance test becomes at least one automated test**, named `atNN_…` as the
  earlier stages did, and the report's table maps spec test → test name.

## When something is not specified

Choose the simplest reading that the spec does not rule out, **write it down** in the stage
report under "For the spec writer", and carry on. An "Open point" is not yours to decide:
ask. If a revision contradicts an earlier section, the later revision wins; say where.

## How to finish each stage

1. `cargo xtask ci` green on the platform you are on; say which platform-only code was not
   compiled where (Windows service code compiles only on Windows; the systemd parts and
   `.deb` only on Linux).
2. `docs/implementation/stage-N.md`: owner decisions taken, what was built by crate and
   file, acceptance tests covered (table), what was not checked and why, questions and
   notes for the spec writer.
3. Do not commit or push.
4. Stop. The owner reads the report before the next stage.
