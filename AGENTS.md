# AGENTS.md — read this first

This file is for every contributor, human or AI agent. Read it completely before
writing code, docs or tests.

## 1. Clean-room protocol (mandatory, applies to every change)

Keep Hub is one of the MoneyKeep Apps. MoneyKeep's full protocol, with its role roster
and its list of prior-art projects, is in `docs/clean-room.md` of the MoneyKeep
repository. The short version, which you must follow here too:

- **Know your role for the task.** You are either a **spec writer** (writes only
  `docs/specs/`) or an **implementer** (writes code from `docs/specs/` and public
  standards only). Never both for the same feature area. State your role at the start
  of a task.
- **Implementers never read** source code of commercial finance products, any
  proprietary product, or any project listed under "Prior art" in MoneyKeep's
  `docs/clean-room.md`, whatever its licence.
- **Never** decompile, disassemble or reverse-engineer other products or their file
  formats.
- **Never** copy trademarks, icons, artwork, help text or UI wording from other
  products.
- If you are an AI agent and you are given, or come across, forbidden material: stop,
  do not use it, and say so in your output.

Public standards and vendor documentation (RFCs, Let's Encrypt, Cloudflare, operating
system documentation) are fine. Cite what you used in the spec's Sources table.

Code may be copied from the other MoneyKeep Apps (MoneyKeep, ShareKeep, CalcKeep,
GroupKeep, Form1099Keep, keep-launcher): they are this project's own work. Keep Hub
copies rather than depends on them, so it builds on its own. The certificate authority,
TLS relay, certificate page, PIN hashing and device registry start as copies from
ShareKeep's `crates/sk-hub`.

## 2. The spec is the input

- `docs/specs/keep-hub.md` says what the hub must do. The name service it talks to is
  specified in `docs/specs/name-service.md` of the `keep-name-service` repository.
- A change of behaviour starts with a change to the spec, agreed with the owner. If the
  spec is unclear or seems wrong, stop and ask. Do not guess and do not quietly build
  something else.
- The spec's "Open points" are not decided. Ask the owner before building on one.
- Every acceptance test in the spec becomes at least one automated test.

## 3. Rules for this repository

- **Secrets stay out of the repository, the logs and any chat.** Device tokens, the
  admin token, the name-service token, shared secrets, private keys, PINs and pairing
  codes are never written to a log, an error message, a test fixture or a commit. Logs
  carry method, path and status only.
- **Keys are sealed by the operating system** on disk, as in ShareKeep's hub. Tests keep
  keys in memory.
- **Never ask for a real certificate in a test or during development.** Use Let's
  Encrypt's staging service and the staging name service (`names.staging` in the spec).
  Real requests spend a weekly allowance shared by every household.
- **Tests do not need the network** unless they are marked as end-to-end. Use fakes for
  the name service, the certificate authority, the resolvers, the firewall and the
  network type.
- **The hub holds no app's books and no app's rules.** If a change makes the hub read or
  alter an app's data, it belongs in that app.
- **An app's backend never sees a device token**, and the hub removes every `Keep-`
  header a phone sends. The one exception is the request id: the hub checks the phone's
  `Keep-Request-Id` and writes it again itself.
- **No panics in shipped code.** Return errors with plain-language messages. Tests may
  unwrap.
- **Line endings.** `.gitattributes` keeps sources LF on Windows checkouts.
- **Users never build anything.** Releases ship through installers.
- **New dependencies** need a licence the project accepts (MIT, Apache-2.0, BSD, ISC or
  similar) and must work with rustls and ring, which the family already uses. Say which
  crate you propose and why before adding it.

## 4. Workflow

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo xtask ci        # all of the above, then the repository rules
```

The first task creates the Cargo workspace and `xtask`, following ShareKeep's.

Run `cargo xtask ci` before every commit and report its result honestly. If a check
fails or was skipped, say so.

## 5. Build order

Work one stage at a time. Finish a stage's tests before starting the next.

1. The relay, the registry (members, grants, devices, apps), pairing and the admin
   address, proven with two small test apps.
2. Web client pass-through: large files, compression, caching, headers.
3. The name and the certificate, against the staging services.
4. The fallback certificate authority and certificate page, and both certificates on
   one port.
5. Addresses and Find the problem.
6. The small library apps copy, with its tests.
7. Running as a service, and the installer pieces.
