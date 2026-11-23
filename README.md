# Keep Hub

The one program on a household's computer that phones connect to. It serves every Keep
and Pick app on that computer: it owns the secure name and certificate, the household
PIN, the list of members and phones, and the record of who may use which app, and it
passes each request to the app it belongs to. Part of the MoneyKeep family (Rust).

**Status: all 7 stages built** (the relay, the registry of apps, members, grants
and devices, pairing and guests, the admin address; web clients' files passed through;
the hub name and its Let's Encrypt certificate; both certificates on every app port and
the certificate page; the home address followed as it changes, the firewall, and Find
the problem; the small library apps copy; running as a Windows service or a macOS daemon,
the Windows setup and the Mac disk image). See `docs/specs/keep-hub.md` and `docs/implementation/`.

## What it does

- **One name per computer.** A permanent web name under `hub.getmoneykeep.org` with a
  certificate phones already trust, so nobody installs a certificate on a phone.
- **A port per app.** Each app answers on its own port under that name, so each app's
  phone client keeps its own saved data.
- **One household PIN, access granted per app.** A phone is paired for one member and
  one app. Knowing the PIN does not open an app without a grant.
- **Administrators and standard members.** Administrators sign in on the hub computer
  with their own password to add members, give grants and approve every phone. A
  household may instead choose that the computer's sign-in is enough (no password, no
  PIN), and secure itself later; an app may pair its phones by code alone.
- **Any web client.** An app can ship a Slint WASM client or a plain HTML and
  JavaScript one. The hub passes its files through unchanged.
- **A fallback** for homes where names cannot work: the hub's own certificate authority,
  as in today's MoneyKeep and ShareKeep hubs.

The hub holds no app's books and no app's rules.

## Related

| Repository | What |
|---|---|
| `keep-name-service` | The Cloudflare Worker that gives each hub its name and places certificate proofs. Only the hub talks to it |
| `keep-launcher` | Installs, updates and removes the hub, as its own release package |
| `sharekeep` | Today's household hub (`crates/sk-hub`), which this hub starts from |
| `moneykeep` | The clean-room protocol (`docs/clean-room.md`) and the Slint WASM phone client |

## Layout

| Path | What |
|---|---|
| `docs/specs/keep-hub.md` | What the hub must do |
| `docs/implementation/stage-1.md` … `stage-10.md` | What each stage built, the choices it made, and what it left for later stages |
| `AGENTS.md` | Rules for every contributor. Read it first |
| `crates/keep-hub` | The hub: library and the `keep-hub` program |
| `crates/keep-hub-app` | The small library each app copies: find the hub, register, check `Keep-Hub-Auth` on the app's backend, and the Phones screen's requests. See `docs/implementation/stage-6.md` |
| `crates/keep-hub/tests` | The acceptance tests, with small test apps (`hub.rs`: stage 1, `web.rs` and `memory.rs`: stage 2, `names.rs`: stage 3, `fallback.rs`: stage 4, `addresses.rs`: stage 5, `library.rs`: stage 6, `service.rs` and `browser.rs`: stage 7, `administrators.rs`: stage 8, `revisions.rs`: stage 9, `tunnel.rs` and `linux.rs`: stage 10, with a fake name service, ACME server and DNS in `support/world.rs` and a fake computer in `support/machine.rs`) |
| `installer/windows`, `installer/macos`, `installer/linux` | The Windows setup (NSIS), the Mac disk image's scripts, and the Linux package's systemd unit, sysusers file and maintainer scripts |
| `scripts/ci/windows-install.ps1` | The Windows setup run for real: install, update, an older version refused, remove with apps registered, install again |
| `.github/workflows` | `ci.yml`: `cargo xtask ci` on Linux and Windows; `windows.yml`: the Windows setup run for real; `linux.yml`: the `.deb` installed for real (test 62, with ufw on), and kept as the run's `keep-hub-deb` download; `release.yml`: a draft release for a `v*` tag |
| `xtask` | `cargo xtask ci`, the repository rules, `cargo xtask installer` and `cargo xtask deb` |

Crates are added as the build stages in `AGENTS.md` are reached.

## Build & test

```sh
cargo test --workspace
cargo xtask ci
```

## Licence

MIT OR Apache-2.0, at your option, as the other MoneyKeep Apps.

## Building the setup

```sh
cargo xtask installer        # Windows, with NSIS 3: dist/keep-hub-<version>-windows-x64-setup.exe
installer/macos/make-dmg.sh <version> target/release   # on a Mac, after cargo build --release -p keep-hub
cargo xtask deb              # Linux, with dpkg-deb: dist/keep-hub_<version>_<arch>.deb
```

Users never build anything: keep-launcher installs the hub from its releases.
