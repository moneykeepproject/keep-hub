# Keep Hub

The one program on a household's computer that phones connect to. It serves every Keep
and Pick app on that computer: it owns the secure name and certificate, the household
PIN, the list of members and phones, and the record of who may use which app, and it
passes each request to the app it belongs to. Part of the MoneyKeep family (Rust).

**Status: stages 1 and 2 of 7 built** (the relay, the registry of apps, members, grants
and devices, pairing and guests, the admin address; web clients' files of any size,
compression and caching passed through). Names and certificates, the certificate page,
addresses, the troubleshooter, the small library for apps and the service are not built
yet. See `docs/specs/keep-hub.md` and `docs/implementation/`.

## What it does

- **One name per computer.** A permanent web name under `hub.getmoneykeep.org` with a
  certificate phones already trust, so nobody installs a certificate on a phone.
- **A port per app.** Each app answers on its own port under that name, so each app's
  phone client keeps its own saved data.
- **One household PIN, access granted per app.** A phone is paired for one member and
  one app. Knowing the PIN does not open an app without a grant.
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
| `docs/implementation/stage-1.md`, `stage-2.md` | What each stage built, the choices it made, and what it left for later stages |
| `AGENTS.md` | Rules for every contributor. Read it first |
| `crates/keep-hub` | The hub: library and the `keep-hub` program |
| `crates/keep-hub/tests` | The acceptance tests, with small test apps (`hub.rs`: stage 1, `web.rs` and `memory.rs`: stage 2) |
| `xtask` | `cargo xtask ci` and the repository rules |

Crates are added as the build stages in `AGENTS.md` are reached.

## Build & test

```sh
cargo test --workspace
cargo xtask ci
```

## Licence

MIT OR Apache-2.0, at your option, as the other MoneyKeep Apps.
