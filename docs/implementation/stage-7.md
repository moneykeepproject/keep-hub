# Stage 7: what was built

Implementer's notes (2026-11-18). This is not a spec: `docs/specs/keep-hub.md` says what the
hub must do. Stage 7 of `AGENTS.md` section 5 is running as a service, and the installer
pieces. It is the last stage.

## Owner decisions on 2026-11-18

- **`windows-service` 0.8** (MIT/Apache-2.0) runs the hub as a Windows service. It is the
  crate and version ShareKeep's hub uses (0.8.1 in both lock files), and is built on Windows
  only.
- **keep-launcher was read** (read only) to see how an app opens it at an entry. It can't
  yet: it reads only `--version` and `--hidden`, and nothing in it mentions the hub. So the
  library takes the launcher from the app as a hook (below). keep-launcher's own spec
  should define the real arguments.
- **The Windows install is tested by a GitHub workflow and a local script**
  (`scripts/ci/windows-install.ps1`), as ShareKeep's.
- **Acceptance test 22 is built and skipped by default**, as test 13 is. It uses Python and
  Playwright, as ShareKeep's browser test does.

## Built

### The service (`crates/keep-hub`)

- `service.rs`, copied from ShareKeep's hub and changed for Keep Hub:
  - **The Windows service** is `KeepHub`, under its own virtual account
    `NT SERVICE\KeepHub`, never LocalSystem. It starts at boot and restarts on failure.
  - **The data folder** is `%ProgramData%\Keep Hub`, owned by Administrators.
    - Every permission anyone put inside it is removed. The folder passes down only full
      control for SYSTEM and Administrators, and modify for the service.
    - The computer's users may list the folder (that folder only) and read `admin.token`
      (owner decision of stage 6). Nothing passed down is theirs, so `keys\` and
      `hub.sqlite` are closed to them.
    - Every step works on a link itself, never on what it points to.
  - **The firewall rule** is the stage 5 one, "Keep Hub": the hub program, TCP, Private and
    Domain networks, any port. It is made with `netsh`, so Find the problem's check finds it.
  - **No PowerShell:** `sc.exe`, `icacls.exe` and `netsh.exe` only.
  - **A folder that is already there** is used only when everything in it belongs to the
    administrators, SYSTEM or a service, and nothing in it is a link (`owner.rs`, copied
    from ShareKeep). Otherwise it is renamed aside and never read.
  - **On a Mac**, the launchd daemon file runs the hub as the person who installed it.
  - **The log** is `hub.log` in the data folder; at 1 MB it is kept as `hub.log.1` and a new
    one starts.
- New commands of the `keep-hub` program:
  - `install-service`: the setup's one elevated step, copied from ShareKeep's `make-hub`.
    - It never takes `--data`: the folder is always `%ProgramData%\Keep Hub`.
    - It refuses unless the program is under Program Files.
    - It moves a folder that isn't the hub's own aside, runs `setup --address auto` the
      first time only (a hub already there keeps its name, certificates and pairings),
      then the service, permissions and rule steps.
    - Exit codes are in `service::Exit`.
  - `remove-service`: the service and the rule go; the data folder stays.
  - `service-run --data`: what Windows' service manager runs.
  - `registered-apps --data`: the titles of the registered apps on one line, for the
    uninstaller. It reads `hub.sqlite` without changing it, and works while the hub runs
    (`Registry::read_apps`).
  - `run --log <file>`: for the Mac daemon.

### The Windows setup

- `installer/windows/keep-hub.nsi`, adapted from ShareKeep's. It installs per-machine in
  `C:\Program Files\Keep Hub`, with administrator approval once. There is no folder page:
  the service must run from Program Files.
- **Pages:** welcome (which version is installed or updated), licence, progress, finish.
  The hub has no window, so there is nothing to open.
- **Updating:** the hub is stopped, replaced and started again, keeping its name and
  pairings.
- **A version older than the installed one** is refused, and nothing changes (exit code 4
  when silent).
- **Installed apps** shows the name, version and its order, publisher, size, location, and
  the uninstaller with its silent form.
- **The uninstaller:**
  - With apps still registered, it names them and asks again. When silent it refuses with
    exit code 5 unless given `/FORCE`, so keep-launcher asks the person itself first.
  - It removes the service, the rule, the program and the registration.
  - It asks whether to delete the data folder too (No by default); silently, only with
    `/DELETEDATA`.
- `cargo xtask installer` (`xtask/src/installer.rs` and `licences.rs`, copied from ShareKeep)
  builds `dist/keep-hub-<version>-windows-x64-setup.exe`, with its `.sha256` and
  `SHA256SUMS.txt`. It ships `THIRD-PARTY-LICENSES.txt` (84 crates) and the licence files.
  - It signs when `KH_SIGN_THUMBPRINT` or `KH_SIGN_CERT` is set, and refuses a password.
  - `KEEP_HUB_VERSION` sets the version: dev builds, and the older setup for test 26.
- `LICENSE-MIT`, `LICENSE-APACHE` (the family's) and a Keep Hub `NOTICE` are now at the
  repository root.
- The setup has no icon of its own yet: it shows NSIS's.

### The Mac disk image

- `installer/macos/`:
  - `make-dmg.sh` makes `keep-hub-<version>-macos-<arch>.dmg` with its `.sha256`. It holds
    `Keep Hub.app` (no window: `LSUIElement`; signed ad hoc) and two scripts.
  - "Install Keep Hub" runs `keep-hub setup` as the person the first time, then writes the
    daemon file itself. With `sudo` it only places that file and starts launchd: nothing of
    Keep Hub's runs as root. A test checks the file is the same as `service::macos_plist`.
  - "Remove Keep Hub" names the registered apps and asks again, then removes the daemon.
    The data stays.
- The data folder is `~/Library/Application Support/Keep Hub` (as ShareKeep's hub).

### The library (`crates/keep-hub-app`)

- `offer(data)` says what to offer when the person turns on phones:
  - `MakeThisTheHub`;
  - `StartHub` (installed and stopped counts as found; nothing is installed);
  - `CantUse` (with why);
  - `Ready`.
- `make_this_the_hub(launcher)` opens keep-launcher at the hub's entry (`LAUNCHER_ENTRY`,
  "keep-hub"), or gives the hub's download page when keep-launcher isn't installed. The app
  supplies the `Launcher`.
- `start_command()` is what the app runs, with the system's permission prompt, to start a
  stopped hub.
- **On Windows `find` trusts `admin.token` only** when the folder and the token belong to
  the administrators, SYSTEM or a service, as ShareKeep's app does. Any user can make a
  folder named `Keep Hub` in `%ProgramData%` before the hub is installed.
- `default_data_folder()` now gives the Mac's folder too.

### CI

- `.github/workflows/ci.yml`: `cargo xtask ci` on Linux, Windows and macOS. Windows is
  where the hub's Windows-only code is first compiled.
- `.github/workflows/windows.yml`: builds the setup and an older one (0.0.1), then runs
  `scripts/ci/windows-install.ps1` in order:
  - install the hub alone;
  - update;
  - an older version refused;
  - two apps register;
  - remove refused while they're registered;
  - remove;
  - install again;
  - remove everything.
- `.github/workflows/release.yml`: a draft release with the Windows setup and the Mac disk
  image, each with its `.sha256`, as ShareKeep's.

## Acceptance tests covered

| Spec test | Where |
|---|---|
| 21 | `registry.rs`: `a_later_hub_opens_this_registry_and_a_newer_registry_is_refused` (since stage 1) |
| 22 | `tests/browser.rs`: `at22_end_to_end_in_a_headless_browser` (ignored: needs the staging name service, a home network and Playwright), with `tests/e2e/browser.py` and the clients in `tests/e2e/client/` |
| 23 | `tests/library.rs`: `at23_no_hub_offers_the_launchers_entry_and_a_stopped_hub_is_offered_a_start` (a fake launcher) |
| 24 | `tests/hub.rs` and `tests/fallback.rs` (since stages 1 and 4), and `windows-install.ps1 -Scenario install`: a running service that other computers reach on 16080 only, with the admin address on 127.0.0.1 |
| 25 | `windows-install.ps1 -Scenario remove-refused`, `remove`, `reinstall`; `tests/service.rs` (registered-apps names both while the hub runs) |
| 26 | `windows-install.ps1 -Scenario older` |

Also tested:
- the service steps: virtual account, owner then permissions, users' read access limited
  to the token, the rule, no PowerShell;
- a planted folder with a link is set aside;
- Program Files only;
- the exit codes;
- the Mac daemon file and scripts (no `sudo` line runs the hub);
- the log rotation;
- `install-service` refusing `--data` and non-Windows;
- the setup script compiling (makensis), the versions' order, the signing rules, the
  licence list.

`the_browser_part_against_a_local_hub` (ignored: needs Playwright only) runs the browser's
steps against a test hub on 127.0.0.1, by a stand-in name, with the hub's own certificate.
It passed here in headless Chrome:
- both clients pair and call `/api/`;
- the WASM client loads its module by streaming under its security policy;
- both open offline from their service workers, and work again with the same token.

Only the check of the name's certificate needs the staging services.

## Not checked here

- **The Windows-only Rust code wasn't compiled in this build:** the Windows service, the
  owner check and sealing. The Rust Windows target couldn't be downloaded here, so the
  first compile is `cargo xtask ci` on Windows. The code is ShareKeep's, and the calls were
  checked against `windows-service` 0.8.1's and `windows-sys` 0.61.2's sources.
- **`scripts/ci/windows-install.ps1` has never run:** PowerShell isn't available here. It
  first runs in the new workflow, or from an administrator PowerShell on your PC (after
  `cargo xtask installer`, and the same with `KEEP_HUB_VERSION=0.0.1 cargo xtask installer
  --skip-build --bin target/release`).
- **The Mac scripts haven't run on a Mac:** they are checked for syntax, and the daemon file
  is compared with the code.
- **The NSIS script** compiles with makensis 3.09 here (no warnings). Its behaviour on
  Windows is what the workflow tests.

## For the spec writer

- **The data folder's permissions:** the computer's users read `admin.token` (stage 6), and
  the folder is otherwise the service's and the administrators'. `hub.json` loses the users'
  read access at the hub's first rewrite (a rewrite makes a new file), so apps use the
  standard admin port, 16081. A different `ports.admin` would need the apps to learn it
  another way.
- **The Mac hub runs as the person who installed it**, with its data in their Library, as
  ShareKeep's hub. The spec says "a data folder only the service and administrators can
  use".
- **keep-launcher's part:**
  - how an app opens it at the hub's entry (the library's `Launcher` hook waits for it);
  - the catalog entry for a component that is a service;
  - the setup's silent exit codes: 4, newer installed; 5, apps still registered, with
    `/FORCE` after asking;
  - `/DELETEDATA`;
  - the local mirror's `keep-hub` checkout.
- **Starting a stopped hub** is for administrators (`start_command`, run with the system's
  permission prompt).
- **The setup's icon.**
