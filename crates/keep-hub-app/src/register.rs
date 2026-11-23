//! Registering the app with the hub (the spec, "Registering an app"): the first time the
//! person turns on phones in the app, and again whenever its version changes. The hub
//! answers with the shared secret, which is kept sealed for this computer in the app's own
//! data folder, for the app's backend to load.

use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::auth::HubAuth;
use crate::client::{HubClient, HubError};
use crate::seal::{self, Scope};

/// What was registered, in the app's data folder (no secret in it).
pub const RECORD_FILE: &str = "keep-hub-app.json";
/// The shared secret, sealed, in the app's data folder.
pub const SECRET_FILE: &str = "keep-hub-app.secret";

/// What the app tells the hub about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    /// Short name, such as `vacapick`.
    pub id: String,
    /// The name people see.
    pub title: String,
    pub version: String,
    /// The hub protocol the app was built for ([`crate::PROTOCOL`]).
    pub protocol: u32,
    /// The app's port for phones (the spec's table: VacaPick 16443, ...).
    pub public_port: u16,
    /// Where the app's backend listens on 127.0.0.1.
    pub loopback_port: u16,
    /// The app holds financial records (it can't accept guests).
    pub money: bool,
    /// The app accepts guests (never with `money`).
    pub guests: bool,
    /// How its phones pair (Revision 2 A): [`CODE_AND_PIN`] (a pairing code and the
    /// household PIN) or [`CODE`] (the code alone). A record saved before has none: it
    /// paired with the PIN.
    #[serde(default = "code_and_pin")]
    pub pairing: String,
}

/// Phones pair with a pairing code and the household PIN (the default).
pub const CODE_AND_PIN: &str = "code_and_pin";
/// Phones pair with the pairing code alone, no PIN.
pub const CODE: &str = "code";

fn code_and_pin() -> String {
    CODE_AND_PIN.into()
}

/// The ports the apps are given (the spec's port table). The hub doesn't hold an app to
/// them: it takes any port no other app holds, that isn't its own and isn't below 1024.
pub mod ports {
    pub const MONEYKEEP: u16 = 14443;
    /// Revision 2 C.
    pub const MONEYKEEP_EZ: u16 = 14444;
    pub const SHAREKEEP: u16 = 15443;
    pub const VACAPICK: u16 = 16443;
    /// The first port of the later Pick apps, one each upward.
    pub const LATER_PICK_APPS: u16 = 16444;
}

impl Registration {
    pub fn new(
        id: &str,
        title: &str,
        version: &str,
        public_port: u16,
        loopback_port: u16,
    ) -> Registration {
        Registration {
            id: id.into(),
            title: title.into(),
            version: version.into(),
            protocol: crate::PROTOCOL,
            public_port,
            loopback_port,
            money: false,
            guests: false,
            pairing: code_and_pin(),
        }
    }

    /// The app's phones pair with the pairing code alone, no PIN (Revision 2 A).
    pub fn by_code_alone(mut self) -> Registration {
        self.pairing = CODE.into();
        self
    }

    /// The app holds financial records.
    pub fn money(mut self) -> Registration {
        self.money = true;
        self
    }

    /// The app accepts guests.
    pub fn guests(mut self) -> Registration {
        self.guests = true;
        self
    }

    /// Whether the hub's record of the app says the same.
    fn same_as(&self, a: &crate::HubApp) -> bool {
        a.id == self.id
            && a.title == self.title
            && a.version == self.version
            && a.protocol == self.protocol
            && a.public_port == self.public_port
            && a.loopback_port == self.loopback_port
            && a.money == self.money
            && a.guests == self.guests
            && a.pairing.as_deref() == Some(self.pairing.as_str())
    }

    /// A hub that doesn't say how an app pairs is older than Revision 2: it pairs every
    /// phone with the PIN.
    fn needs_newer_hub(&self, version: &str) -> HubError {
        HubError::here(
            "hub_too_old",
            format!(
                "Keep Hub on this computer (version {version}) is older than {} needs to pair phones without a PIN. Update it in keep-launcher.",
                self.title
            ),
        )
    }
}

/// The result of [`ensure_registered`].
#[derive(Debug, Clone)]
pub struct Registered {
    /// For checking requests on the backend.
    pub auth: HubAuth,
    /// The app was registered (again) just now, so the secret is new: a backend that is
    /// already running loads it again ([`HubAuth::load`]).
    pub now: bool,
    /// On Linux, when the firewall doesn't let phones reach the app's port yet: words to
    /// show, which point to ServicesKeep's Fix. (Only from a registration just now; Find the
    /// problem's check 4 says it any time.)
    pub firewall: Option<String>,
}

/// Register the app unless the hub already has it as described, with the secret this
/// folder holds. The hub's secret changes with each registration, so this registers only
/// when needed: the first time, when anything in `r` changed (a new version), when the
/// hub lost the app or its secret, or when the secret here can't be read.
pub fn ensure_registered(
    hub: &HubClient,
    r: &Registration,
    app_data: &Path,
) -> Result<Registered, HubError> {
    let status = hub.status()?;
    if !status.accepts(r.protocol) {
        return Err(HubError::here(
            "hub_too_old",
            format!(
                "Keep Hub on this computer (version {}) is older than {} needs. Update it in keep-launcher.",
                status.version, r.title
            ),
        ));
    }
    let on_hub = status
        .app(&r.id)
        .filter(|a| a.state != "not_registered_fully")
        .is_some_and(|a| r.same_as(&a.app));
    let recorded = std::fs::read(app_data.join(RECORD_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice::<Registration>(&b).ok())
        .is_some_and(|kept| kept == *r);
    if on_hub && recorded {
        if let Ok(secret) = read_secret(app_data) {
            return Ok(Registered {
                auth: HubAuth::new(&secret),
                now: false,
                firewall: None,
            });
        }
    }
    if r.pairing == CODE && lists_apps_without_pairing(&status) {
        return Err(r.needs_newer_hub(&status.version));
    }
    let (secret, pairing, firewall) = hub.register_raw(r)?;
    write_secret(app_data, &secret)?;
    // An app that asked for `code` and got an answer without `pairing` is talking to an
    // older hub: it must not offer pairing (Revision 2 A). The secret is kept all the same,
    // so the backend still checks what the hub forwards.
    if r.pairing == CODE && pairing.is_none() {
        return Err(r.needs_newer_hub(&status.version));
    }
    let record =
        serde_json::to_vec_pretty(r).map_err(|e| HubError::here("not_saved", e.to_string()))?;
    write_private(&app_data.join(RECORD_FILE), &record)?;
    Ok(Registered {
        auth: HubAuth::new(&secret),
        now: true,
        firewall,
    })
}

/// Whether the hub lists apps without their `pairing`: one older than Revision 2. (A hub
/// with no app registered can't tell; the registration's answer then does.)
fn lists_apps_without_pairing(status: &crate::HubStatus) -> bool {
    status.apps.iter().any(|a| a.app.pairing.is_none())
}

/// The shared secret kept in `app_data`.
pub(crate) fn read_secret(app_data: &Path) -> Result<Zeroizing<String>, HubError> {
    let missing = |why: &str| {
        HubError::here(
            "not_registered",
            format!("This app's link with Keep Hub {why}: turn phones on again in the app."),
        )
    };
    let bytes = Zeroizing::new(
        std::fs::read(app_data.join(SECRET_FILE)).map_err(|_| missing("isn't set up"))?,
    );
    let (plain, _sealed) = seal::unseal(&bytes, Scope::User)
        .map_err(|_| missing("can't be opened on this computer"))?;
    let text = std::str::from_utf8(&plain).map_err(|_| missing("is damaged"))?;
    let text = text.trim();
    if text.is_empty() {
        return Err(missing("is damaged"));
    }
    Ok(Zeroizing::new(text.to_string()))
}

fn write_secret(app_data: &Path, secret: &str) -> Result<(), HubError> {
    let sealed = seal::seal(secret.as_bytes(), Scope::User).map_err(|e| {
        HubError::here(
            "not_saved",
            format!("The app's link with Keep Hub couldn't be saved: {e}"),
        )
    })?;
    write_private(&app_data.join(SECRET_FILE), &sealed)
}

/// Write a file readable only by its owner on Unix, through a temporary file (copied from
/// Keep Hub's `util.rs`).
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), HubError> {
    use std::io::Write;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    let result = (|| -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    result.map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        HubError::here(
            "not_saved",
            format!("{} can't be written: {e}", path.display()),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_secret_is_kept_sealed_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_secret(dir.path()).unwrap_err().code, "not_registered");
        write_secret(dir.path(), "abc123").unwrap();
        assert_eq!(read_secret(dir.path()).unwrap().as_str(), "abc123");
        let on_disk = std::fs::read(dir.path().join(SECRET_FILE)).unwrap();
        if seal::SEALS {
            assert!(on_disk.starts_with(seal::MAGIC));
            assert!(!on_disk.windows(6).any(|w| w == b"abc123"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(SECRET_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "owner only");
        }
        // a damaged file says so, without the bytes
        std::fs::write(dir.path().join(SECRET_FILE), b"  ").unwrap();
        let e = read_secret(dir.path()).unwrap_err();
        assert!(e.message.contains("damaged"), "{e}");
    }

    #[test]
    fn a_registration_starts_without_money_or_guests() {
        let r = Registration::new("vacapick", "VacaPick", "1.0.0", 16443, 16444);
        assert_eq!(
            (r.money, r.guests, r.protocol),
            (false, false, crate::PROTOCOL)
        );
        assert!(r.clone().money().money);
        assert!(r.clone().guests().guests);
        assert_eq!(r.pairing, CODE_AND_PIN);
        assert_eq!(r.by_code_alone().pairing, CODE);
    }

    /// A record saved before Revision 2 reads as `code_and_pin`.
    #[test]
    fn an_older_record_pairs_with_the_pin() {
        let r: Registration = serde_json::from_str(
            r#"{"id":"vacapick","title":"VacaPick","version":"1.0.0","protocol":1,
                "public_port":16443,"loopback_port":26443,"money":false,"guests":false}"#,
        )
        .unwrap();
        assert_eq!(r.pairing, CODE_AND_PIN);
        assert_eq!(ports::MONEYKEEP_EZ, 14444);
    }
}
