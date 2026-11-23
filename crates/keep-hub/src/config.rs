//! `hub.json`: where the hub listens. Public facts only (no keys, no PIN). Copied from
//! ShareKeep's hub, `config.rs`.
//!
//! Each app's public port is in the registry, given when the app registers. The hub finds
//! its home address itself and follows its changes (`hub.rs`); the one in use is kept here,
//! beside the `address.*` settings.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::Path;

use crate::util::{write_private, StoreResult};

/// The plain-HTTP certificate page of the fallback (`ports.helper`; built in stage 4).
pub const HELPER_PORT: u16 = 16080;
/// The admin address, this computer only (`ports.admin`).
pub const ADMIN_PORT: u16 = 16081;
/// Life of a pairing code in minutes (`pair.code_minutes`).
pub const CODE_MINUTES: u32 = 10;
/// Life of a guest invite in days (`guest.invite_days`).
pub const INVITE_DAYS: u32 = 7;

pub const CONFIG_FILE: &str = "hub.json";

/// How often the hub looks for a new address (`address.check_minutes`).
pub const CHECK_MINUTES: u32 = 5;

/// The hub's settings, with the spec's keys: `ports.helper` is `{"ports": {"helper": …}}`.
/// A key that is left out has its default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubConfig {
    /// The `address.*` settings, and the home address in use.
    #[serde(default)]
    pub address: AddressSettings,
    #[serde(default)]
    pub ports: Ports,
    #[serde(default)]
    pub pair: Pair,
    #[serde(default)]
    pub guest: Guest,
    #[serde(default)]
    pub names: NamesSettings,
    #[serde(default)]
    pub cert: CertSettings,
    #[serde(default)]
    pub admin: AdminSettings,
    #[serde(default)]
    pub tunnel: TunnelSettings,
    #[serde(default)]
    pub probe: ProbeSettings,
}

/// The `tunnel.*` settings (Revision 4 B).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TunnelSettings {
    /// The public hostname ServicesKeep set up (empty: none). Shown to apps and phones,
    /// nothing more.
    pub hostname: String,
}

/// Life of a probe nonce in minutes (`probe.minutes`).
pub const PROBE_MINUTES: u32 = 10;

/// The `probe.*` settings (Revision 4 A).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProbeSettings {
    pub minutes: u32,
}

impl Default for ProbeSettings {
    fn default() -> Self {
        ProbeSettings {
            minutes: PROBE_MINUTES,
        }
    }
}

/// The longest `tunnel.hostname`, in characters.
pub const HOSTNAME_MAX: usize = 253;

/// `tunnel.hostname` as it is kept: empty, or a host name of at most 253 characters whose
/// labels are letters, digits and hyphens (each 1 to 63 characters, not starting or ending
/// with a hyphen), in lower case. The reason when not.
pub fn check_hostname(name: &str) -> Result<String, String> {
    let n = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if n.is_empty() {
        return Ok(n);
    }
    let why = format!(
        "A tunnel hostname is at most {HOSTNAME_MAX} characters, in labels of letters, digits and hyphens separated by dots (such as hub.example.org)."
    );
    if n.len() > HOSTNAME_MAX {
        return Err(why);
    }
    let label_ok = |l: &str| {
        (1..=63).contains(&l.len())
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    if !n.split('.').all(label_ok) {
        return Err(why);
    }
    Ok(n)
}

/// How long an administrator's session lasts after its last use (stage 8).
pub const SESSION_MINUTES: u32 = 15;

/// The `admin.*` settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AdminSettings {
    pub session_minutes: u32,
}

impl Default for AdminSettings {
    fn default() -> Self {
        AdminSettings {
            session_minutes: SESSION_MINUTES,
        }
    }
}

/// The `address.*` settings, and the address in use (`current`, written by the hub).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressSettings {
    /// The home address in use (`None`: not on a home network).
    pub current: Option<Ipv4Addr>,
    /// Which adapter's address to publish: `automatic` (the default route's) or an
    /// adapter's name.
    pub adapter: String,
    /// How often to look for a new address, in minutes.
    pub check_minutes: u32,
}

impl Default for AddressSettings {
    fn default() -> Self {
        AddressSettings {
            current: None,
            adapter: "automatic".into(),
            check_minutes: CHECK_MINUTES,
        }
    }
}

impl AddressSettings {
    /// Whether the adapter is chosen automatically.
    pub fn automatic(&self) -> bool {
        let a = self.adapter.trim();
        a.is_empty() || a.eq_ignore_ascii_case("automatic")
    }
}

/// `address` as written by stages 1 to 4 (a plain address) or now (the settings).
#[derive(Deserialize)]
#[serde(untagged)]
enum AddressForm {
    Plain(Ipv4Addr),
    Settings {
        #[serde(default)]
        current: Option<Ipv4Addr>,
        #[serde(default)]
        adapter: Option<String>,
        #[serde(default)]
        check_minutes: Option<u32>,
    },
}

impl<'de> Deserialize<'de> for AddressSettings {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let d0 = AddressSettings::default();
        Ok(match AddressForm::deserialize(d)? {
            AddressForm::Plain(ip) => AddressSettings {
                current: Some(ip),
                ..d0
            },
            AddressForm::Settings {
                current,
                adapter,
                check_minutes,
            } => AddressSettings {
                current,
                adapter: adapter.unwrap_or(d0.adapter),
                check_minutes: check_minutes.unwrap_or(d0.check_minutes),
            },
        })
    }
}

/// Where a person asks for a registration code (`names.code_page`, Revision 3).
pub const CODE_PAGE: &str = "https://getmoneykeep.org/phone-access/";
/// The longest `names.code_page`, in characters.
pub const CODE_PAGE_MAX: usize = 200;

/// Whether `page` may be `names.code_page`: an `https://` address with a host, of at most
/// [`CODE_PAGE_MAX`] characters, with no spaces or control characters. The reason when not.
pub fn check_code_page(page: &str) -> Result<(), String> {
    let why = format!(
        "The page for registration codes must be an https:// address of at most {CODE_PAGE_MAX} characters."
    );
    if page.chars().count() > CODE_PAGE_MAX
        || page.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(why);
    }
    let Some(rest) = page.strip_prefix("https://") else {
        return Err(why);
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() || host.contains('@') {
        return Err(why);
    }
    Ok(())
}

/// The `names.*` settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NamesSettings {
    /// Use a hub name (off until the person turns it on).
    pub enabled: bool,
    /// The name service.
    pub service: String,
    /// The certificate authority's ACME directory.
    pub acme: String,
    /// Use Let's Encrypt's staging service (and `service` must then be the staging name
    /// service).
    pub staging: bool,
    /// Where a person asks for a registration code (Revision 3). Shown to the apps; the
    /// hub never opens it.
    pub code_page: String,
}

impl NamesSettings {
    /// `code_page`, or the default when `hub.json` holds one that isn't allowed (it was
    /// edited by hand): the apps never get a page the setting's rules refuse.
    pub fn code_page(&self) -> &str {
        if check_code_page(&self.code_page).is_ok() {
            &self.code_page
        } else {
            CODE_PAGE
        }
    }
}

impl Default for NamesSettings {
    fn default() -> Self {
        NamesSettings {
            enabled: false,
            service: crate::nameservice::NAME_SERVICE.to_string(),
            acme: crate::acme::LETS_ENCRYPT.to_string(),
            staging: false,
            code_page: CODE_PAGE.to_string(),
        }
    }
}

/// The `cert.*` settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CertSettings {
    /// Tell the person renewal is failing when this many days or fewer remain.
    pub warn_days: u32,
}

impl Default for CertSettings {
    fn default() -> Self {
        CertSettings { warn_days: 14 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Ports {
    pub helper: u16,
    pub admin: u16,
}

impl Default for Ports {
    fn default() -> Self {
        Ports {
            helper: HELPER_PORT,
            admin: ADMIN_PORT,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Pair {
    pub code_minutes: u32,
}

impl Default for Pair {
    fn default() -> Self {
        Pair {
            code_minutes: CODE_MINUTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Guest {
    pub invite_days: u32,
}

impl Default for Guest {
    fn default() -> Self {
        Guest {
            invite_days: INVITE_DAYS,
        }
    }
}

impl HubConfig {
    /// Settings for a hub at `address` (the address it found, or was given at setup).
    pub fn new(address: Ipv4Addr) -> Self {
        HubConfig {
            address: AddressSettings {
                current: Some(address),
                ..AddressSettings::default()
            },
            ports: Ports::default(),
            pair: Pair::default(),
            guest: Guest::default(),
            names: NamesSettings::default(),
            cert: CertSettings::default(),
            admin: AdminSettings::default(),
            tunnel: TunnelSettings::default(),
            probe: ProbeSettings::default(),
        }
    }

    pub fn load(dir: &Path) -> StoreResult<HubConfig> {
        let b = std::fs::read(dir.join(CONFIG_FILE))
            .map_err(|e| format!("The hub isn't set up yet ({CONFIG_FILE} can't be read: {e})."))?;
        serde_json::from_slice(&b).map_err(|e| format!("{CONFIG_FILE} is damaged ({e})"))
    }

    pub fn save(&self, dir: &Path) -> StoreResult<()> {
        let b = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        write_private(&dir.join(CONFIG_FILE), &b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_config_round_trips_with_the_spec_defaults() {
        let dir = tempfile::tempdir().unwrap();
        assert!(HubConfig::load(dir.path()).is_err());
        let cfg = HubConfig::new(Ipv4Addr::new(192, 168, 1, 20));
        assert_eq!((cfg.ports.helper, cfg.ports.admin), (16080, 16081));
        assert_eq!((cfg.pair.code_minutes, cfg.guest.invite_days), (10, 7));
        assert!(!cfg.names.enabled && !cfg.names.staging);
        assert_eq!(cfg.names.service, "https://names.getmoneykeep.org/v1");
        assert_eq!(
            cfg.names.acme,
            "https://acme-v02.api.letsencrypt.org/directory"
        );
        assert_eq!(cfg.cert.warn_days, 14);
        assert_eq!(
            cfg.names.code_page,
            "https://getmoneykeep.org/phone-access/"
        );
        cfg.save(dir.path()).unwrap();
        assert_eq!(HubConfig::load(dir.path()).unwrap(), cfg);
    }

    /// Revision 3: `names.code_page` is an https address of at most 200 characters.
    #[test]
    fn the_code_page_is_an_https_address_of_200_characters_at_most() {
        assert!(check_code_page(CODE_PAGE).is_ok());
        let long = format!("https://example.org/{}", "a".repeat(CODE_PAGE_MAX - 20));
        assert_eq!(long.chars().count(), CODE_PAGE_MAX);
        assert!(check_code_page(&long).is_ok());
        for bad in [
            "http://getmoneykeep.org/phone-access/",
            "https://",
            "https:///path",
            "https://user@example.org/",
            "https://example.org/a b",
            "getmoneykeep.org/phone-access/",
            "",
            &format!("{long}a"),
        ] {
            assert!(check_code_page(bad).is_err(), "{bad}");
        }
        let mut s = NamesSettings {
            code_page: "http://example.org/".into(),
            ..NamesSettings::default()
        };
        assert_eq!(
            s.code_page(),
            CODE_PAGE,
            "a hand-edited bad page isn't shown"
        );
        s.code_page = "https://example.org/codes".into();
        assert_eq!(s.code_page(), "https://example.org/codes");
    }

    /// Revision 4 B: the tunnel hostname's rules.
    #[test]
    fn a_tunnel_hostname_is_labels_of_letters_digits_and_hyphens() {
        assert_eq!(check_hostname("").unwrap(), "");
        assert_eq!(
            check_hostname(" Hub.Example.org. ").unwrap(),
            "hub.example.org"
        );
        assert_eq!(
            check_hostname("k7m2p9xw4t01.away.getmoneykeep.org").unwrap(),
            "k7m2p9xw4t01.away.getmoneykeep.org"
        );
        let label = "a".repeat(63);
        let long = [label.as_str(); 4].join(".");
        assert_eq!(long.len(), 255);
        let fits = &long[..253];
        assert!(check_hostname(fits).is_ok());
        for bad in [
            long.as_str(),
            &"a".repeat(300),
            "hub example.org",
            "hub_1.example.org",
            "-hub.example.org",
            "hub..example.org",
            "https://hub.example.org",
            &format!("{}a.example.org", label),
        ] {
            assert!(check_hostname(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn settings_left_out_have_their_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let text = r#"{ "address": "10.0.0.5", "pair": { "code_minutes": 3 }, "ports": { "admin": 17000 } }"#;
        std::fs::write(dir.path().join(CONFIG_FILE), text).unwrap();
        let cfg = HubConfig::load(dir.path()).unwrap();
        assert_eq!(cfg.pair.code_minutes, 3);
        assert_eq!((cfg.ports.helper, cfg.ports.admin), (16080, 17000));
        assert_eq!(cfg.guest.invite_days, 7);
        // the address as stages 1 to 4 wrote it
        assert_eq!(cfg.address.current, Some(Ipv4Addr::new(10, 0, 0, 5)));
        assert!(cfg.address.automatic());
        assert_eq!(cfg.address.check_minutes, 5);
        let text = r#"{ "address": { "current": null, "adapter": "Ethernet" } }"#;
        std::fs::write(dir.path().join(CONFIG_FILE), text).unwrap();
        let cfg = HubConfig::load(dir.path()).unwrap();
        assert_eq!(cfg.address.current, None);
        assert!(!cfg.address.automatic());
        assert_eq!(cfg.address.check_minutes, 5);
        std::fs::write(dir.path().join(CONFIG_FILE), "{").unwrap();
        assert!(HubConfig::load(dir.path()).unwrap_err().contains("damaged"));
    }
}
