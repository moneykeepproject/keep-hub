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
}

impl Default for NamesSettings {
    fn default() -> Self {
        NamesSettings {
            enabled: false,
            service: crate::nameservice::NAME_SERVICE.to_string(),
            acme: crate::acme::LETS_ENCRYPT.to_string(),
            staging: false,
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
        cfg.save(dir.path()).unwrap();
        assert_eq!(HubConfig::load(dir.path()).unwrap(), cfg);
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
