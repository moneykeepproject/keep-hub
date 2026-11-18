//! `hub.json`: where the hub listens. Public facts only (no keys, no PIN). Copied from
//! ShareKeep's hub, `config.rs`.
//!
//! Each app's public port is in the registry, given when the app registers. Stage 1 keeps
//! the hub computer's address here, as ShareKeep does; finding it and following its
//! changes comes with stage 5 (Addresses).

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

/// The hub's settings, with the spec's keys: `ports.helper` is `{"ports": {"helper": …}}`.
/// A key that is left out has its default. (The `names`, `address` and `cert` settings join
/// with their stages.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubConfig {
    /// The hub computer's address on the home network.
    pub address: Ipv4Addr,
    #[serde(default)]
    pub ports: Ports,
    #[serde(default)]
    pub pair: Pair,
    #[serde(default)]
    pub guest: Guest,
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
    pub fn new(address: Ipv4Addr) -> Self {
        HubConfig {
            address,
            ports: Ports::default(),
            pair: Pair::default(),
            guest: Guest::default(),
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
        std::fs::write(dir.path().join(CONFIG_FILE), "{").unwrap();
        assert!(HubConfig::load(dir.path()).unwrap_err().contains("damaged"));
    }
}
