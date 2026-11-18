//! Keep Hub: the one program on a household's computer that phones connect to, shared by
//! every Keep and Pick app on that computer. See `docs/specs/keep-hub.md`.
//!
//! Built so far (stage 1 of AGENTS.md section 5): the relay on each app's port
//! ([`relay`]), the registry of apps, members, grants and devices ([`registry`]), pairing
//! and guests ([`hub`]) and the admin address ([`admin`]).
//!
//! Copied from ShareKeep's hub (`crates/sk-hub`) as the starting point: the certificate
//! authority and TLS settings ([`ca`]), the PIN hashing ([`pin`]), the key store ([`keys`],
//! with [`seal`] from `sk-client`), the device registry ([`registry`]) and the connection
//! limits of the TLS relay ([`relay`]). Keep Hub copies rather than depends on them, so it
//! builds on its own.
//!
//! The hub holds no app's books and no app's rules.

mod admin;
pub mod ca;
pub mod config;
pub mod http;
pub mod hub;
pub mod keys;
pub mod pin;
pub mod registry;
pub mod relay;
pub mod seal;
pub mod util;

pub use config::HubConfig;
pub use hub::{admin_token, setup, start, HubOptions, Running};
pub use keys::KeyStore;
