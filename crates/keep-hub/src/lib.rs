//! Keep Hub: the one program on a household's computer that phones connect to, shared by
//! every Keep and Pick app on that computer. See `docs/specs/keep-hub.md`.
//!
//! Built (stages 1 to 7 of AGENTS.md section 5, and stage 8): the relay on each app's port
//! ([`relay`]), the registry of apps, members, grants and devices ([`registry`]), pairing
//! and guests ([`hub`]), the admin address ([`admin`]), web clients' files passed through
//! whatever their size, compression or caching ([`relay`], [`http`]), and the hub name with
//! its certificate ([`names`], using [`nameservice`], [`acme`], [`dns`], [`client`] and
//! [`der`]), both certificates on every app port ([`ca`]) and the certificate page
//! ([`page`]), the home address and the firewall ([`machine`]), Find the problem
//! ([`problems`]), running as a service ([`service`], with [`owner`]), and (stage 8)
//! administrators and standard members (`hub::household`).
//!
//! Copied from ShareKeep's hub (`crates/sk-hub`) as the starting point: the certificate
//! authority and TLS settings ([`ca`]), the PIN hashing ([`pin`]), the key store ([`keys`],
//! with [`seal`] from `sk-client`), the device registry ([`registry`]) and the connection
//! limits of the TLS relay ([`relay`]). From MoneyKeep's server: the firewall check and
//! fix, and the adapter scripts ([`machine`]). Keep Hub copies rather than depends on them, so it
//! builds on its own.
//!
//! Apps work with the hub through the small library in `crates/keep-hub-app` (stage 6),
//! which each app copies.
//!
//! The hub holds no app's books and no app's rules.

pub mod acme;
mod admin;
pub mod ca;
pub mod client;
pub mod config;
pub mod der;
pub mod dns;
pub mod http;
pub mod hub;
pub mod keys;
pub mod linuxfw;
pub mod machine;
pub mod names;
pub mod nameservice;
pub mod owner;
pub mod page;
pub mod pin;
pub mod probe;
pub mod problems;
pub mod proof;
pub mod registry;
pub mod relay;
pub mod seal;
pub mod service;
pub mod util;
pub mod winfw;

pub use config::HubConfig;
pub use hub::{admin_token, reset_administrator, setup, start, HubOptions, Running};
pub use keys::KeyStore;
