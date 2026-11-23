//! What a Keep or Pick app needs from Keep Hub, the shared hub phones connect to
//! (`docs/specs/keep-hub.md` of the keep-hub repository). Each app copies this crate, as
//! the Keep apps copy from each other, so every app still builds on its own.
//!
//! - **On the app's backend** (its local server): [`HubAuth`] refuses any request that
//!   didn't come through the hub (the `Keep-Hub-Auth` header) and reads who sent it (the
//!   member, the device, a guest's scope). [`listen`] binds the backend to 127.0.0.1 only.
//! - **In the app's desktop program:** [`offer`] says what to offer when the person turns
//!   on phones (make this computer the hub through keep-launcher, start a stopped hub, or go
//!   on); [`find`] looks for the hub on this computer;
//!   [`HubClient`] talks to its admin address, for every request the Phones screen makes
//!   (members, grants, phones, pairing codes, invites, the PIN, the name, Find the
//!   problem); [`ensure_registered`] registers the app the first time and again when its
//!   version changes, and keeps the shared secret sealed for this computer.
//!
//! The library never logs. Its errors never hold a secret: the shared secret, the admin
//! token, a PIN and pairing codes stay out of them.
//!
//! ```no_run
//! use keep_hub_app::{ensure_registered, find, Found, HubAuth, Registration};
//! # fn main() -> Result<(), keep_hub_app::HubError> {
//! # let app_data = std::path::Path::new("app-data");
//! // the desktop program, when the person turns on phones
//! let Some(folder) = keep_hub_app::default_data_folder() else { return Ok(()) };
//! let hub = match find(&folder) {
//!     Found::Running(hub, _status) => hub,
//!     _ => return Ok(()), // offer to install or start the hub
//! };
//! let me = Registration::new("vacapick", "VacaPick", "1.2.0", 16443, 16444);
//! ensure_registered(&hub, &me, app_data)?;
//!
//! // the backend, at start
//! let auth = HubAuth::load(app_data)?;
//! // each request: the connection's address, the path and the headers
//! let peer: std::net::SocketAddr = "127.0.0.1:50000".parse().unwrap();
//! let headers = [("Keep-Hub-Auth", "...")];
//! if let Some(hello) = auth.hello(peer, "/api/trips", &headers) {
//!     // the hub's hello: answer hello.status with hello.headers (or the refusal) and
//!     // keep the connection open for the request that follows
//!     return Ok(());
//! }
//! match auth.check_from(peer, &headers) {
//!     Ok(Some(caller)) => { /* /api/: caller.member, caller.device, ... */ }
//!     Ok(None) => { /* through the hub, no phone identity: the web client's files */ }
//!     Err(refused) => { /* answer refused.status with refused.code */ }
//! }
//! # Ok(())
//! # }
//! ```

mod auth;
mod client;
mod listener;
mod offer;
mod owner;
mod register;
pub mod seal;

pub use auth::{
    listen, proofs, Caller, Header, Hello, HubAuth, Refused, CHALLENGE, HELLO_PATH, PROOF,
};
pub use client::{
    default_data_folder, find, AppState, Device, Found, Grant, HubApp, HubClient, HubError,
    HubStatus, Invite, Member, MoneyKeepTunnel, Pairing, Probe, ProbeSeen, ProblemCheck, Problems,
    SignedIn, TunnelStatus, ADMINISTRATOR, STANDARD,
};
#[cfg(debug_assertions)]
pub use listener::expect_this_account;
pub use listener::Listener;
pub use offer::{
    make_this_the_hub, offer, start_command, Launcher, Next, Offer, DOWNLOAD_PAGE, LAUNCHER_ENTRY,
};
pub use register::{
    ensure_registered, ports, Registered, Registration, CODE, CODE_AND_PIN, RECORD_FILE,
    SECRET_FILE,
};

/// The hub protocol this library speaks (the hub accepts every older number it supported).
/// Protocol 2 (Revision 5 A): the backend proves it holds the shared secret before the hub
/// sends it anything ([`HubAuth::hello`]).
pub const PROTOCOL: u32 = 2;
