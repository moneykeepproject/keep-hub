//! The desktop program's side: find the hub on this computer and use its admin address
//! (`http://127.0.0.1:16081`, this computer only) with the admin token from the hub's data
//! folder. Every request the Phones screen needs is here.
//!
//! The admin address is plain HTTP/1.1 on loopback, one request per connection, so this
//! talks to it with `std` alone.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

/// The hub's public facts in its data folder.
const HUB_FILE: &str = "hub.json";
/// The admin token in the hub's data folder.
const TOKEN_FILE: &str = "admin.token";
/// The admin address's port when `hub.json` doesn't say.
const ADMIN_PORT: u16 = 16081;
/// The largest answer read (the admin address's lists are small).
const MAX_ANSWER: u64 = 4 * 1024 * 1024;

/// The hub's data folder: `%ProgramData%\Keep Hub` on Windows (the spec), and on a Mac
/// `~/Library/Application Support/Keep Hub`, where the hub's disk image puts it (the hub runs
/// as the person who installed it, as ShareKeep's), and on Linux `/var/lib/keep-hub`, the
/// systemd service's folder (Revision 4 D; its `admin.token` is readable by the `keep-hub`
/// group). Elsewhere none: the app passes its own.
pub fn default_data_folder() -> Option<PathBuf> {
    if cfg!(windows) {
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        Some(base.join("Keep Hub"))
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|h| {
            PathBuf::from(h)
                .join("Library")
                .join("Application Support")
                .join("Keep Hub")
        })
    } else if cfg!(target_os = "linux") {
        Some(PathBuf::from("/var/lib/keep-hub"))
    } else {
        None
    }
}

/// A request to the hub that didn't work: the hub's own code and words, or why it
/// couldn't be asked. Never holds a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubError {
    /// The hub's answer, or `None` when it couldn't be reached or read.
    pub status: Option<u16>,
    /// The hub's code (such as `pin_wrong` or `port_taken`), or this library's.
    pub code: String,
    /// Plain words for the person.
    pub message: String,
}

impl HubError {
    pub(crate) fn here(code: &str, message: impl Into<String>) -> HubError {
        HubError {
            status: None,
            code: code.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for HubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for HubError {}

/// What [`find`] found on this computer.
#[derive(Debug)]
pub enum Found {
    /// No hub here: offer to make this computer the household's hub (keep-launcher).
    NotInstalled,
    /// Installed, but its admin token can't be read (the message says why).
    NoAccess(HubError),
    /// Installed and stopped: offer to start it. The client works once it runs.
    Stopped(HubClient),
    /// Running, and not set up yet: the first administrator and the household PIN come
    /// first ([`HubClient::set_up`]), or the first administrator of a household where the
    /// computer's sign-in is enough ([`HubClient::set_up_open`]). Until then the hub accepts
    /// nothing else.
    NotSetUp(HubClient),
    /// Running.
    Running(HubClient, HubStatus),
}

/// Look for the hub whose data folder is `data`: installed, and running?
///
/// On Windows the folder and the admin token must belong to the administrators, SYSTEM or the
/// hub's service: any user can make a folder of that name in `%ProgramData%`, and an app that
/// believed its token would register with whatever answered.
pub fn find(data: &Path) -> Found {
    find_with(data, crate::owner::protected)
}

/// [`find`], with the owner check given: the unit tests' temporary folders are the person's
/// own, which Windows' check rightly refuses. Not public: an app always gets the real check.
fn find_with(data: &Path, protected: fn(&Path) -> Result<(), String>) -> Found {
    if !data.join(HUB_FILE).is_file() && !data.join(TOKEN_FILE).is_file() {
        return Found::NotInstalled;
    }
    for p in [data.to_path_buf(), data.join(TOKEN_FILE)] {
        if let Err(why) = protected(&p) {
            return Found::NoAccess(HubError::here(
                "not_the_hubs_folder",
                format!(
                    "A folder named {} is on this computer, but Keep Hub's setup didn't make it ({why}). Remove it, then install Keep Hub again.",
                    data.display()
                ),
            ));
        }
    }
    let hub = match HubClient::open(data) {
        Ok(h) => h,
        Err(e) => return Found::NoAccess(e),
    };
    match hub.status() {
        Ok(s) => Found::Running(hub, s),
        Err(e) if e.code == "setup_needed" => Found::NotSetUp(hub),
        Err(_) => Found::Stopped(hub),
    }
}

/// An administrator signed in on this computer ([`HubClient::sign_in`]).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SignedIn {
    pub member: Member,
    /// How long the session lasts after its last use.
    pub session_minutes: u32,
}

/// The classes of household member.
pub const ADMINISTRATOR: &str = "administrator";
pub const STANDARD: &str = "standard";

/// The hub's admin address, with its token, and an administrator's session once one signs
/// in. The session is kept in memory only, and goes when the client is dropped (as the
/// spec asks: "The desktop app drops it when it closes").
pub struct HubClient {
    addr: SocketAddr,
    token: Zeroizing<String>,
    session: std::sync::Mutex<Option<Zeroizing<String>>>,
    timeout: Duration,
}

impl std::fmt::Debug for HubClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HubClient")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

// ----- what the hub answers ----------------------------------------------------------------------

/// A registered app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubApp {
    pub id: String,
    pub title: String,
    pub version: String,
    pub protocol: u32,
    pub public_port: u16,
    pub loopback_port: u16,
    pub money: bool,
    pub guests: bool,
    /// When it was first registered (milliseconds since 1970).
    pub registered: i64,
    /// How its phones pair: `code_and_pin` or `code` (Revision 2 A). `None` from a hub
    /// older than that, which pairs every phone with the PIN.
    #[serde(default)]
    pub pairing: Option<String>,
}

/// A registered app and how it is doing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppState {
    pub app: HubApp,
    /// `running`, `app_stopped` (its backend doesn't answer), `port_closed` (not on a home
    /// network, or the port couldn't be opened), or `not_registered_fully`.
    pub state: String,
}

/// `GET /admin/v1/status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubStatus {
    pub version: String,
    /// The hub protocol numbers this hub accepts.
    pub protocols: Vec<u32>,
    /// This computer's home address, when it has one.
    pub address: Option<String>,
    /// The name's state: `off`, `registering`, `proving`, `ready`, `blocked`, `waiting`.
    pub names: String,
    /// Where a person asks for a registration code (Revision 3; `None` from an older hub).
    #[serde(default)]
    pub code_page: Option<String>,
    /// Whether turning names on needs a registration code: show the code field and the
    /// **Get a code** button only then (Revision 3).
    #[serde(default)]
    pub code_needed: Option<bool>,
    /// `open` (the computer's sign-in is enough) or `secured` (Revision 2 B; `None` from an
    /// older hub, whose households are all secured).
    #[serde(default)]
    pub household: Option<String>,
    /// The tunnel's public hostname, when one is set (Revision 4 B; `None` also from an
    /// older hub).
    #[serde(default)]
    pub tunnel: Option<TunnelStatus>,
    pub apps: Vec<AppState>,
}

/// The tunnel part of the status (Revision 4 B).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelStatus {
    /// Away from home, phones open `https://<hostname>`.
    pub hostname: Option<String>,
}

/// A probe nonce (Revision 4 A): open `url`, then ask [`HubClient::probe_seen`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Probe {
    pub nonce: String,
    /// The address a phone should open (`None` with no home address).
    pub url: Option<String>,
    /// When it is forgotten (milliseconds since 1970).
    pub expires: i64,
    pub minutes: u32,
}

/// Whether the hub saw a probe, when, and how: `home`, `tunnel`, `this_computer` or
/// `outside`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ProbeSeen {
    pub seen: bool,
    #[serde(default)]
    pub when: Option<i64>,
    #[serde(default)]
    pub source: Option<String>,
}

/// A tunnel from the name service (Revision 4 B, Path B). The token is for the connector
/// only: hand it on and drop it. It is never in `Debug`.
pub struct MoneyKeepTunnel {
    pub hostname: String,
    pub port: u16,
    pub token: Zeroizing<String>,
}

impl std::fmt::Debug for MoneyKeepTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MoneyKeepTunnel")
            .field("hostname", &self.hostname)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl HubStatus {
    /// Whether this hub accepts `protocol`.
    pub fn accepts(&self, protocol: u32) -> bool {
        self.protocols.contains(&protocol)
    }

    /// This app's entry, when registered.
    pub fn app(&self, id: &str) -> Option<&AppState> {
        self.apps.iter().find(|a| a.app.id == id)
    }

    /// Whether the household is open: the admin token alone acts as an administrator,
    /// and nobody signs in (Revision 2 B).
    pub fn household_is_open(&self) -> bool {
        self.household.as_deref() == Some("open")
    }
}

/// A person in the household, or a guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub id: u32,
    pub name: String,
    /// `administrator`, `standard` or `guest`.
    #[serde(default)]
    pub class: String,
    /// An administrator with a password (who can sign in).
    #[serde(default)]
    pub password_set: bool,
    /// For a guest: the app and scope of the invite.
    #[serde(default)]
    pub guest_app: Option<String>,
    #[serde(default)]
    pub guest_scope: Option<String>,
    #[serde(default)]
    pub created: i64,
}

/// A member may use an app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub member: u32,
    pub app: String,
    pub created: i64,
}

/// One app on one phone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub id: u32,
    pub member: u32,
    pub app: String,
    pub name: String,
    pub created: i64,
    pub last_seen: Option<i64>,
    /// When it was removed; it stays in the list.
    pub revoked: Option<i64>,
}

/// A guest invite not used yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    pub id: u32,
    pub app: String,
    pub scope: String,
    pub created: i64,
    pub expires: i64,
}

/// A pairing code or a guest invite, with where the phone opens it. Show `code` and a QR
/// code of `url`; it is a secret until used, so don't log it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pairing {
    /// `ABCD-EFGH`.
    pub code: String,
    /// By the hub's name when it has a real certificate, else by address.
    pub url: String,
    pub url_by_name: Option<String>,
    pub url_by_address: String,
    /// The certificate page, for a phone that connects by address.
    pub certificate_page: String,
    pub expires: i64,
    /// An invite's id (to cancel it); none for a pairing code.
    #[serde(default)]
    pub id: Option<u32>,
}

impl std::fmt::Debug for Pairing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pairing")
            .field("expires", &self.expires)
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// One of Find the problem's checks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProblemCheck {
    /// 1 to 10, in the spec's order.
    pub number: u8,
    pub code: String,
    /// `ok`, `failed`, `skipped` or `unknown` (couldn't be checked).
    pub status: String,
    /// Plain words for the person.
    pub words: String,
    /// What to offer, if anything: `{"kind", "label", ...}`. Kinds: `open` (`target`),
    /// `fix` (`command`, `permission`: run it with the system's permission prompt),
    /// `retry`, `admin` (`method`, `path` on the admin address), `fallback` (`target`),
    /// `start_app` (`app`).
    pub action: Option<Value>,
}

/// Find the problem's results.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Problems {
    pub checks: Vec<ProblemCheck>,
    /// The failed check the run stopped at; none when nothing failed.
    pub stopped_at: Option<u8>,
    /// When the checks ran (none before the first run).
    pub at: Option<i64>,
}

impl Problems {
    /// The check that failed, if one did.
    pub fn failure(&self) -> Option<&ProblemCheck> {
        self.checks.iter().find(|c| c.status == "failed")
    }
}

// ----- the client --------------------------------------------------------------------------------

fn field<T: for<'de> Deserialize<'de>>(v: Value, key: &str) -> Result<T, HubError> {
    let inner = match v {
        Value::Object(mut m) => m.remove(key).unwrap_or(Value::Null),
        _ => Value::Null,
    };
    serde_json::from_value(inner).map_err(|e| unreadable(&e))
}

fn parse<T: for<'de> Deserialize<'de>>(v: Value) -> Result<T, HubError> {
    serde_json::from_value(v).map_err(|e| unreadable(&e))
}

fn unreadable(e: &dyn std::fmt::Display) -> HubError {
    HubError::here(
        "unreadable",
        format!("Keep Hub's answer couldn't be read ({e}). Is the hub newer than this app?"),
    )
}

/// One path part, percent-encoded.
fn part(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl HubClient {
    /// The hub whose data folder is `data`: its admin port from `hub.json`, its token from
    /// `admin.token`. Doesn't contact it.
    pub fn open(data: &Path) -> Result<HubClient, HubError> {
        let port = std::fs::read(data.join(HUB_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|v| v["ports"]["admin"].as_u64())
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0)
            .unwrap_or(ADMIN_PORT);
        let token = std::fs::read_to_string(data.join(TOKEN_FILE)).map_err(|e| {
            let why = if e.kind() == std::io::ErrorKind::PermissionDenied {
                "this user isn't allowed to read it"
            } else {
                "it can't be read"
            };
            HubError::here(
                "no_admin_token",
                format!("Keep Hub is installed, but its admin token can't be used: {why}."),
            )
        })?;
        Ok(HubClient::at(
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            token.trim(),
        ))
    }

    /// A hub at a known admin address (tests, or a hub started with other ports).
    pub fn at(addr: SocketAddr, token: &str) -> HubClient {
        HubClient {
            addr,
            token: Zeroizing::new(token.to_string()),
            session: std::sync::Mutex::new(None),
            timeout: Duration::from_secs(60),
        }
    }

    /// Where the admin address is.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// One request; the hub's JSON answer, or its refusal.
    fn call(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, HubError> {
        let down = |e: std::io::Error| {
            HubError::here(
                "hub_unreachable",
                format!("Keep Hub isn't answering on this computer ({e}). Is it running?"),
            )
        };
        // (the body can hold a PIN: wiped after sending, like the token)
        let body = Zeroizing::new(body.map(|b| b.to_string()).unwrap_or_default());
        let mut stream =
            TcpStream::connect_timeout(&self.addr, Duration::from_secs(3)).map_err(down)?;
        stream.set_read_timeout(Some(self.timeout)).map_err(down)?;
        stream.set_write_timeout(Some(self.timeout)).map_err(down)?;
        let session = match self.session.lock() {
            Ok(s) => s
                .as_ref()
                .map(|s| Zeroizing::new(format!("Keep-Admin-Session: {}\r\n", s.as_str()))),
            Err(_) => None,
        };
        let head = format!(
            "{method} /admin/v1/{path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\n{}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.addr,
            self.token.as_str(),
            session.as_ref().map_or("", |s| s.as_str()),
            body.len()
        );
        let mut request = Zeroizing::new(head.into_bytes());
        request.extend_from_slice(body.as_bytes());
        stream.write_all(&request).map_err(down)?;
        let mut answer = Vec::new();
        (&mut stream)
            .take(MAX_ANSWER)
            .read_to_end(&mut answer)
            .map_err(down)?;
        let (status, body) = split_answer(&answer)?;
        let v: Value = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).map_err(|e| unreadable(&e))?
        };
        if (200..300).contains(&status) {
            Ok(v)
        } else {
            Err(HubError {
                status: Some(status),
                code: v["error"].as_str().unwrap_or("refused").to_string(),
                message: v["message"]
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("Keep Hub refused the request ({status}).")),
            })
        }
    }

    // ----- administrators -----

    /// The first set-up, while the hub has no administrator: the first administrator (a
    /// name and a password of at least 8 characters) and the household PIN. This client is
    /// then signed in as them.
    pub fn set_up(&self, name: &str, password: &str, pin: &str) -> Result<SignedIn, HubError> {
        let body = json!({ "name": name, "password": password, "pin": pin });
        let v = self.call("POST", "setup", Some(&body))?;
        self.keep_session(v)
    }

    /// The first set-up of an open household (Revision 2 B): the first administrator, by
    /// name, with no password and no household PIN. The computer's sign-in is then enough:
    /// anyone who can use this computer under a sign-in that can read the hub's admin token
    /// can add phones, members and apps. Say so plainly before offering it.
    pub fn set_up_open(&self, name: &str) -> Result<Member, HubError> {
        let body = json!({ "name": name, "sign_in_is_enough": true });
        field(self.call("POST", "setup", Some(&body))?, "member")
    }

    /// Secure an open household (Revision 2 B), for good: a password for the named
    /// administrator and the household PIN. This client is then signed in as them.
    pub fn secure(&self, name: &str, password: &str, pin: &str) -> Result<SignedIn, HubError> {
        let body = json!({ "name": name, "password": password, "pin": pin });
        let v = self.call("POST", "secure", Some(&body))?;
        self.keep_session(v)
    }

    /// Sign in as an administrator. Requests that need one carry the session from then on.
    pub fn sign_in(&self, name: &str, password: &str) -> Result<SignedIn, HubError> {
        let body = json!({ "name": name, "password": password });
        let v = self.call("POST", "session", Some(&body))?;
        self.keep_session(v)
    }

    fn keep_session(&self, mut v: Value) -> Result<SignedIn, HubError> {
        let session = v
            .get_mut("session")
            .and_then(|s| s.as_str().map(|s| Zeroizing::new(s.to_string())))
            .ok_or_else(|| unreadable(&"no session"))?;
        if let Some(s) = v.as_object_mut() {
            s.remove("session");
        }
        let signed: SignedIn = parse(v)?;
        if let Ok(mut s) = self.session.lock() {
            *s = Some(session);
        }
        Ok(signed)
    }

    /// Sign out: the hub ends the session.
    pub fn sign_out(&self) -> Result<(), HubError> {
        let r = self.call("DELETE", "session", None).map(drop);
        if let Ok(mut s) = self.session.lock() {
            *s = None;
        }
        r
    }

    /// Whether this client holds a session. (The hub may have ended it since: a request
    /// then answers `administrator_needed`, and the person signs in again.)
    pub fn signed_in(&self) -> bool {
        self.session.lock().map(|s| s.is_some()).unwrap_or(false)
    }

    // ----- the hub and apps -----

    /// The hub's version, protocols, address, name state and each app's state.
    pub fn status(&self) -> Result<HubStatus, HubError> {
        parse(self.call("GET", "status", None)?)
    }

    pub fn apps(&self) -> Result<Vec<HubApp>, HubError> {
        field(self.call("GET", "apps", None)?, "apps")
    }

    /// Register (see [`crate::ensure_registered`], which keeps the secret): the shared
    /// secret, which isn't kept anywhere by this call.
    /// The answer's `pairing` is `None` from a hub older than Revision 2; its firewall words
    /// come only on Linux, when the port isn't open yet.
    #[allow(clippy::type_complexity)]
    pub(crate) fn register_raw(
        &self,
        r: &crate::Registration,
    ) -> Result<(Zeroizing<String>, Option<String>, Option<String>), HubError> {
        let body = serde_json::to_value(r).map_err(|e| unreadable(&e))?;
        let v = self.call("POST", "apps", Some(&body))?;
        let secret = v["secret"]
            .as_str()
            .map(|s| Zeroizing::new(s.to_string()))
            .ok_or_else(|| unreadable(&"no secret"))?;
        Ok((
            secret,
            v["pairing"].as_str().map(str::to_string),
            v["firewall"]["words"].as_str().map(str::to_string),
        ))
    }

    /// Unregister an app: its port closes and its phones are removed.
    pub fn unregister(&self, app: &str) -> Result<(), HubError> {
        self.call("DELETE", &format!("apps/{}", part(app)), None)
            .map(drop)
    }

    // ----- members and grants -----

    pub fn members(&self) -> Result<Vec<Member>, HubError> {
        field(self.call("GET", "members", None)?, "members")
    }

    /// Add a person to the household as a standard member: their id.
    pub fn add_member(&self, name: &str) -> Result<u32, HubError> {
        self.add_member_as(name, STANDARD)
    }

    /// Add a person to the household as an [`ADMINISTRATOR`] or a [`STANDARD`] member: their
    /// id. A new administrator has no password until one is set
    /// ([`Self::set_password`]).
    pub fn add_member_as(&self, name: &str, class: &str) -> Result<u32, HubError> {
        let body = json!({ "name": name, "class": class });
        field(self.call("POST", "members", Some(&body))?, "id")
    }

    /// Make a member an administrator or a standard member. The last administrator stays
    /// one (`last_administrator`).
    pub fn set_class(&self, member: u32, class: &str) -> Result<(), HubError> {
        let body = json!({ "class": class });
        self.call("PUT", &format!("members/{member}/class"), Some(&body))
            .map(drop)
    }

    /// Set an administrator's password (at least 8 characters).
    pub fn set_password(&self, member: u32, password: &str) -> Result<(), HubError> {
        let body = json!({ "password": password });
        self.call("PUT", &format!("members/{member}/password"), Some(&body))
            .map(drop)
    }

    /// Remove a member from the household: their phones are removed and their grants go.
    pub fn remove_member(&self, member: u32) -> Result<(), HubError> {
        self.call("DELETE", &format!("members/{member}"), None)
            .map(drop)
    }

    pub fn rename_member(&self, member: u32, name: &str) -> Result<(), HubError> {
        self.call(
            "PUT",
            &format!("members/{member}"),
            Some(&json!({ "name": name })),
        )
        .map(drop)
    }

    pub fn grants(&self) -> Result<Vec<Grant>, HubError> {
        field(self.call("GET", "grants", None)?, "grants")
    }

    /// Let a member use an app (an administrator's act; no PIN is asked).
    pub fn give_grant(&self, member: u32, app: &str) -> Result<(), HubError> {
        let body = json!({ "member": member, "app": app });
        self.call("POST", "grants", Some(&body)).map(drop)
    }

    /// Take the app away from a member: their phones for it stop working.
    pub fn remove_grant(&self, member: u32, app: &str) -> Result<(), HubError> {
        self.call("DELETE", &format!("grants/{member}/{}", part(app)), None)
            .map(drop)
    }

    // ----- phones -----

    pub fn devices(&self) -> Result<Vec<Device>, HubError> {
        field(self.call("GET", "devices", None)?, "devices")
    }

    /// Remove a phone: its token is refused from then on.
    pub fn revoke_device(&self, device: u32) -> Result<(), HubError> {
        self.call("DELETE", &format!("devices/{device}"), None)
            .map(drop)
    }

    /// A pairing code for a member and an app (making the grant first if needed).
    pub fn make_pairing_code(&self, member: u32, app: &str) -> Result<Pairing, HubError> {
        let body = json!({ "member": member, "app": app });
        parse(self.call("POST", "pairing-codes", Some(&body))?)
    }

    pub fn cancel_pairing_code(&self, code: &str) -> Result<(), HubError> {
        self.call("DELETE", &format!("pairing-codes/{}", part(code)), None)
            .map(drop)
    }

    pub fn invites(&self) -> Result<Vec<Invite>, HubError> {
        field(self.call("GET", "invites", None)?, "invites")
    }

    /// A guest invite for an app that accepts guests, for one scope (the app's own text).
    pub fn make_invite(&self, app: &str, scope: &str) -> Result<Pairing, HubError> {
        let body = json!({ "app": app, "scope": scope });
        parse(self.call("POST", "invites", Some(&body))?)
    }

    pub fn cancel_invite(&self, invite: u32) -> Result<(), HubError> {
        self.call("DELETE", &format!("invites/{invite}"), None)
            .map(drop)
    }

    // ----- the PIN -----

    /// Whether the household has a PIN yet.
    pub fn pin_is_set(&self) -> Result<bool, HubError> {
        field(self.call("GET", "pin", None)?, "set")
    }

    /// Set a new household PIN (6 to 12 digits). The old one is not needed.
    pub fn set_pin(&self, pin: &str) -> Result<(), HubError> {
        let body = json!({ "pin": pin });
        self.call("PUT", "pin", Some(&body)).map(drop)
    }

    // ----- the name -----

    /// The name's state and certificate, as the hub gives them.
    pub fn names(&self) -> Result<Value, HubError> {
        self.call("GET", "names", None)
    }

    /// Turn names on (the name service's registration code the first time).
    pub fn names_on(&self, registration_code: Option<&str>) -> Result<Value, HubError> {
        let body = json!({ "registration_code": registration_code });
        self.call("POST", "names/on", Some(&body))
    }

    /// Change where a person asks for a registration code (`names.code_page`): an
    /// `https://` address of at most 200 characters (Revision 3).
    pub fn set_code_page(&self, page: &str) -> Result<Value, HubError> {
        let body = json!({ "code_page": page });
        self.call("PUT", "names/code-page", Some(&body))
    }

    // ----- Revision 4: the probe, the tunnel, Fix -----

    /// A probe nonce and the address a phone should open (an administrator's request).
    pub fn probe(&self) -> Result<Probe, HubError> {
        parse(self.call("POST", "probe", None)?)
    }

    /// Whether the hub saw the probe `nonce` (`no_such_probe` once its life is over).
    pub fn probe_seen(&self, nonce: &str) -> Result<ProbeSeen, HubError> {
        parse(self.call("GET", &format!("probe/{}", part(nonce)), None)?)
    }

    /// Set the tunnel's public hostname (`tunnel.hostname`), shown to apps and phones.
    pub fn set_tunnel_hostname(&self, hostname: &str) -> Result<Option<String>, HubError> {
        let body = json!({ "hostname": hostname });
        field(self.call("PUT", "tunnel", Some(&body))?, "hostname")
    }

    /// Clear the tunnel's hostname.
    pub fn clear_tunnel_hostname(&self) -> Result<(), HubError> {
        self.call("DELETE", "tunnel", None).map(drop)
    }

    /// Ask the name service, through the hub, for a tunnel to the first app's port. The
    /// hub sets the hostname to the away name; the token is for the connector only.
    pub fn make_moneykeep_tunnel(&self) -> Result<MoneyKeepTunnel, HubError> {
        let mut v = self.call("PUT", "tunnel/moneykeep-name", None)?;
        let token = v
            .get_mut("token")
            .and_then(|t| t.as_str().map(|t| Zeroizing::new(t.to_string())))
            .ok_or_else(|| unreadable(&"no token"))?;
        if let Some(o) = v.as_object_mut() {
            o.remove("token");
        }
        Ok(MoneyKeepTunnel {
            hostname: v["hostname"].as_str().unwrap_or("").to_string(),
            port: v["port"]
                .as_u64()
                .and_then(|p| u16::try_from(p).ok())
                .unwrap_or(0),
            token,
        })
    }

    /// The name service deletes the tunnel, and the hub clears the hostname.
    pub fn remove_moneykeep_tunnel(&self) -> Result<(), HubError> {
        self.call("DELETE", "tunnel/moneykeep-name", None).map(drop)
    }

    /// Fix a check (only check 4, the firewall, has one): the check's new result.
    pub fn fix(&self, check: u8) -> Result<ProblemCheck, HubError> {
        let body = json!({ "check": check });
        field(self.call("POST", "problems/fix", Some(&body))?, "check")
    }

    /// Turn names off (the name and certificate are kept).
    pub fn names_off(&self) -> Result<Value, HubError> {
        self.call("POST", "names/off", None)
    }

    /// Ask for a new certificate now ("Renew now").
    pub fn renew(&self) -> Result<Value, HubError> {
        self.call("POST", "names/renew", None)
    }

    /// Send the address to the name service again ("Update the name").
    pub fn resend_address(&self) -> Result<(), HubError> {
        self.call("POST", "names/address", None).map(drop)
    }

    /// This computer's home address, the adapter setting, and every adapter.
    pub fn addresses(&self) -> Result<Value, HubError> {
        self.call("GET", "addresses", None)
    }

    /// Which adapter's address to use (`automatic` for the default route's).
    pub fn choose_adapter(&self, adapter: &str) -> Result<Value, HubError> {
        self.call("PUT", "address", Some(&json!({ "adapter": adapter })))
    }

    // ----- Find the problem -----

    /// Run the checks (they can take some seconds: the name service and DNS are asked).
    pub fn find_problems(&self) -> Result<Problems, HubError> {
        parse(self.call("POST", "problems", None)?)
    }

    /// The last results, from whichever app ran them.
    pub fn last_problems(&self) -> Result<Problems, HubError> {
        parse(self.call("GET", "problems", None)?)
    }

    /// Any other admin request (`path` after `/admin/v1/`), for what this library doesn't
    /// wrap yet.
    pub fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, HubError> {
        self.call(method, path.trim_start_matches('/'), body)
    }
}

/// The status and body of an HTTP/1.1 answer (with `Content-Length`, chunked, or ended by
/// the connection closing).
fn split_answer(answer: &[u8]) -> Result<(u16, Vec<u8>), HubError> {
    let bad = || HubError::here("unreadable", "Keep Hub's answer couldn't be read.");
    let end = answer
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(bad)?;
    let head = std::str::from_utf8(answer.get(..end).ok_or_else(bad)?).map_err(|_| bad())?;
    let body = answer.get(end + 4..).ok_or_else(bad)?;
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(bad)?;
    let mut length = None;
    let mut chunked = false;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let (k, v) = (k.trim(), v.trim());
            if k.eq_ignore_ascii_case("content-length") {
                length = v.parse::<usize>().ok();
            } else if k.eq_ignore_ascii_case("transfer-encoding") {
                chunked = v.to_ascii_lowercase().contains("chunked");
            }
        }
    }
    let body = if chunked {
        unchunk(body).ok_or_else(bad)?
    } else if let Some(n) = length {
        body.get(..n).ok_or_else(bad)?.to_vec()
    } else {
        body.to_vec()
    };
    Ok((status, body))
}

fn unchunk(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = b.windows(2).position(|w| w == b"\r\n")?;
        let size = std::str::from_utf8(b.get(..eol)?).ok()?;
        let size = usize::from_str_radix(size.split(';').next()?.trim(), 16).ok()?;
        b = b.get(eol + 2..)?;
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(b.get(..size)?);
        b = b.get(size + 2..)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_are_read_with_a_length_chunked_or_to_the_end() {
        let (s, b) = split_answer(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}junk").unwrap();
        assert_eq!((s, b.as_slice()), (200, b"{}".as_slice()));
        let (s, b) = split_answer(
            b"HTTP/1.1 409 Conflict\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n{\"a\r\n4\r\n\":1}\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!((s, b.as_slice()), (409, b"{\"a\":1}".as_slice()));
        let (s, b) = split_answer(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();
        assert_eq!((s, b.len()), (204, 0));
        assert!(split_answer(b"HTTP/1.1 200 OK\r\n").is_err());
        assert!(split_answer(b"nonsense\r\n\r\n").is_err());
    }

    #[test]
    fn path_parts_are_encoded() {
        assert_eq!(part("ABCD-EFGH"), "ABCD-EFGH");
        assert_eq!(part("a/b c"), "a%2Fb%20c");
    }

    /// The owner check passed, for a test's temporary folder (the person's own).
    fn anyones(_: &Path) -> Result<(), String> {
        Ok(())
    }

    /// On Windows a folder the person owns is refused before anything else is read. A test's
    /// temporary folder is the person's own on their computer; when the tests run elevated
    /// (GitHub's Windows runner) the administrators own it and the real check believes it, so
    /// the refusal is expected only where the owner check itself refuses (always passes
    /// elsewhere).
    fn refused_on_windows(dir: &Path) {
        let believed = [dir.to_path_buf(), dir.join(TOKEN_FILE)]
            .iter()
            .all(|p| crate::owner::protected(p).is_ok());
        if !believed {
            match find(dir) {
                Found::NoAccess(e) => assert_eq!(e.code, "not_the_hubs_folder", "{e}"),
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn a_missing_folder_is_not_installed_and_an_unreadable_token_says_so() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(find(dir.path()), Found::NotInstalled));
        std::fs::write(dir.path().join(HUB_FILE), r#"{"ports":{"admin":1}}"#).unwrap();
        refused_on_windows(dir.path());
        match find_with(dir.path(), anyones) {
            Found::NoAccess(e) => {
                assert_eq!(e.code, "no_admin_token");
                assert!(e.message.contains("installed"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_hub_that_doesnt_answer_is_stopped_and_the_port_comes_from_hub_json() {
        let dir = tempfile::tempdir().unwrap();
        // a port nothing listens on
        let free = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = free.local_addr().unwrap().port();
        drop(free);
        std::fs::write(
            dir.path().join(HUB_FILE),
            format!(r#"{{"ports":{{"admin":{port}}}}}"#),
        )
        .unwrap();
        std::fs::write(dir.path().join(TOKEN_FILE), "the-token\n").unwrap();
        refused_on_windows(dir.path());
        match find_with(dir.path(), anyones) {
            Found::Stopped(h) => {
                assert_eq!(h.addr().port(), port);
                let e = h.status().unwrap_err();
                assert_eq!((e.status, e.code.as_str()), (None, "hub_unreachable"));
                assert!(!format!("{h:?} {e}").contains("the-token"));
            }
            other => panic!("{other:?}"),
        }
        // the default port when hub.json doesn't say
        std::fs::write(dir.path().join(HUB_FILE), "{}").unwrap();
        assert_eq!(
            HubClient::open(dir.path()).unwrap().addr().port(),
            ADMIN_PORT
        );
    }

    #[test]
    fn the_spec_puts_the_data_folder_in_programdata_on_windows() {
        let found = default_data_folder();
        assert_eq!(
            found.is_some(),
            cfg!(windows) || cfg!(target_os = "macos") || cfg!(target_os = "linux")
        );
        if let Some(p) = found {
            assert!(
                p.ends_with("Keep Hub") || p.ends_with("keep-hub"),
                "{}",
                p.display()
            );
        }
    }
}
