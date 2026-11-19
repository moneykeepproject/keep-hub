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

/// The hub's data folder where the spec puts it: `%ProgramData%\Keep Hub` on Windows. The
/// spec doesn't name the folder on other systems yet, so there the app passes its own.
pub fn default_data_folder() -> Option<PathBuf> {
    if cfg!(windows) {
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        Some(base.join("Keep Hub"))
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
    /// Running.
    Running(HubClient, HubStatus),
}

/// Look for the hub whose data folder is `data`: installed, and running?
pub fn find(data: &Path) -> Found {
    if !data.join(HUB_FILE).is_file() {
        return Found::NotInstalled;
    }
    let hub = match HubClient::open(data) {
        Ok(h) => h,
        Err(e) => return Found::NoAccess(e),
    };
    match hub.status() {
        Ok(s) => Found::Running(hub, s),
        Err(_) => Found::Stopped(hub),
    }
}

/// The hub's admin address, with its token.
pub struct HubClient {
    addr: SocketAddr,
    token: Zeroizing<String>,
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
    pub apps: Vec<AppState>,
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
}

/// A person in the household, or a guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub id: u32,
    pub name: String,
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
        let head = format!(
            "{method} /admin/v1/{path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.addr,
            self.token.as_str(),
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
    pub(crate) fn register_raw(
        &self,
        r: &crate::Registration,
    ) -> Result<Zeroizing<String>, HubError> {
        let body = serde_json::to_value(r).map_err(|e| unreadable(&e))?;
        let v = self.call("POST", "apps", Some(&body))?;
        v["secret"]
            .as_str()
            .map(|s| Zeroizing::new(s.to_string()))
            .ok_or_else(|| unreadable(&"no secret"))
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

    /// Add a person to the household: their id.
    pub fn add_member(&self, name: &str) -> Result<u32, HubError> {
        field(
            self.call("POST", "members", Some(&json!({ "name": name })))?,
            "id",
        )
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

    /// Let a member use an app. An app that declared `money` needs the household PIN.
    pub fn give_grant(&self, member: u32, app: &str, pin: Option<&str>) -> Result<(), HubError> {
        let body = json!({ "member": member, "app": app, "pin": pin });
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

    /// A pairing code for a member and an app (making the grant first if needed; an app
    /// that declared `money` needs the PIN for that).
    pub fn make_pairing_code(
        &self,
        member: u32,
        app: &str,
        pin: Option<&str>,
    ) -> Result<Pairing, HubError> {
        let body = json!({ "member": member, "app": app, "pin": pin });
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

    /// Set the household PIN (6 to 12 digits), or change it with the old one.
    pub fn set_pin(&self, pin: &str, old: Option<&str>) -> Result<(), HubError> {
        let body = json!({ "pin": pin, "old": old });
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

    #[test]
    fn a_missing_folder_is_not_installed_and_an_unreadable_token_says_so() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(find(dir.path()), Found::NotInstalled));
        std::fs::write(dir.path().join(HUB_FILE), r#"{"ports":{"admin":1}}"#).unwrap();
        match find(dir.path()) {
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
        match find(dir.path()) {
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
        assert_eq!(found.is_some(), cfg!(windows));
        if let Some(p) = found {
            assert!(p.ends_with("Keep Hub"));
        }
    }
}
