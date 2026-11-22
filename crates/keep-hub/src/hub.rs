//! The running hub: what it knows (apps, members, grants, devices, pairing codes) and the
//! rules for pairing a phone and for letting a request through. Started from ShareKeep's
//! hub, `server.rs` (setup, start, the pairing rules), then changed for apps and grants.
//!
//! - **Each registered app's port** (`https://<address>:<app port>`): see [`crate::relay`].
//! - **The admin address** (`http://127.0.0.1:16081`, this computer only): see
//!   [`crate::admin`]. It needs the admin token in the hub's data folder.
//!
//! The hub holds no app's books and no app's rules: it only decides who a request is from
//! and whether they may use the app, and passes it on.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};
use tiny_http::Server;
use zeroize::Zeroizing;

use crate::config::HubConfig;
use crate::keys::KeyStore;
use crate::machine::{self, Machine};
use crate::registry::{App, Device, Member, Registry, CODE, CODE_AND_PIN, PIN_KEY};
use crate::util::{self, StoreResult};
use crate::{admin, ca, names, page, pin, relay};

pub(crate) mod household;
pub use household::reset_administrator;

/// The hub protocols this hub accepts from an app. A newer hub keeps every older number.
pub const PROTOCOLS: &[u32] = &[1];
/// The hub's version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const ADMIN_TOKEN_FILE: &str = "admin.token";

/// Wrong PINs before a pairing code is burned.
const CODE_TRIES: u32 = 5;
const FAILURE_WINDOW_MS: i64 = 10 * 60 * 1000;
/// Wrong tries from one address before pairing pauses for that address (as ShareKeep, whose
/// review found that one guest could pause pairing for everyone; owner decision 2026-11-18).
pub const MAX_FAILURES: usize = 10;
/// Wrong tries from everywhere before pairing pauses for everyone (many addresses at once).
pub const MAX_FAILURES_ALL: usize = 100;
/// A device's "last seen" is written at most this often.
const TOUCH_EVERY_MS: i64 = 60_000;
const ADMIN_WORKERS: usize = 4;

/// The hub's clock: milliseconds since 1970 UTC.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;
/// Where log lines go. Lines name the method, path and status only: never a token, a PIN,
/// a pairing code or a shared secret.
pub type Log = Arc<dyn Fn(&str) + Send + Sync>;

/// How the hub runs.
pub struct HubOptions {
    pub data: PathBuf,
    pub keys: KeyStore,
    pub clock: Clock,
    pub log: Log,
    /// The PIN's hash cost (cheaper in tests).
    pub pin_cost: pin::Cost,
    /// A transfer with no bytes moving for this long is closed ([`relay::IDLE`]; shorter
    /// in tests).
    pub idle: Duration,
    /// How long a backend may take to start its answer ([`relay::FIRST_BYTE`]; shorter in
    /// tests).
    pub first_byte: Duration,
    /// The internet, for the hub name (`None`: the real one, trusting what this computer
    /// trusts; tests give fakes).
    pub outside: Option<names::Outside>,
    /// This computer: its address, adapters and firewall (`None`: the real one).
    pub machine: Option<Arc<dyn Machine>>,
    /// How often the hub looks at the default route for a new address.
    pub address_poll: Duration,
}

/// How often the hub looks for a new address (owner decision 2026-11-18: a cheap look at
/// the default route, instead of the system's network-change events). The full look at
/// the adapters is every `address.check_minutes`.
pub const ADDRESS_POLL: Duration = Duration::from_secs(15);

impl HubOptions {
    /// The production settings for a hub keeping its data in `data`.
    pub fn new(data: PathBuf) -> Self {
        HubOptions {
            keys: KeyStore::files(data.clone()),
            data,
            clock: Arc::new(util::now_ms),
            log: Arc::new(|l: &str| eprintln!("{l}")),
            pin_cost: pin::COST,
            idle: relay::IDLE,
            first_byte: relay::FIRST_BYTE,
            outside: None,
            machine: None,
            address_poll: ADDRESS_POLL,
        }
    }
}

/// Set the hub up in `data`: its folder, `hub.json`, the hub's own certificate authority
/// and server certificate, and the admin token. Run once (again only to change the address,
/// which makes a new certificate authority).
pub fn setup(
    data: &Path,
    cfg: &HubConfig,
    keys: &KeyStore,
    computer: &str,
    now_ms: i64,
) -> StoreResult<ca::Info> {
    std::fs::create_dir_all(data).map_err(|e| format!("{} can't be made: {e}", data.display()))?;
    cfg.save(data)?;
    let ip = cfg
        .address
        .current
        .ok_or("The hub needs this computer's home address to be set up.")?;
    let m = ca::ensure(data, keys, &ca::Target { ip }, computer, now_ms / 1000)?;
    if !data.join(ADMIN_TOKEN_FILE).exists() {
        let t = util::hex(&util::random::<32>()?);
        util::write_private(&data.join(ADMIN_TOKEN_FILE), t.as_bytes())?;
    }
    Ok(m.info)
}

/// The admin token the apps' desktop programs on the hub computer use.
pub fn admin_token(data: &Path) -> StoreResult<String> {
    std::fs::read_to_string(data.join(ADMIN_TOKEN_FILE))
        .map(|t| t.trim().to_string())
        .map_err(|e| format!("the admin token can't be read: {e}"))
}

/// A refusal: the HTTP status, a short code for programs, plain words for people.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

impl Refusal {
    pub fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Refusal {
            status,
            code,
            message: message.into(),
        }
    }

    /// The hub's own records failed.
    pub(crate) fn inner(message: String) -> Self {
        Refusal::new(500, "hub_error", message)
    }

    pub(crate) fn not_paired() -> Self {
        Refusal::new(
            401,
            "not_paired",
            "This phone isn't paired with the hub (or was removed). Pair it again.",
        )
    }

    pub(crate) fn no_access() -> Self {
        Refusal::new(
            403,
            "no_access",
            "You don't have access to this app. Ask for it on the hub computer.",
        )
    }
}

/// Who a request is from, once its token is checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub member: Member,
    pub device: Device,
}

/// The key-store name of the secret the hub shares with an app.
fn secret_key(app: &str) -> String {
    format!("app-{app}")
}

#[derive(Debug, Clone)]
struct Pairing {
    app: String,
    member: u32,
    expires: i64,
    tries: u32,
}

/// One app's open port.
pub(crate) struct Listener {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    pub(crate) addr: SocketAddr,
}

impl Listener {
    /// Stop accepting and wait for the port to close.
    fn close(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wait for the loop only when it was woken: otherwise it ends by itself with the
        // next connection, and the hub mustn't hang on it.
        if relay::wake(self.addr) {
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }
}

pub(crate) struct State {
    pub(crate) registry: Registry,
    codes: HashMap<String, Pairing>,
    /// Wrong pairing tries in the last [`FAILURE_WINDOW_MS`], with the address they came from.
    failures: VecDeque<(i64, IpAddr)>,
    /// The secret shared with each app, for `Keep-Hub-Auth`.
    secrets: HashMap<String, Zeroizing<String>>,
    listeners: HashMap<String, Listener>,
    /// The certificate page's front on the home network.
    page: Option<Listener>,
    /// The last "Find the problem" results.
    pub(crate) problems: Option<Value>,
    /// Signed-in administrators, by the SHA-256 of their session.
    sessions: HashMap<[u8; 32], household::Session>,
    /// Wrong passwords and pauses, by administrator.
    sign_ins: HashMap<u32, household::SignIn>,
}

pub(crate) struct Hub {
    state: Mutex<State>,
    /// One registration or removal of an app at a time.
    changing_apps: Mutex<()>,
    pub(crate) data: PathBuf,
    pub(crate) cfg: HubConfig,
    pub(crate) keys: KeyStore,
    clock: Clock,
    log: Log,
    pub(crate) pin_cost: pin::Cost,
    pub(crate) idle: Duration,
    pub(crate) first_byte: Duration,
    pub(crate) admin_token: String,
    /// Where the admin address and the certificate page really listen.
    admin_port: u16,
    helper_port: std::sync::atomic::AtomicU16,
    /// The certificate page's own server on loopback.
    page_backend: SocketAddr,
    /// The home address in use (`None`: not on a home network).
    address: Mutex<Option<Ipv4Addr>>,
    pub(crate) machine: Arc<dyn Machine>,
    pub(crate) tls: Arc<rustls::ServerConfig>,
    pub(crate) resolver: Arc<ca::Resolver>,
    pub(crate) gate: Arc<relay::Gate>,
    pub(crate) stopping: Arc<AtomicBool>,
    pub(crate) names: Arc<names::Names>,
}

fn normalise_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        })
        .collect()
}

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Eight characters, 40 random bits, with no letters that look like digits.
fn new_code() -> StoreResult<String> {
    let r = util::random::<8>()?;
    Ok(r.iter()
        .filter_map(|b| CROCKFORD.get(usize::from(*b) % 32))
        .map(|c| char::from(*c))
        .collect())
}

/// A code as people read it: `ABCD-EFGH`.
fn shown(code: &str) -> String {
    match (code.get(..4), code.get(4..)) {
        (Some(a), Some(b)) => format!("{a}-{b}"),
        _ => code.to_string(),
    }
}

/// A name people gave (a member, a phone): trimmed, 1 to 64 characters, no control
/// characters.
pub(crate) fn clean_name(name: &str, what: &str) -> Result<String, Refusal> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > 64 || n.chars().any(char::is_control) {
        return Err(Refusal::new(
            400,
            "bad_name",
            format!("Give {what} a name of up to 64 characters."),
        ));
    }
    Ok(n.to_string())
}

/// Pairing a phone for an app that asks for the household PIN, while there is none. Since
/// stage 8 every secured household has a PIN; this is met when an open household (Revision
/// 2 B) still has an app that asks for one, as a hub upgraded from stage 7 may.
fn pin_not_set() -> Refusal {
    Refusal::new(
        409,
        "pin_not_set",
        "This app's phones pair with the household PIN, and there is none yet. Set a password and PIN for the household on the hub computer first.",
    )
}

fn wrong() -> Refusal {
    Refusal::new(
        403,
        "wrong_code",
        "That code or PIN isn't right, or the code has expired. Make a new code on the hub computer.",
    )
}

#[derive(Debug, Deserialize)]
struct PairRequest {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    pin: Option<String>,
    #[serde(default)]
    device: Option<String>,
    #[serde(default)]
    invite: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

/// What registering an app needs (the spec's table).
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Registration {
    pub id: String,
    pub title: String,
    pub version: String,
    pub protocol: u32,
    pub public_port: u16,
    pub loopback_port: u16,
    #[serde(default)]
    pub money: bool,
    #[serde(default)]
    pub guests: bool,
    /// How the app's phones pair (Revision 2 A): `code_and_pin` (left out) or `code`.
    #[serde(default)]
    pub pairing: Option<String>,
}

impl Hub {
    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        // A panic in one request must not stop the hub: the state is still consistent
        // (every change is one database statement or transaction).
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) fn now(&self) -> i64 {
        (self.clock)()
    }

    /// A log line: the method, the path without its query, and the status. Nothing else.
    pub(crate) fn log_request(&self, method: &str, path: &str, status: u16) {
        (self.log)(&format!("{method} {path} {status}"));
    }

    pub(crate) fn log(&self, line: &str) {
        (self.log)(line);
    }

    // ----- letting a request through --------------------------------------------------------------

    /// Who holds `token`, if they may use `app`: the device must be paired for this app and
    /// not revoked, and its member must hold a grant for the app now.
    pub(crate) fn authorise(&self, app: &str, token: &str) -> Result<Identity, Refusal> {
        let now = self.now();
        let st = self.lock();
        let Some(device) = st.registry.device_by_token(token).map_err(Refusal::inner)? else {
            return Err(Refusal::not_paired());
        };
        if device.app != app
            || !st
                .registry
                .has_grant(device.member, app)
                .map_err(Refusal::inner)?
        {
            return Err(Refusal::no_access());
        }
        let Some(member) = st.registry.member(device.member).map_err(Refusal::inner)? else {
            return Err(Refusal::not_paired());
        };
        if device.last_seen.is_none_or(|t| now - t >= TOUCH_EVERY_MS) {
            let _ = st.registry.touch(device.id, now);
        }
        Ok(Identity { member, device })
    }

    /// `/hub/unpair`: the calling device revokes itself (the person removed the app from
    /// this phone). It works without a grant; another device is never touched.
    pub(crate) fn unpair(&self, app: &str, token: &str) -> Result<(), Refusal> {
        let now = self.now();
        let st = self.lock();
        let Some(device) = st.registry.device_by_token(token).map_err(Refusal::inner)? else {
            return Err(Refusal::not_paired());
        };
        if device.app != app {
            return Err(Refusal::not_paired());
        }
        st.registry
            .revoke_device(device.id, now)
            .map_err(Refusal::inner)?;
        drop(st);
        self.log(&format!("device {} unpaired itself", device.id));
        Ok(())
    }

    /// Where an app's backend listens and the secret it shares with the hub. `None` when
    /// the app isn't registered (its port is closing).
    pub(crate) fn backend(&self, app: &str) -> Option<(App, Zeroizing<String>)> {
        let st = self.lock();
        let info = st.registry.app(app).ok().flatten()?;
        let secret = st.secrets.get(app)?.clone();
        Some((info, secret))
    }

    /// Give the app ports the hub name's certificate as it now stands (after a renewal,
    /// turning names on or off). Phones already connected keep their connection.
    pub(crate) fn refresh_name(&self) {
        let cert = self.names.serving();
        let set = self.resolver.set_named(cert.as_ref().map(|c| {
            (
                c.name.as_str(),
                c.chain.as_slice(),
                c.key.as_slice(),
                c.staging,
            )
        }));
        match set {
            Ok(true) if cert.is_some() => self.log("names: certificate in use on the app ports"),
            Ok(true) => self.log("names: app ports answer by address only"),
            Ok(false) => {}
            Err(e) => self.log(&format!("names: {e}")),
        }
    }

    /// The addresses that open `app` with a pairing code or invite in `fragment`
    /// (`pair=…` or `invite=…`): by the hub name when it has a real certificate, by address,
    /// and the certificate page for phones that connect by address.
    fn open_addresses(&self, app: &App, key: &str, code: &str) -> Value {
        let ip = self
            .address()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "(no home address)".into());
        let by_address = format!("https://{ip}:{}/#{key}={code}", app.public_port);
        let by_name = self
            .resolver
            .name()
            .filter(|n| self.resolver.trusted_name(Some(n)))
            .map(|n| format!("https://{n}:{}/#{key}={code}", app.public_port));
        json!({
            "url": by_name.clone().unwrap_or_else(|| by_address.clone()),
            "url_by_name": by_name,
            "url_by_address": by_address,
            "certificate_page": format!(
                "http://{ip}:{}/?app={}&{key}={code}",
                self.helper_port(),
                app.id
            ),
        })
    }

    // ----- pairing --------------------------------------------------------------------------------

    /// Drop old failures; refuse when this address, or everyone together, has failed too
    /// often in the last ten minutes.
    fn throttle(st: &mut State, now: i64, ip: IpAddr) -> Result<(), Refusal> {
        while st
            .failures
            .front()
            .is_some_and(|(t, _)| now - *t > FAILURE_WINDOW_MS)
        {
            st.failures.pop_front();
        }
        let mine = st.failures.iter().filter(|(_, a)| *a == ip).count();
        if mine >= MAX_FAILURES || st.failures.len() >= MAX_FAILURES_ALL {
            return Err(Refusal::new(
                429,
                "pairing_paused",
                "Too many wrong tries: pairing is paused for 10 minutes.",
            ));
        }
        Ok(())
    }

    /// `/hub/pair` on `app`'s port: a household member's code, PIN and device name, or a
    /// guest's invite and name. Answers with the new device's token.
    pub(crate) fn pair(&self, app: &str, body: &[u8], ip: IpAddr) -> Result<Value, Refusal> {
        let p: PairRequest = serde_json::from_slice(body)
            .map_err(|_| Refusal::new(400, "bad_request", "The request isn't valid."))?;
        if let Some(invite) = &p.invite {
            return self.pair_guest(app, invite, p.name.as_deref().unwrap_or(""), ip);
        }
        let device_name = clean_name(p.device.as_deref().unwrap_or(""), "this phone")?;
        let code = normalise_code(p.code.as_deref().unwrap_or(""));
        let now = self.now();
        // `None`: this app's phones pair with the code alone (Revision 2 A). A `pin` in the
        // body is then ignored and never checked.
        let pin_hash = {
            let mut st = self.lock();
            Self::throttle(&mut st, now, ip)?;
            let by_code = st
                .registry
                .app(app)
                .map_err(Refusal::inner)?
                .is_some_and(|a| a.pairs_by_code_alone());
            let pin_hash = if by_code {
                None
            } else {
                let Some(h) = st.registry.get(PIN_KEY).map_err(Refusal::inner)? else {
                    return Err(pin_not_set());
                };
                Some(h)
            };
            // the code must be for this app's port
            let valid = st
                .codes
                .get(&code)
                .is_some_and(|c| c.expires > now && c.app == app);
            if !valid {
                st.failures.push_back((now, ip));
                return Err(wrong());
            }
            pin_hash
        };
        // Slow on purpose (Argon2id); the hub stays responsive meanwhile.
        let pin_ok = pin_hash
            .as_deref()
            .is_none_or(|h| pin::verify(p.pin.as_deref().unwrap_or("").trim(), h));
        let mut st = self.lock();
        if !pin_ok {
            st.failures.push_back((now, ip));
            let burn = match st.codes.get_mut(&code) {
                Some(c) => {
                    c.tries += 1;
                    c.tries >= CODE_TRIES
                }
                None => false,
            };
            if burn {
                st.codes.remove(&code);
            }
            return Err(wrong());
        }
        // one use: the code is gone whatever happens next
        let Some(pairing) = st.codes.remove(&code).filter(|c| c.app == app) else {
            return Err(wrong());
        };
        let member = st.registry.member(pairing.member).map_err(Refusal::inner)?;
        let granted = st
            .registry
            .has_grant(pairing.member, app)
            .map_err(Refusal::inner)?;
        let Some(member) = member.filter(|_| granted) else {
            return Err(Refusal::no_access());
        };
        let token = Zeroizing::new(util::hex(&util::random::<32>().map_err(Refusal::inner)?));
        let device_id = st
            .registry
            .add_device(&token, member.id, app, &device_name, now)
            .map_err(Refusal::inner)?;
        drop(st);
        self.log(&format!("device {device_id} paired"));
        Ok(json!({
            "token": token.as_str(),
            "device_id": device_id,
            "member": household::shown(&member),
            "app": app,
        }))
    }

    fn pair_guest(
        &self,
        app: &str,
        invite: &str,
        name: &str,
        ip: IpAddr,
    ) -> Result<Value, Refusal> {
        let name = clean_name(name, "yourself")?;
        let code = normalise_code(invite);
        let now = self.now();
        let mut st = self.lock();
        Self::throttle(&mut st, now, ip)?;
        let found = st.registry.invite_by_code(&code).map_err(Refusal::inner)?;
        let accepts = st
            .registry
            .app(app)
            .map_err(Refusal::inner)?
            .is_some_and(|a| a.guests);
        let Some(invite) = found.filter(|i| accepts && i.app == app && i.expires > now) else {
            st.failures.push_back((now, ip));
            return Err(wrong());
        };
        let token = Zeroizing::new(util::hex(&util::random::<32>().map_err(Refusal::inner)?));
        let Some((member, device_id)) = st
            .registry
            .pair_guest(&invite, &name, &token, now)
            .map_err(Refusal::inner)?
        else {
            return Err(wrong());
        };
        drop(st);
        self.log(&format!("device {device_id} paired (guest)"));
        Ok(json!({
            "token": token.as_str(),
            "device_id": device_id,
            "member": { "id": member, "name": name, "class": crate::registry::GUEST },
            "app": app,
            "guest_scope": invite.scope,
        }))
    }

    /// Set or change the household PIN (an administrator's act: the old PIN is not
    /// needed).
    pub(crate) fn set_pin(&self, new: &str) -> Result<(), Refusal> {
        // (an open household gets its PIN with `secure`, with an administrator's password)
        if self.is_open()? {
            return Err(household::household_not_secured());
        }
        let new = new.trim();
        pin::check(new).map_err(|e| Refusal::new(400, "bad_pin", e))?;
        let hash = pin::hash_with(new, self.pin_cost).map_err(Refusal::inner)?;
        self.lock()
            .registry
            .set(PIN_KEY, &hash)
            .map_err(Refusal::inner)
    }

    /// The registered app `id`, and the household member `member` (not a guest).
    fn app_and_member(&self, app: &str, member: u32) -> Result<(App, Member), Refusal> {
        let st = self.lock();
        let Some(a) = st.registry.app(app).map_err(Refusal::inner)? else {
            return Err(Refusal::new(
                404,
                "no_such_app",
                "That app isn't registered.",
            ));
        };
        let m = st.registry.member(member).map_err(Refusal::inner)?;
        let Some(m) = m.filter(|m| m.guest_app.is_none()) else {
            return Err(Refusal::new(
                404,
                "no_such_member",
                "That person isn't in the household's list.",
            ));
        };
        Ok((a, m))
    }

    /// Let a member use an app (an administrator's act; no PIN is asked, money or not).
    pub(crate) fn give_grant(&self, member: u32, app: &str) -> Result<(), Refusal> {
        self.app_and_member(app, member)?;
        let now = self.now();
        self.lock()
            .registry
            .give_grant(member, app, now)
            .map_err(Refusal::inner)
    }

    /// A pairing code for a member and an app. Without a grant one is made first.
    pub(crate) fn make_code(&self, member: u32, app: &str) -> Result<Value, Refusal> {
        let (a, _) = self.app_and_member(app, member)?;
        let (has_pin, granted) = {
            let st = self.lock();
            (
                st.registry.get(PIN_KEY).map_err(Refusal::inner)?.is_some(),
                st.registry.has_grant(member, app).map_err(Refusal::inner)?,
            )
        };
        // (an app that pairs by code alone needs no PIN: Revision 2 A)
        if !has_pin && !a.pairs_by_code_alone() {
            return Err(pin_not_set());
        }
        if !granted {
            self.give_grant(member, app)?;
        }
        let code = new_code().map_err(Refusal::inner)?;
        let now = self.now();
        let expires = now + i64::from(self.cfg.pair.code_minutes.max(1)) * 60_000;
        let mut st = self.lock();
        st.codes.retain(|_, c| c.expires > now);
        st.codes.insert(
            code.clone(),
            Pairing {
                app: app.to_string(),
                member,
                expires,
                tries: 0,
            },
        );
        let mut v = self.open_addresses(&a, "pair", &shown(&code));
        v["code"] = json!(shown(&code));
        v["expires"] = json!(expires);
        Ok(v)
    }

    /// Cancel a pairing code. `false` when there is no such code.
    pub(crate) fn cancel_code(&self, code: &str) -> bool {
        self.lock().codes.remove(&normalise_code(code)).is_some()
    }

    /// A guest invite for an app that accepts guests, for one scope (the app's own text).
    pub(crate) fn make_invite(&self, app: &str, scope: &str) -> Result<Value, Refusal> {
        // The scope travels in a header (`Keep-Guest-Scope`) exactly as given.
        if scope.is_empty() || scope.len() > 200 || !scope.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(Refusal::new(
                400,
                "bad_scope",
                "An invite's scope is 1 to 200 letters, digits or signs, without spaces.",
            ));
        }
        let code = new_code().map_err(Refusal::inner)?;
        let now = self.now();
        let expires = now + i64::from(self.cfg.guest.invite_days.max(1)) * 86_400_000;
        let st = self.lock();
        let Some(a) = st.registry.app(app).map_err(Refusal::inner)? else {
            return Err(Refusal::new(
                404,
                "no_such_app",
                "That app isn't registered.",
            ));
        };
        if !a.guests {
            return Err(Refusal::new(
                409,
                "no_guests",
                format!("{} doesn't accept guests.", a.title),
            ));
        }
        let id = st
            .registry
            .add_invite(&code, app, scope, now, expires)
            .map_err(Refusal::inner)?;
        drop(st);
        let mut v = self.open_addresses(&a, "invite", &shown(&code));
        v["id"] = json!(id);
        v["code"] = json!(shown(&code));
        v["expires"] = json!(expires);
        Ok(v)
    }

    // ----- apps and their ports -------------------------------------------------------------------

    /// The home address in use.
    pub(crate) fn address(&self) -> Option<Ipv4Addr> {
        *self.address.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The certificate page's port (its address is [`Hub::address`]).
    pub(crate) fn helper_port(&self) -> u16 {
        self.helper_port.load(Ordering::SeqCst)
    }

    /// Open `app`'s public port on the home address.
    fn open_port(self: &Arc<Self>, app: &str, port: u16) -> StoreResult<Listener> {
        let ip = self
            .address()
            .ok_or("This computer isn't on a home network, so no port is opened.")?;
        let listener = TcpListener::bind((ip, port)).map_err(|e| {
            format!("Port {port} can't be opened on {ip}: {e}. Is another program using it?")
        })?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (hub, app, stop) = (self.clone(), app.to_string(), stop.clone());
            spawn(&format!("hub-{app}"), move || {
                relay::accept_loop(listener, hub, app, stop)
            })?
        };
        Ok(Listener {
            stop,
            thread: Some(thread),
            addr,
        })
    }

    /// Where `app`'s public port is open.
    pub(crate) fn port_of(&self, app: &str) -> Option<SocketAddr> {
        self.lock().listeners.get(app).map(|l| l.addr)
    }

    /// Register an app: its desktop program does so the first time phones are turned on in
    /// it, and again whenever its version changes. Its port is opened at once and a new
    /// shared secret is made, which the answer carries.
    ///
    /// `administrator`: whether the request carried an administrator's live session. The
    /// first registration of an app needs one; registering it again (an update) doesn't.
    pub(crate) fn register(
        self: &Arc<Self>,
        r: &Registration,
        administrator: bool,
    ) -> Result<Value, Refusal> {
        let bad = |m: String| Refusal::new(400, "bad_registration", m);
        let id_ok = r.id.len() <= 32
            && r.id.starts_with(|c: char| c.is_ascii_lowercase())
            && r.id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !id_ok {
            return Err(bad(format!(
                "\"{}\" isn't an app id: use up to 32 lower-case letters, digits and dashes, starting with a letter.",
                r.id
            )));
        }
        let title = clean_name(&r.title, "the app").map_err(|e| bad(e.message))?;
        let version = r.version.trim().to_string();
        if version.is_empty()
            || version.len() > 32
            || !version.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(bad("The app's version is missing or too long.".into()));
        }
        if !PROTOCOLS.contains(&r.protocol) {
            return Err(Refusal::new(
                409,
                "unknown_protocol",
                format!(
                    "{title} was built for hub protocol {}, which this Keep Hub ({VERSION}) doesn't know. Update Keep Hub.",
                    r.protocol
                ),
            ));
        }
        if r.money && r.guests {
            return Err(Refusal::new(
                409,
                "money_with_guests",
                format!("{title} holds financial records, so it can't accept guests."),
            ));
        }
        let own = [
            self.cfg.ports.helper,
            self.cfg.ports.admin,
            self.admin_port,
            self.helper_port(),
        ];
        for (port, what) in [(r.public_port, "public"), (r.loopback_port, "loopback")] {
            if port < 1024 || own.contains(&port) {
                return Err(bad(format!(
                    "{title} can't use {port} as its {what} port: it is the hub's own or below 1024."
                )));
            }
        }
        let pairing = match r.pairing.as_deref().map(str::trim) {
            None => CODE_AND_PIN,
            Some(CODE_AND_PIN) => CODE_AND_PIN,
            Some(CODE) => CODE,
            Some(_) => {
                return Err(bad(format!(
                    "{title} asked to pair its phones in a way this Keep Hub doesn't know: use \"{CODE_AND_PIN}\" or \"{CODE}\"."
                )))
            }
        };
        if r.public_port == r.loopback_port {
            return Err(bad(format!(
                "{title} needs two different ports: one for phones and one for its own backend."
            )));
        }

        let _one = self.changing_apps.lock().unwrap_or_else(|p| p.into_inner());
        let now = self.now();
        let existing = {
            let st = self.lock();
            let apps = st.registry.apps().map_err(Refusal::inner)?;
            for other in apps.iter().filter(|a| a.id != r.id) {
                for port in [r.public_port, r.loopback_port] {
                    if port == other.public_port || port == other.loopback_port {
                        return Err(Refusal::new(
                            409,
                            "port_taken",
                            format!("Port {port} is already used by {}.", other.title),
                        ));
                    }
                }
            }
            apps.into_iter().find(|a| a.id == r.id)
        };
        // A new app, or a change of how its phones pair, needs what a first registration
        // needs (Revision 2 A); an update that keeps its pairing needs the token alone.
        let first_time = existing.as_ref().is_none_or(|a| a.pairing != pairing);
        if first_time && !administrator {
            return Err(household::administrator_needed());
        }
        // An app that pairs with the PIN needs a household that has one (Revision 2 B).
        if first_time && pairing == CODE_AND_PIN && self.is_open()? {
            return Err(household::household_not_secured());
        }
        // the port: kept when it's already this app's, opened otherwise (before the old one
        // closes, so a failure leaves the app as it was). Away from a home network nothing
        // is open: the port opens when an address comes.
        let open_at = self.port_of(&r.id).map(|a| a.port());
        let opened = if open_at == Some(r.public_port) || self.address().is_none() {
            None
        } else {
            Some(
                self.open_port(&r.id, r.public_port)
                    .map_err(|e| Refusal::new(409, "port_unavailable", e))?,
            )
        };
        let app = App {
            id: r.id.clone(),
            title,
            version,
            protocol: r.protocol,
            public_port: r.public_port,
            loopback_port: r.loopback_port,
            money: r.money,
            guests: r.guests,
            registered: existing.as_ref().map_or(now, |a| a.registered),
            pairing: pairing.to_string(),
        };
        let stored = (|| -> StoreResult<Zeroizing<String>> {
            let secret = Zeroizing::new(util::hex(&util::random::<32>()?));
            self.keys.set(&secret_key(&r.id), secret.as_bytes())?;
            self.lock().registry.put_app(&app)?;
            Ok(secret)
        })();
        let secret = match stored {
            Ok(s) => s,
            Err(e) => {
                if let Some(l) = opened {
                    l.close();
                }
                return Err(Refusal::inner(e));
            }
        };
        let old = {
            let mut st = self.lock();
            st.secrets.insert(r.id.clone(), secret.clone());
            match opened {
                Some(l) => st.listeners.insert(r.id.clone(), l),
                None => None,
            }
        };
        if let Some(l) = old {
            l.close();
        }
        self.log(&format!("app {} registered", r.id));
        Ok(json!({
            "id": r.id,
            "secret": secret.as_str(),
            "protocol": r.protocol,
            "hub_version": VERSION,
            "pairing": pairing,
        }))
    }

    /// Unregister an app: its port closes and its devices are revoked.
    pub(crate) fn unregister(&self, id: &str) -> Result<(), Refusal> {
        let _one = self.changing_apps.lock().unwrap_or_else(|p| p.into_inner());
        let now = self.now();
        let (found, listener) = {
            let mut st = self.lock();
            let found = st.registry.remove_app(id, now).map_err(Refusal::inner)?;
            st.secrets.remove(id);
            st.codes.retain(|_, c| c.app != id);
            (found, st.listeners.remove(id))
        };
        if let Some(l) = listener {
            l.close();
        }
        if !found {
            return Err(Refusal::new(
                404,
                "no_such_app",
                "That app isn't registered.",
            ));
        }
        let _ = self.keys.delete(&secret_key(id));
        self.log(&format!("app {id} unregistered"));
        Ok(())
    }

    /// Each app with its state: `running`, `app_stopped` (its backend doesn't answer),
    /// `port_closed` (the hub couldn't open its port) or `not_registered_fully` (its shared
    /// secret is missing: the app must register again).
    pub(crate) fn status(&self) -> Result<Value, Refusal> {
        let (apps, open, with_secret): (Vec<App>, Vec<String>, Vec<String>) = {
            let st = self.lock();
            (
                st.registry.apps().map_err(Refusal::inner)?,
                st.listeners.keys().cloned().collect(),
                st.secrets.keys().cloned().collect(),
            )
        };
        let apps: Vec<Value> = apps
            .iter()
            .map(|a| {
                let state = if !with_secret.contains(&a.id) {
                    "not_registered_fully"
                } else if !open.contains(&a.id) {
                    "port_closed"
                } else if std::net::TcpStream::connect_timeout(
                    &SocketAddr::from((Ipv4Addr::LOCALHOST, a.loopback_port)),
                    Duration::from_millis(300),
                )
                .is_ok()
                {
                    "running"
                } else {
                    "app_stopped"
                };
                json!({ "app": a, "state": state })
            })
            .collect();
        let names = self.names.status();
        Ok(json!({
            "hub": "keep-hub",
            "version": VERSION,
            "protocols": PROTOCOLS,
            "address": self.address(),
            "names": names["state"],
            "code_page": names["code_page"],
            "code_needed": names["code_needed"],
            "household": if self.is_open()? { "open" } else { "secured" },
            "apps": apps,
        }))
    }
}

// ----- the home address ------------------------------------------------------------------------

impl Hub {
    /// Open the certificate page's front on the home address.
    fn open_page(self: &Arc<Self>) -> StoreResult<Listener> {
        let ip = self
            .address()
            .ok_or("This computer isn't on a home network, so the certificate page isn't open.")?;
        let port = self.helper_port();
        let listener = TcpListener::bind((ip, port)).map_err(|e| {
            format!("the hub can't listen on {ip}:{port}: {e}. Is another program using that port?")
        })?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        self.helper_port.store(addr.port(), Ordering::SeqCst);
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (backend, stop, stopping) =
                (self.page_backend, stop.clone(), self.stopping.clone());
            spawn("hub-page-front", move || {
                page::front(listener, backend, stop, stopping)
            })?
        };
        Ok(Listener {
            stop,
            thread: Some(thread),
            addr,
        })
    }

    /// Open every registered app's port and the certificate page on the home address. A
    /// port that can't be opened is logged and left closed: the others keep working.
    fn open_all(self: &Arc<Self>) {
        let apps = self.lock().registry.apps().unwrap_or_default();
        for a in &apps {
            if !self.lock().secrets.contains_key(&a.id) {
                continue;
            }
            match self.open_port(&a.id, a.public_port) {
                Ok(l) => {
                    if let Some(old) = self.lock().listeners.insert(a.id.clone(), l) {
                        old.close();
                    }
                }
                Err(e) => self.log(&e),
            }
        }
        match self.open_page() {
            Ok(l) => {
                if let Some(old) = self.lock().page.replace(l) {
                    old.close();
                }
            }
            Err(e) => self.log(&e),
        }
    }

    /// Close every app port and the certificate page.
    fn close_all(&self) {
        let (ports, page) = {
            let mut st = self.lock();
            (
                st.listeners.drain().map(|(_, l)| l).collect::<Vec<_>>(),
                st.page.take(),
            )
        };
        for l in ports.into_iter().chain(page) {
            l.close();
        }
    }

    /// The home address now: the default route's, or the chosen adapter's (looked up
    /// only when `full`).
    fn find_address(&self, full: bool) -> Option<Ipv4Addr> {
        let cfg = HubConfig::load(&self.data).unwrap_or_else(|_| self.cfg.clone());
        if cfg.address.automatic() {
            return self.machine.default_address();
        }
        if !full {
            return self.address();
        }
        machine::choose(&cfg.address.adapter, None, || self.machine.addresses())
    }

    /// Follow a change of the home address: a new authority for phones that connect by
    /// address (the spec: they install it again), every port and the page on the new
    /// address, the address in `hub.json`, and the name service told (through the names
    /// engine). Phones that use the name are unaffected.
    pub(crate) fn move_to(self: &Arc<Self>, new: Option<Ipv4Addr>) {
        let _one = self.changing_apps.lock().unwrap_or_else(|p| p.into_inner());
        let old = self.address();
        if old == new {
            return;
        }
        match new {
            Some(ip) => {
                match ca::ensure(
                    &self.data,
                    &self.keys,
                    &ca::Target { ip },
                    &ca::computer_name(),
                    self.now() / 1000,
                ) {
                    Ok(m) => {
                        let _ = self.resolver.set(&m);
                        if m.ca_created {
                            self.log("address changed: a new certificate for phones that connect by address");
                        }
                    }
                    Err(e) => self.log(&e),
                }
                *self.address.lock().unwrap_or_else(|p| p.into_inner()) = Some(ip);
                self.close_all();
                self.open_all();
                self.log("address changed: ports opened on the new address");
            }
            None => {
                *self.address.lock().unwrap_or_else(|p| p.into_inner()) = None;
                self.close_all();
                self.log("address lost: not on a home network");
            }
        }
        if let Ok(mut cfg) = HubConfig::load(&self.data) {
            cfg.address.current = new;
            if let Err(e) = cfg.save(&self.data) {
                self.log(&e);
            }
        }
        self.names.set_address(new);
    }

    /// Choose the adapter whose address to publish (`automatic`, or an adapter's name), and
    /// look again at once.
    pub(crate) fn choose_adapter(self: &Arc<Self>, adapter: &str) -> Result<(), String> {
        let a = adapter.trim();
        if a.is_empty() || a.len() > 64 || a.chars().any(char::is_control) {
            return Err("Give an adapter's name, or \"automatic\".".into());
        }
        let mut cfg = HubConfig::load(&self.data)?;
        cfg.address.adapter = a.to_string();
        cfg.save(&self.data)?;
        let found = self.find_address(true);
        self.move_to(found);
        Ok(())
    }
}

/// A running hub.
pub struct Running {
    /// The admin address (this computer only).
    pub admin: SocketAddr,
    hub: Arc<Hub>,
    threads: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for Running {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Running")
            .field("admin", &self.admin)
            .finish_non_exhaustive()
    }
}

impl Running {
    /// Where a registered app's public port is open.
    pub fn app_port(&self, app: &str) -> Option<SocketAddr> {
        self.hub.port_of(app)
    }

    /// The home address in use.
    pub fn address(&self) -> Option<Ipv4Addr> {
        self.hub.address()
    }

    /// The certificate page (plain HTTP on the home network), when open.
    pub fn helper(&self) -> Option<SocketAddr> {
        self.hub.lock().page.as_ref().map(|l| l.addr)
    }

    /// The hub's own certificate authority: its public facts.
    pub fn info(&self) -> ca::Info {
        ca::read_info(&self.hub.data).unwrap_or_default()
    }

    /// The hub's own certificate authority's certificate (DER).
    pub fn ca_der(&self) -> Vec<u8> {
        std::fs::read_to_string(self.hub.data.join(ca::CA_CERT_FILE))
            .ok()
            .and_then(|t| ca::from_pem(&t))
            .unwrap_or_default()
    }

    /// Stop every listener and wait for them.
    pub fn stop(mut self) {
        self.hub.stopping.store(true, Ordering::SeqCst);
        self.hub.names.poke();
        self.hub.close_all();
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }

    /// Run until the process ends.
    pub fn wait(mut self) {
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

fn spawn(name: &str, f: impl FnOnce() + Send + 'static) -> StoreResult<JoinHandle<()>> {
    std::thread::Builder::new()
        .name(name.into())
        .spawn(f)
        .map_err(|e| format!("the hub can't start a thread: {e}"))
}

/// Start the hub set up in `opts.data`: the admin address, the certificate page and the
/// port of every app registered so far, on the home address it finds. A hub installed
/// alone, with no app registered, listens on the admin address and the certificate page
/// only. A hub not on a home network listens on the admin address only, and opens the
/// rest when an address appears.
pub fn start(opts: HubOptions) -> StoreResult<Running> {
    let cfg = HubConfig::load(&opts.data)?;
    let now = (opts.clock)();
    let machine: Arc<dyn Machine> = opts
        .machine
        .clone()
        .unwrap_or_else(|| Arc::new(machine::System));

    // the home address now, and the authority for it
    let home = if cfg.address.automatic() {
        machine.default_address()
    } else {
        machine::choose(&cfg.address.adapter, None, || machine.addresses())
    };
    let made_for: Option<Ipv4Addr> = ca::read_info(&opts.data).and_then(|i| i.address.parse().ok());
    let material = match (home, made_for) {
        // moved while the hub was stopped: a new authority for the new address
        (Some(ip), Some(was)) if ip != was => ca::ensure(
            &opts.data,
            &opts.keys,
            &ca::Target { ip },
            &ca::computer_name(),
            now / 1000,
        )?,
        (_, Some(was)) => {
            ca::ensure_existing(&opts.data, &opts.keys, &ca::Target { ip: was }, now / 1000)?
        }
        (Some(ip), None) => ca::ensure(
            &opts.data,
            &opts.keys,
            &ca::Target { ip },
            &ca::computer_name(),
            now / 1000,
        )?,
        (None, None) => return Err(format!("{} (the certificate's address)", ca::DAMAGED)),
    };
    if home != cfg.address.current {
        let mut c = cfg.clone();
        c.address.current = home;
        c.save(&opts.data)?;
    }
    let resolver = Arc::new(ca::Resolver::new(&material)?);
    let tls = ca::server_config(resolver.clone())?;
    let registry = Registry::open(&opts.data)?;
    let apps = registry.apps()?;
    let admin_token = admin_token(&opts.data)?;

    let admin_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, cfg.ports.admin));
    let admin_server = Server::http(admin_addr).map_err(|e| {
        format!("the hub can't listen on {admin_addr}: {e}. Is another program using that port?")
    })?;
    let admin_addr = admin_server
        .server_addr()
        .to_ip()
        .ok_or_else(|| "the hub's admin listener has no address".to_string())?;
    let admin_server = Arc::new(admin_server);

    // the certificate page: its own server on loopback, behind a front with limits
    let page_server = Server::http(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .map_err(|e| format!("the hub can't start its certificate page: {e}"))?;
    let page_backend = page_server
        .server_addr()
        .to_ip()
        .ok_or_else(|| "the certificate page has no address".to_string())?;
    let page_server = Arc::new(page_server);

    let outside = match opts.outside {
        Some(o) => o,
        None => names::Outside::system().unwrap_or_else(|e| {
            (opts.log)(&format!("names: {e}"));
            names::Outside::unavailable(&e)
        }),
    };
    let names = Arc::new(names::Names::open(
        &opts.data,
        &cfg,
        opts.keys.clone(),
        outside,
        opts.clock.clone(),
        opts.log.clone(),
    ));
    names.set_address(home);

    let mut secrets = HashMap::new();
    for a in &apps {
        match opts.keys.get(&secret_key(&a.id)) {
            Ok(Some(s)) => {
                let text = String::from_utf8_lossy(&s).into_owned();
                secrets.insert(a.id.clone(), Zeroizing::new(text));
            }
            Ok(None) => (opts.log)(&format!("app {}: its shared secret is missing", a.id)),
            Err(e) => (opts.log)(&format!("app {}: {e}", a.id)),
        }
    }

    let hub = Arc::new(Hub {
        state: Mutex::new(State {
            registry,
            codes: HashMap::new(),
            failures: VecDeque::new(),
            secrets,
            listeners: HashMap::new(),
            page: None,
            problems: None,
            sessions: HashMap::new(),
            sign_ins: HashMap::new(),
        }),
        changing_apps: Mutex::new(()),
        data: opts.data.clone(),
        helper_port: std::sync::atomic::AtomicU16::new(cfg.ports.helper),
        cfg,
        keys: opts.keys,
        clock: opts.clock,
        log: opts.log,
        pin_cost: opts.pin_cost,
        idle: opts.idle,
        first_byte: opts.first_byte,
        admin_token,
        admin_port: admin_addr.port(),
        page_backend,
        address: Mutex::new(home),
        machine,
        tls,
        resolver,
        gate: relay::Gate::new(),
        stopping: Arc::new(AtomicBool::new(false)),
        names,
    });

    if home.is_some() {
        // the certificate page must open (its port is the hub's own); app ports may fail
        let page = hub.open_page()?;
        hub.lock().page = Some(page);
        let apps = hub.lock().registry.apps().unwrap_or_default();
        for a in &apps {
            if !hub.lock().secrets.contains_key(&a.id) {
                continue;
            }
            match hub.open_port(&a.id, a.public_port) {
                Ok(l) => {
                    hub.lock().listeners.insert(a.id.clone(), l);
                }
                Err(e) => hub.log(&e),
            }
        }
    } else {
        hub.log("not on a home network: phones can't connect until there is a home address");
    }

    hub.refresh_name();
    let mut threads = Vec::new();
    for i in 0..2 {
        let (server, hub) = (page_server.clone(), hub.clone());
        threads.push(spawn(&format!("hub-page-{i}"), move || {
            while !hub.stopping.load(Ordering::SeqCst) {
                match server.recv_timeout(Duration::from_millis(200)) {
                    Ok(Some(req)) => page::handle(&hub, req),
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
        })?);
    }
    for i in 0..ADMIN_WORKERS {
        let (server, hub) = (admin_server.clone(), hub.clone());
        threads.push(spawn(&format!("hub-admin-{i}"), move || {
            while !hub.stopping.load(Ordering::SeqCst) {
                match server.recv_timeout(Duration::from_millis(200)) {
                    Ok(Some(req)) => admin::handle(&hub, req),
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
        })?);
    }
    {
        // The hub name: whatever is due, when the admin address asks and every minute.
        let hub = hub.clone();
        threads.push(spawn("hub-names", move || {
            while !hub.stopping.load(Ordering::SeqCst) {
                hub.names.run_once();
                hub.refresh_name();
                hub.names.wait_for_work(Duration::from_secs(60));
            }
        })?);
    }
    {
        // The home address: the default route every `address_poll`, the chosen adapter
        // every `address.check_minutes`.
        let (hub, poll) = (hub.clone(), opts.address_poll);
        threads.push(spawn("hub-address", move || {
            let mut last_full = hub.now();
            while !hub.stopping.load(Ordering::SeqCst) {
                let until = std::time::Instant::now() + poll;
                while std::time::Instant::now() < until && !hub.stopping.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(50).min(poll));
                }
                let minutes = HubConfig::load(&hub.data)
                    .map(|c| c.address.check_minutes)
                    .unwrap_or(crate::config::CHECK_MINUTES);
                let full = hub.now() - last_full >= i64::from(minutes.max(1)) * 60_000;
                if full {
                    last_full = hub.now();
                }
                let found = hub.find_address(full);
                if found != hub.address() {
                    hub.move_to(found);
                }
            }
        })?);
    }
    {
        // Renew the hub's own server certificate when it's due (hourly check), without
        // dropping phones.
        let hub = hub.clone();
        threads.push(spawn("hub-upkeep", move || {
            let mut last_check = hub.now();
            while !hub.stopping.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(200));
                let now = hub.now();
                if now - last_check >= 3_600_000 {
                    last_check = now;
                    let Some(ip) = hub.address() else { continue };
                    match ca::ensure_existing(&hub.data, &hub.keys, &ca::Target { ip }, now / 1000)
                    {
                        Ok(m) if m.renewed => {
                            let _ = hub.resolver.set(&m);
                            hub.log("certificate renewed");
                        }
                        Ok(_) => {}
                        Err(e) => hub.log(&e),
                    }
                }
            }
        })?);
    }
    Ok(Running {
        admin: admin_addr,
        hub,
        threads,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_typed_forgivingly() {
        assert_eq!(normalise_code(" abcd-efgh "), "ABCDEFGH");
        assert_eq!(normalise_code("o0il-1Lxy"), "001111XY");
        assert_eq!(shown("ABCDEFGH"), "ABCD-EFGH");
        for _ in 0..50 {
            let c = new_code().unwrap();
            assert_eq!(c.len(), 8);
            // what is shown comes back as what was made
            assert_eq!(normalise_code(&shown(&c)), c);
            assert!(!c.contains(['I', 'L', 'O', 'U']));
        }
    }

    #[test]
    fn names_are_trimmed_and_limited() {
        assert_eq!(clean_name("  Sam's phone ", "x").unwrap(), "Sam's phone");
        assert!(clean_name("   ", "x").is_err());
        assert!(clean_name(&"a".repeat(65), "x").is_err());
        assert!(clean_name("a\r\nKeep-Member: 1", "x").is_err());
        assert_eq!(
            clean_name(&"é".repeat(64), "x").unwrap().chars().count(),
            64
        );
    }
}
