//! The hub's name and its certificate (the spec's "The name and the certificate").
//!
//! States: **Off**, **Registering**, **Proving**, **Ready**, **Blocked** (the home router
//! refuses the name), **Waiting** (no internet, or a limit was reached).
//!
//! Turning names on: register with the name service (once, with a registration code), send
//! the home address, make a key, order a certificate for the one name, publish the DNS
//! proof, wait (at most 2 minutes) until a public resolver sees it, let Let's Encrypt check,
//! save the certificate, clear the proof. Then the self-test: the name looked up through
//! this computer's own resolver and through the public one.
//!
//! Renewal is checked once a day and starts when a third of the certificate's life remains
//! (from its own dates). A failed request is tried again the next day, or after the time
//! Let's Encrypt gives. The hub never sends more than 3 certificate requests for its name in
//! 7 days.
//!
//! Kept in the data folder: `names.json` (public facts: the id, the name, the account's URL,
//! when requests were sent), `hub-name.crt` (the certificate chain), and in the key store,
//! sealed, the name service's token, the account key and the certificate's key.
//!
//! The app ports serve the certificate to phones that ask for the hub name, beside the
//! hub's own ([`crate::ca::Resolver`], refreshed by the hub after every run). Finding a new
//! home address is stage 5; until then the address is the one in `hub.json`.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::acme::{self, Acme, AcmeError};
use crate::client::{Http, HttpsClient, Response};
use crate::config::{HubConfig, NamesSettings};
use crate::der;
use crate::dns::{Kind, Lookup, SystemLookup};
use crate::keys::KeyStore;
use crate::nameservice::{NameService, NAME_SERVICE};
use crate::util::{self, StoreResult};

pub const NAMES_FILE: &str = "names.json";
pub const NAME_CERT_FILE: &str = "hub-name.crt";
const TOKEN_KEY: &str = "name-token";
const ACCOUNT_KEY: &str = "acme-account";
const CERT_KEY: &str = "name-key";

const MINUTE: i64 = 60_000;
const DAY: i64 = 24 * 60 * MINUTE;
/// Certificate requests for the name in [`LIMIT_WINDOW`], at most (below Let's Encrypt's 5).
pub const MAX_REQUESTS: usize = 3;
pub const LIMIT_WINDOW: i64 = 7 * DAY;
/// How long the hub waits for a public resolver to see its proof.
const PROOF_WAIT: i64 = 2 * MINUTE;
/// How long the hub waits for Let's Encrypt to check, and to issue.
const ACME_WAIT: i64 = 2 * MINUTE;
const POLL: Duration = Duration::from_secs(5);
/// A failed address update is tried again after this.
const ADDRESS_RETRY: i64 = 15 * MINUTE;

/// The world outside this computer, as the names engine sees it. Tests use fakes.
#[derive(Clone)]
pub struct Outside {
    pub http: Arc<dyn Http>,
    pub lookup: Arc<dyn Lookup>,
    /// Wait between checks (a real sleep; tests move their clock instead).
    pub wait: Arc<dyn Fn(Duration) + Send + Sync>,
}

/// An outside that answers nothing, with a reason (no trust store, or tests).
struct Unavailable(String);

impl Http for Unavailable {
    fn send(
        &self,
        _: &str,
        _: &str,
        _: &[(&str, &str)],
        _: Option<&[u8]>,
    ) -> Result<Response, String> {
        Err(self.0.clone())
    }
}

impl Lookup for Unavailable {
    fn public(&self, _: &str, _: Kind) -> Result<Vec<String>, String> {
        Err(self.0.clone())
    }
    fn home(&self, _: &str) -> Result<Vec<Ipv4Addr>, String> {
        Err(self.0.clone())
    }
}

impl Outside {
    /// The real internet, trusting what this computer trusts.
    pub fn system() -> Result<Outside, String> {
        let http: Arc<dyn Http> = Arc::new(HttpsClient::system()?);
        Ok(Outside {
            lookup: Arc::new(SystemLookup::new(http.clone())),
            http,
            wait: Arc::new(std::thread::sleep),
        })
    }

    /// Nothing can be reached; every request fails with `why`.
    pub fn unavailable(why: &str) -> Outside {
        let u = Arc::new(Unavailable(why.to_string()));
        Outside {
            http: u.clone(),
            lookup: u,
            wait: Arc::new(|_| {}),
        }
    }
}

/// The states of the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NameState {
    Off,
    Registering,
    Proving,
    Ready,
    Blocked,
    Waiting,
}

/// What `names.json` holds: public facts only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
struct Saved {
    id: Option<String>,
    name: Option<String>,
    /// The name service the hub registered with (a name belongs to it).
    service: Option<String>,
    /// The ACME directory and account URL.
    acme: Option<String>,
    account_url: Option<String>,
    /// The address last accepted by the name service.
    address_sent: Option<String>,
    address_retry_at: i64,
    /// When certificate requests were sent (ms), the last 7 days.
    requests: Vec<i64>,
    /// The next daily check.
    next_check: i64,
    /// No certificate request before this (a failure, a limit).
    retry_at: i64,
    /// The certificate came from Let's Encrypt's staging service.
    cert_staging: bool,
}

/// The certificate in use: its name, chain (DER, leaf first), key (PKCS#8) and dates.
pub struct NameCert {
    pub name: String,
    pub chain: Vec<Vec<u8>>,
    pub key: Zeroizing<Vec<u8>>,
    pub info: der::CertInfo,
    pub staging: bool,
}

impl std::fmt::Debug for NameCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NameCert")
            .field("info", &self.info)
            .field("staging", &self.staging)
            .finish_non_exhaustive()
    }
}

struct Live {
    settings: NamesSettings,
    warn_days: u32,
    /// The home address (`None`: not on a home network).
    address: Option<Ipv4Addr>,
    state: NameState,
    message: Option<String>,
    blocked: bool,
    /// The self-test has run since the hub started.
    tested: bool,
    /// The registration code, until it is used (never stored or logged).
    code: Option<Zeroizing<String>>,
    force: bool,
    poked: bool,
    /// What an admin request asked of `names.json`, for the engine to write: it is the
    /// file's only writer, so a change can't be lost to another write at the same moment.
    asks: Asks,
}

/// Changes to `names.json` asked by the admin address, applied by the engine.
#[derive(Default)]
struct Asks {
    /// Try at once, whatever an earlier failure said (turning names on).
    retry_now: bool,
    /// Send the address again at once (a new address).
    address_now: bool,
    /// Send the address again even if the service has it ("Update the name").
    resend: bool,
}

pub struct Names {
    data: PathBuf,
    keys: KeyStore,
    outside: Outside,
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
    live: Mutex<Live>,
    wake: Condvar,
    /// One run at a time.
    running: Mutex<()>,
}

/// A step that failed: why, and not before when to try again (if the other side said).
struct Failed {
    message: String,
    retry_at: Option<i64>,
}

impl From<AcmeError> for Failed {
    fn from(e: AcmeError) -> Self {
        let retry_at = match &e {
            AcmeError::RateLimited {
                retry_after: Some(s),
                ..
            } => Some(
                i64::try_from(*s)
                    .unwrap_or(i64::MAX / 2)
                    .saturating_mul(1000),
            ),
            _ => None,
        };
        Failed {
            message: e.to_string(),
            retry_at,
        }
    }
}

fn fail(message: impl Into<String>) -> Failed {
    Failed {
        message: message.into(),
        retry_at: None,
    }
}

impl NamesSettings {
    /// The ACME directory to use: Let's Encrypt's staging service when `staging` is set and
    /// the directory is Let's Encrypt's.
    pub fn directory(&self) -> &str {
        if self.staging && self.acme == acme::LETS_ENCRYPT {
            acme::LETS_ENCRYPT_STAGING
        } else {
            &self.acme
        }
    }

    /// Why these settings can't be used, if they can't.
    pub fn problem(&self) -> Option<String> {
        if self.staging && self.service == NAME_SERVICE {
            return Some(
                "names.staging is on but names.service is the real name service: set names.service to the staging name service's address."
                    .into(),
            );
        }
        if !self.service.starts_with("https://") || !self.acme.starts_with("https://") {
            return Some("names.service and names.acme must be https:// addresses.".into());
        }
        None
    }
}

impl Names {
    pub fn open(
        data: &Path,
        cfg: &HubConfig,
        keys: KeyStore,
        outside: Outside,
        clock: Arc<dyn Fn() -> i64 + Send + Sync>,
        log: Arc<dyn Fn(&str) + Send + Sync>,
    ) -> Names {
        Names {
            data: data.to_path_buf(),
            keys,
            outside,
            clock,
            log,
            live: Mutex::new(Live {
                settings: cfg.names.clone(),
                warn_days: cfg.cert.warn_days,
                address: cfg.address.current,
                state: NameState::Off,
                message: None,
                blocked: false,
                tested: false,
                code: None,
                force: false,
                poked: true,
                asks: Asks::default(),
            }),
            wake: Condvar::new(),
            running: Mutex::new(()),
        }
    }

    fn live(&self) -> MutexGuard<'_, Live> {
        self.live.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn now(&self) -> i64 {
        (self.clock)()
    }

    fn load(&self) -> Saved {
        std::fs::read(self.data.join(NAMES_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save(&self, s: &Saved) -> StoreResult<()> {
        let b = serde_json::to_vec_pretty(s).map_err(|e| e.to_string())?;
        util::write_private(&self.data.join(NAMES_FILE), &b)
    }

    /// Write `names.enabled` to `hub.json`, keeping everything else in it.
    fn save_enabled(&self, enabled: bool) -> StoreResult<()> {
        HubConfig::update(&self.data, |c| c.names.enabled = enabled)
    }

    fn set(&self, state: NameState, message: Option<String>) {
        let mut l = self.live();
        l.state = state;
        l.message = message;
    }

    /// The hub's name, once registered with the name service in use.
    fn registration(&self, saved: &Saved, settings: &NamesSettings) -> Option<(String, String)> {
        match (&saved.id, &saved.name, &saved.service) {
            (Some(id), Some(name), Some(svc)) if *svc == settings.service => {
                Some((id.clone(), name.clone()))
            }
            _ => None,
        }
    }

    /// The certificate in use, when its key is there, it matches, it is for the name, and
    /// it comes from the service now chosen (staging or not).
    pub fn certificate(&self) -> Option<NameCert> {
        let saved = self.load();
        let staging = self.live().settings.staging;
        let name = saved.name.clone()?;
        if saved.cert_staging != staging {
            return None;
        }
        let pem = std::fs::read_to_string(self.data.join(NAME_CERT_FILE)).ok()?;
        let chain = der::pem_certificates(&pem);
        let info = der::cert_info(chain.first()?)?;
        let key = self.keys.get(CERT_KEY).ok().flatten()?;
        let pair = KeyPair::try_from(key.as_slice()).ok()?;
        if pair.subject_public_key_info() != info.spki || !info.dns_names.contains(&name) {
            return None;
        }
        Some(NameCert {
            name,
            chain,
            key,
            info,
            staging,
        })
    }

    // ----- the admin address ----------------------------------------------------------------------

    /// Turn names on. The first time (or with another name service) a registration code is
    /// needed. Work starts in the background at once.
    pub fn turn_on(&self, code: Option<&str>) -> Result<(), String> {
        let settings = self.live().settings.clone();
        if let Some(p) = settings.problem() {
            return Err(p);
        }
        let code = code.map(str::trim).filter(|c| !c.is_empty());
        let saved = self.load();
        if self.registration(&saved, &settings).is_none() && code.is_none() {
            return Err(
                "Enter the registration code for the name service: it's needed the first time."
                    .into(),
            );
        }
        self.save_enabled(true)?;
        let mut l = self.live();
        // try at once, whatever an earlier failure said (the 7-day limit still holds)
        l.asks.retry_now = true;
        l.settings.enabled = true;
        if let Some(c) = code {
            l.code = Some(Zeroizing::new(c.to_string()));
        }
        l.message = None;
        l.poked = true;
        drop(l);
        self.wake.notify_all();
        Ok(())
    }

    /// Stop using the name. The registration and the certificate are kept, so turning on
    /// again needs no code and no new certificate.
    pub fn turn_off(&self) -> Result<(), String> {
        self.save_enabled(false)?;
        let mut l = self.live();
        l.settings.enabled = false;
        l.state = NameState::Off;
        l.message = None;
        l.code = None;
        l.poked = true;
        drop(l);
        self.wake.notify_all();
        Ok(())
    }

    /// Ask for a new certificate now (still at most 3 in 7 days).
    pub fn renew_now(&self) -> Result<(), String> {
        let mut l = self.live();
        if !l.settings.enabled {
            return Err("Names are off: turn them on first.".into());
        }
        l.force = true;
        l.poked = true;
        drop(l);
        self.wake.notify_all();
        Ok(())
    }

    /// The state, for the apps' Phones screen.
    pub fn status(&self) -> Value {
        let now = self.now();
        let saved = self.load();
        let cert = self.certificate();
        let l = self.live();
        let day_s = 86_400;
        // days left, counted up: 14.5 days is "15", and the warning comes with "14"
        let left = |c: &NameCert| (c.info.not_after - now / 1000).max(0);
        let certificate = cert.as_ref().map(|c| {
            json!({
                "not_before": c.info.not_before,
                "not_after": c.info.not_after,
                "days_left": (left(c) + day_s - 1) / day_s,
                "staging": c.staging,
            })
        });
        let warning = cert
            .as_ref()
            .is_some_and(|c| left(c) <= i64::from(l.warn_days) * day_s);
        let recent = saved
            .requests
            .iter()
            .filter(|t| now - **t < LIMIT_WINDOW)
            .count();
        json!({
            "state": l.state,
            "enabled": l.settings.enabled,
            "name": saved.name,
            "staging": l.settings.staging,
            "certificate": certificate,
            "renewal_warning": warning,
            "retry_at": (saved.retry_at > now).then_some(saved.retry_at),
            "requests_last_7_days": recent,
            "fallback_offered": l.state == NameState::Blocked,
            "message": l.message,
            // Revision 3: where a person asks for a registration code, and whether one is
            // needed (the hub has never registered with this name service).
            "code_page": l.settings.code_page(),
            "code_needed": self.registration(&saved, &l.settings).is_none(),
        })
    }

    /// Change `names.code_page` (Revision 3). A page the rules refuse leaves the old one.
    pub fn set_code_page(&self, page: &str) -> Result<(), String> {
        let page = page.trim();
        crate::config::check_code_page(page)?;
        HubConfig::update(&self.data, |c| c.names.code_page = page.to_string())?;
        self.live().settings.code_page = page.to_string();
        Ok(())
    }

    /// The certificate phones asking for the hub name get: none while names are off.
    pub fn serving(&self) -> Option<NameCert> {
        if !self.live().settings.enabled {
            return None;
        }
        self.certificate()
    }

    /// Wait until poked or `timeout` passes; `true` when poked.
    pub fn wait_for_work(&self, timeout: Duration) -> bool {
        let l = self.live();
        let (mut l, _) = self
            .wake
            .wait_timeout_while(l, timeout, |l| !l.poked)
            .unwrap_or_else(|p| p.into_inner());
        std::mem::replace(&mut l.poked, false)
    }

    /// The home address changed (or was lost): send it at once, and test the name again.
    pub fn set_address(&self, address: Option<Ipv4Addr>) {
        let mut l = self.live();
        l.asks.address_now = true;
        l.address = address;
        l.tested = false;
        l.poked = true;
        drop(l);
        self.wake.notify_all();
    }

    /// Send the address to the name service again ("Update the name").
    pub fn resend_address(&self) {
        self.live().asks.resend = true;
        self.poke();
    }

    /// Apply what the admin address asked to `saved`, and write it. The engine only.
    fn apply_asks(&self, saved: &mut Saved) {
        let asks = std::mem::take(&mut self.live().asks);
        if !(asks.retry_now || asks.address_now || asks.resend) {
            return;
        }
        if asks.retry_now {
            saved.retry_at = 0;
            saved.next_check = 0;
        }
        saved.address_retry_at = 0;
        if asks.resend {
            saved.address_sent = None;
        }
        if let Err(e) = self.save(saved) {
            (self.log)(&format!("names: {e}"));
        }
    }

    /// The `names.*` settings in use, and the warning days.
    pub fn settings(&self) -> (NamesSettings, u32) {
        let l = self.live();
        (l.settings.clone(), l.warn_days)
    }

    /// The hub's name, once registered.
    pub fn name(&self) -> Option<String> {
        self.load().name
    }

    /// Whether names are on and the name service has taken this hub's address: the tunnel
    /// routes of Revision 4 B exist only then.
    pub fn address_set(&self) -> bool {
        let settings = self.live().settings.clone();
        let saved = self.load();
        settings.enabled
            && self.registration(&saved, &settings).is_some()
            && saved.address_sent.is_some()
    }

    /// The hub's id and token at the name service in use.
    fn credentials(&self) -> Result<(String, Zeroizing<String>, String), String> {
        let settings = self.live().settings.clone();
        let saved = self.load();
        let (id, _) = self
            .registration(&saved, &settings)
            .ok_or("The hub isn't registered with the name service.")?;
        let token = self
            .keys
            .get(TOKEN_KEY)?
            .ok_or("The name service's token is missing: turn names off, then on with a new registration code.")?;
        let token = Zeroizing::new(String::from_utf8_lossy(&token).into_owned());
        Ok((id, token, settings.service))
    }

    /// Make tunnel at the name service (revision 1) for `port`. Its refusal in its own words.
    pub fn make_tunnel(&self, port: u16) -> Result<crate::nameservice::Tunnel, String> {
        let (id, token, service) = self.credentials()?;
        NameService::new(self.outside.http.as_ref(), &service)
            .make_tunnel(&id, &token, port)
            .map_err(|e| e.to_string())
    }

    /// Remove tunnel at the name service (revision 1).
    pub fn remove_tunnel(&self) -> Result<(), String> {
        let (id, token, service) = self.credentials()?;
        NameService::new(self.outside.http.as_ref(), &service)
            .remove_tunnel(&id, &token)
            .map_err(|e| e.to_string())
    }

    /// The outside world the engine uses (for Find the problem).
    pub fn outside(&self) -> &Outside {
        &self.outside
    }

    /// Wake [`Names::wait_for_work`] (the hub stopping).
    pub fn poke(&self) {
        self.live().poked = true;
        self.wake.notify_all();
    }

    // ----- the work -----------------------------------------------------------------------------

    /// Do whatever is due now. The hub's thread calls this when poked and every minute.
    pub fn run_once(&self) {
        let _one = self.running.lock().unwrap_or_else(|p| p.into_inner());
        let now = self.now();
        let (settings, address) = {
            let l = self.live();
            (l.settings.clone(), l.address)
        };
        if !settings.enabled {
            self.set(NameState::Off, None);
            return;
        }
        if let Some(p) = settings.problem() {
            self.set(NameState::Off, Some(p));
            return;
        }
        let Some(address) = address else {
            self.set(
                NameState::Waiting,
                Some("This computer isn't on a home network (it has no home or office address), so the name can't point to it.".into()),
            );
            return;
        };
        let mut saved = self.load();
        self.apply_asks(&mut saved);

        // 1. the registration
        let (id, name) = match self.registration(&saved, &settings) {
            Some(r) => {
                self.live().code = None; // not needed: forget it
                r
            }
            None => match self.register(&mut saved, &settings) {
                Ok(r) => r,
                Err((state, f)) => {
                    self.set(state, Some(f.message));
                    return;
                }
            },
        };
        let Some(token) = self.keys.get(TOKEN_KEY).ok().flatten() else {
            self.set(
                NameState::Off,
                Some("The name service's token is missing: turn names off, then on with a new registration code.".into()),
            );
            return;
        };
        let token = String::from_utf8_lossy(&token).into_owned();
        let token = Zeroizing::new(token);
        let service = NameService::new(self.outside.http.as_ref(), &settings.service);

        // 2. the address
        let addr = address.to_string();
        if saved.address_sent.as_deref() != Some(addr.as_str()) {
            if now < saved.address_retry_at {
                let m = self.live().message.clone();
                self.set(NameState::Waiting, m);
                return;
            }
            if let Err(e) = service.set_address(&id, &token, &addr) {
                saved.address_retry_at = now + ADDRESS_RETRY;
                let _ = self.save(&saved);
                (self.log)(&format!("names: the address wasn't accepted ({})", e.code));
                self.set(NameState::Waiting, Some(e.to_string()));
                return;
            }
            saved.address_sent = Some(addr.clone());
            let _ = self.save(&saved);
            (self.log)("names: address sent");
        }

        // 3. the certificate
        let force = std::mem::replace(&mut self.live().force, false);
        let daily = now >= saved.next_check;
        let current = self.certificate();
        let due = match &current {
            None => true,
            Some(c) => {
                let life = c.info.not_after - c.info.not_before;
                now / 1000 >= c.info.not_after - life / 3
            }
        };
        let mut issued = false;
        let mut message: Option<String> = None;
        if force || (due && (daily || current.is_none()) && now >= saved.retry_at) {
            saved.requests.retain(|t| now - *t < LIMIT_WINDOW);
            if saved.requests.len() >= MAX_REQUESTS {
                let free = saved.requests.iter().min().copied().unwrap_or(now) + LIMIT_WINDOW;
                saved.retry_at = saved.retry_at.max(free);
                message = Some(format!(
                    "The hub has asked for {MAX_REQUESTS} certificates in 7 days, its own limit; it will ask again after that."
                ));
                (self.log)("names: certificate request held back by the 7-day limit");
            } else {
                self.set(NameState::Proving, None);
                match self.issue(&mut saved, &settings, &service, &id, &token, &name) {
                    Ok(()) => {
                        saved.retry_at = 0;
                        issued = true;
                        (self.log)("names: certificate issued");
                    }
                    Err(f) => {
                        saved.retry_at =
                            f.retry_at.map_or(now + DAY, |r| now + r).max(now + MINUTE);
                        (self.log)("names: certificate request failed");
                        message = Some(f.message);
                    }
                }
            }
            let _ = self.save(&saved);
        }

        // 4. the self-test
        let (mut blocked, tested) = {
            let l = self.live();
            (l.blocked, l.tested)
        };
        if issued || daily || !tested {
            blocked = self.self_test(&name, address).unwrap_or(blocked);
            let mut l = self.live();
            l.blocked = blocked;
            l.tested = true;
        }
        if daily {
            saved.next_check = now + DAY;
            let _ = self.save(&saved);
        }

        let state = match (self.certificate().is_some(), blocked) {
            (false, _) => NameState::Waiting,
            (true, true) => NameState::Blocked,
            (true, false) => NameState::Ready,
        };
        let message = match state {
            NameState::Blocked => Some(
                "This home's router refuses the hub's name. Allow the name in the router, or connect phones the other way (the hub's own certificate)."
                    .into(),
            ),
            _ => message,
        };
        self.set(state, message);
    }

    /// Register with the code given; on failure the state to show.
    fn register(
        &self,
        saved: &mut Saved,
        settings: &NamesSettings,
    ) -> Result<(String, String), (NameState, Failed)> {
        let (code, said) = {
            let mut l = self.live();
            (l.code.take(), l.message.clone())
        };
        let Some(code) = code else {
            // (keeps the reason the last code was refused, if there was one)
            let m = said.unwrap_or_else(|| {
                "Enter the registration code for the name service to turn names on.".into()
            });
            return Err((NameState::Off, fail(m)));
        };
        self.set(NameState::Registering, None);
        let service = NameService::new(self.outside.http.as_ref(), &settings.service);
        match service.register(&code, env!("CARGO_PKG_VERSION")) {
            Ok(r) => {
                if let Err(e) = self.keys.set(TOKEN_KEY, r.token.as_bytes()) {
                    return Err((NameState::Waiting, fail(e)));
                }
                *saved = Saved {
                    id: Some(r.id.clone()),
                    name: Some(r.name.clone()),
                    service: Some(settings.service.clone()),
                    // (requests for an earlier name still count against Let's Encrypt)
                    requests: std::mem::take(&mut saved.requests),
                    ..Saved::default()
                };
                let _ = std::fs::remove_file(self.data.join(NAME_CERT_FILE));
                if let Err(e) = self.save(saved) {
                    return Err((NameState::Waiting, fail(e)));
                }
                (self.log)("names: registered");
                Ok((r.id, r.name))
            }
            Err(e) => {
                let state = if e.status == 0 || e.code == "rate_limited" {
                    // no internet, or a limit: the code is kept for the next try
                    self.live().code = Some(code);
                    NameState::Waiting
                } else {
                    NameState::Off
                };
                (self.log)(&format!("names: registration refused ({})", e.code));
                Err((state, fail(e.to_string())))
            }
        }
    }

    /// Wait until a public resolver sees `proof` at `_acme-challenge.<name>`.
    fn proof_visible(&self, name: &str, proof: &str) -> Result<(), Failed> {
        let record = format!("_acme-challenge.{name}");
        let until = self.now() + PROOF_WAIT;
        loop {
            if let Ok(found) = self.outside.lookup.public(&record, Kind::Txt) {
                if found.iter().any(|v| v == proof) {
                    return Ok(());
                }
            }
            if self.now() >= until {
                return Err(fail(
                    "The proof didn't appear in public DNS within 2 minutes.",
                ));
            }
            (self.outside.wait)(POLL);
        }
    }

    fn issue(
        &self,
        saved: &mut Saved,
        settings: &NamesSettings,
        service: &NameService<'_>,
        id: &str,
        token: &str,
        name: &str,
    ) -> Result<(), Failed> {
        let directory = settings.directory().to_string();
        let account_key = match self.keys.get(ACCOUNT_KEY).map_err(fail)? {
            Some(k) if saved.acme.as_deref() == Some(directory.as_str()) => k,
            _ => {
                let k = acme::new_account_key().map_err(fail)?;
                self.keys.set(ACCOUNT_KEY, &k).map_err(fail)?;
                saved.acme = Some(directory.clone());
                saved.account_url = None;
                k
            }
        };
        let mut a = Acme::new(
            self.outside.http.as_ref(),
            &directory,
            &account_key,
            saved.account_url.clone(),
        )?;
        if a.kid.is_none() {
            saved.account_url = Some(a.account()?);
            self.save(saved).map_err(fail)?;
        }
        // counted before it is sent, so nothing can send a fourth
        saved.requests.push(self.now());
        self.save(saved).map_err(fail)?;
        let order = a.new_order(name)?;

        let proved = (|| -> Result<(), Failed> {
            for authz in &order.authorizations {
                let (status, ch) = a.dns_challenge(authz)?;
                if status == "valid" {
                    continue;
                }
                service
                    .set_proof(id, token, &ch.proof)
                    .map_err(|e| Failed {
                        message: e.to_string(),
                        retry_at: e.retry_after.map(|s| i64::try_from(s).unwrap_or(0) * 1000),
                    })?;
                self.proof_visible(name, &ch.proof)?;
                a.respond(&ch.url)?;
                let until = self.now() + ACME_WAIT;
                loop {
                    let (status, why, after) = a.authorization(authz)?;
                    match status.as_str() {
                        "valid" => break,
                        "pending" | "processing" if self.now() < until => {
                            (self.outside.wait)(after.map_or(POLL, Duration::from_secs));
                        }
                        _ => {
                            return Err(fail(format!(
                                "Let's Encrypt couldn't check the proof: {}",
                                why.unwrap_or(status)
                            )))
                        }
                    }
                }
            }
            Ok(())
        })();
        // the proof is cleared whatever happened
        if let Err(e) = service.clear_proof(id, token) {
            (self.log)(&format!("names: the proof wasn't cleared ({})", e.code));
        }
        proved?;

        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| fail(format!("a key can't be made: {e}")))?;
        let csr = CertificateParams::new(vec![name.to_string()])
            .and_then(|p| p.serialize_request(&key))
            .map_err(|e| fail(format!("the certificate request can't be made: {e}")))?;
        let mut order = a.finalize(&order, csr.der())?;
        let until = self.now() + ACME_WAIT;
        while order.status != "valid" {
            if order.status == "invalid" || self.now() >= until {
                return Err(fail(format!(
                    "Let's Encrypt didn't issue the certificate (the order is {}).",
                    order.status
                )));
            }
            (self.outside.wait)(POLL);
            order = a.order(&order.url)?.0;
        }
        let url = order
            .certificate
            .ok_or_else(|| fail("Let's Encrypt gave no certificate address."))?;
        let pem = a.certificate(&url)?;
        let chain = der::pem_certificates(&pem);
        let info = chain
            .first()
            .and_then(|c| der::cert_info(c))
            .ok_or_else(|| fail("The certificate from Let's Encrypt can't be read."))?;
        if info.spki != key.subject_public_key_info() || !info.dns_names.iter().any(|n| n == name) {
            return Err(fail(
                "The certificate from Let's Encrypt isn't for this hub's name and key.",
            ));
        }
        let key_der = Zeroizing::new(key.serialize_der());
        self.keys.set(CERT_KEY, &key_der).map_err(fail)?;
        util::write_private(&self.data.join(NAME_CERT_FILE), pem.as_bytes()).map_err(fail)?;
        saved.cert_staging = settings.staging;
        Ok(())
    }

    /// The self-test: `Some(true)` when the public resolver gives this computer's address
    /// for the name and this computer's own resolver doesn't; `None` when the public one
    /// can't tell (no answer yet).
    fn self_test(&self, name: &str, address: Ipv4Addr) -> Option<bool> {
        let public = self.outside.lookup.public(name, Kind::A).ok()?;
        if !public.contains(&address.to_string()) {
            return None;
        }
        let home = self.outside.lookup.home(name).unwrap_or_default();
        Some(!home.contains(&address))
    }
}
