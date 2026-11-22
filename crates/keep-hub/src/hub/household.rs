//! Administrators and standard members (the spec, "Administrators and standard members",
//! stage 8): the first set-up, signing in, sessions, and the requests that change the
//! household's members.
//!
//! - **Passwords** are kept only as an Argon2id record (the PIN's form, [`crate::pin`]).
//! - **Sessions** live in the hub's memory only: 32 random bytes, of which the hub keeps the
//!   SHA-256. A session lasts `admin.session_minutes` from its last use, and ends when the
//!   hub restarts, when its member is removed or made a standard member, or on sign-out.
//! - **Wrong passwords** are counted per administrator: five in 10 minutes pause that
//!   administrator's sign-in for 10 minutes. Others can still sign in.
//! - **An open household** (Revision 2 B) is one where the computer's sign-in is enough:
//!   its first set-up gave no password and no PIN, the admin token alone is an
//!   administrator, and signing in is not used. `secure` makes it a secured household, once
//!   and for good. `hub.sqlite` records which it is ([`HOUSEHOLD_KEY`]).

use std::collections::VecDeque;

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{clean_name, Hub, Refusal, State};
use crate::registry::{Member, ADMINISTRATOR, HOUSEHOLD_KEY, OPEN, PIN_KEY, STANDARD};
use crate::{pin, util};

/// Wrong passwords for one administrator before their sign-in pauses.
pub const MAX_WRONG_PASSWORDS: usize = 5;
const WRONG_WINDOW_MS: i64 = 10 * 60 * 1000;
const PAUSE_MS: i64 = 10 * 60 * 1000;
/// The shortest administrator password, in characters.
pub const MIN_PASSWORD: usize = 8;
/// The longest, so a request can't make the hub hash megabytes.
const MAX_PASSWORD: usize = 256;

/// A signed-in administrator's session.
pub(crate) struct Session {
    member: u32,
    last_used: i64,
}

/// One administrator's wrong passwords, and when a pause ends.
#[derive(Default)]
pub(crate) struct SignIn {
    wrong: VecDeque<i64>,
    paused_until: i64,
}

fn session_key(token: &str) -> [u8; 32] {
    Sha256::digest(token.trim().as_bytes()).into()
}

pub(crate) fn administrator_needed() -> Refusal {
    Refusal::new(
        401,
        "administrator_needed",
        "An administrator must sign in on this computer first.",
    )
}

/// What an open household doesn't have (a PIN, passwords) until it is secured.
pub(crate) fn household_not_secured() -> Refusal {
    Refusal::new(
        409,
        "household_not_secured",
        "This household has no administrator password or household PIN yet. Set a password and a PIN for the household first.",
    )
}

fn sign_in_not_used() -> Refusal {
    Refusal::new(
        409,
        "sign_in_not_used",
        "In this household the computer's sign-in is enough: there is nothing to sign in to.",
    )
}

fn setup_needed() -> Refusal {
    Refusal::new(
        409,
        "setup_needed",
        "Keep Hub isn't set up yet: make the first administrator and the household PIN.",
    )
}

/// A class an administrator may give a household member.
fn household_class(class: &str) -> Result<&'static str, Refusal> {
    match class {
        ADMINISTRATOR => Ok(ADMINISTRATOR),
        STANDARD => Ok(STANDARD),
        _ => Err(Refusal::new(
            400,
            "bad_class",
            "A household member is an administrator or a standard member.",
        )),
    }
}

fn check_password(password: &str) -> Result<(), Refusal> {
    let n = password.chars().count();
    if !(MIN_PASSWORD..=MAX_PASSWORD).contains(&n) {
        return Err(Refusal::new(
            400,
            "bad_password",
            format!("An administrator password is {MIN_PASSWORD} to {MAX_PASSWORD} characters."),
        ));
    }
    Ok(())
}

fn no_member() -> Refusal {
    Refusal::new(
        404,
        "no_such_member",
        "That person isn't in the household's list.",
    )
}

/// A member as the admin address shows one.
pub(crate) fn shown(m: &Member) -> Value {
    json!({ "id": m.id, "name": m.name, "class": m.class })
}

/// The first set-up, in either form: a name, a password and the household PIN; or a name
/// and `sign_in_is_enough`, with no password and no PIN (Revision 2 B).
#[derive(Debug, Deserialize)]
pub(crate) struct SetupRequest {
    pub name: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub pin: Option<String>,
    #[serde(default)]
    pub sign_in_is_enough: bool,
}

/// `secure`: an administrator's name, a password for them and the household PIN.
#[derive(Debug, Deserialize)]
pub(crate) struct SecureRequest {
    pub name: String,
    pub password: String,
    pub pin: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SignInRequest {
    pub name: String,
    pub password: String,
}

impl Hub {
    /// Whether the household is open: the computer's sign-in is enough (Revision 2 B).
    pub(crate) fn is_open(&self) -> Result<bool, Refusal> {
        Ok(self
            .lock()
            .registry
            .get(HOUSEHOLD_KEY)
            .map_err(Refusal::inner)?
            .is_some_and(|v| v == OPEN))
    }

    /// What a request marked A needs: in an open household the admin token (already
    /// checked) is enough; otherwise an administrator's live session.
    pub(crate) fn acting_administrator(&self, session: Option<&str>) -> Result<(), Refusal> {
        if self.is_open()? {
            return Ok(());
        }
        self.administrator(session).map(|_| ())
    }

    /// Whether the first set-up has been done (there is an administrator).
    pub(crate) fn is_set_up(&self) -> Result<bool, Refusal> {
        Ok(self
            .lock()
            .registry
            .administrators()
            .map_err(Refusal::inner)?
            > 0)
    }

    /// Refused until the first set-up is done.
    pub(crate) fn needs_setup(&self) -> Result<(), Refusal> {
        if self.is_set_up()? {
            Ok(())
        } else {
            Err(setup_needed())
        }
    }

    /// Another administrator with this name (case and spaces aside), other than `except`:
    /// a sign-in names its administrator.
    fn administrator_named(
        st: &State,
        name: &str,
        except: Option<u32>,
    ) -> Result<Option<Member>, Refusal> {
        let want = name.trim().to_lowercase();
        Ok(st
            .registry
            .members()
            .map_err(Refusal::inner)?
            .into_iter()
            .find(|m| {
                m.is_administrator() && Some(m.id) != except && m.name.to_lowercase() == want
            }))
    }

    fn name_free_for_administrator(
        st: &State,
        name: &str,
        except: Option<u32>,
    ) -> Result<(), Refusal> {
        if Self::administrator_named(st, name, except)?.is_some() {
            return Err(Refusal::new(
                409,
                "name_taken",
                "Another administrator has that name. Give each administrator their own name, so signing in can tell them apart.",
            ));
        }
        Ok(())
    }

    /// The first set-up: the first administrator, their password and the household PIN.
    /// Only while no administrator exists. Answers with the administrator and a session.
    pub(crate) fn first_setup(&self, r: &SetupRequest) -> Result<Value, Refusal> {
        let name = clean_name(&r.name, "the first administrator")?;
        if r.sign_in_is_enough {
            return self.first_setup_open(&name, r);
        }
        let (Some(password), Some(new_pin)) = (&r.password, &r.pin) else {
            return Err(Refusal::new(
                400,
                "bad_setup",
                "The first set-up needs an administrator password and the household PIN, or sign_in_is_enough.",
            ));
        };
        check_password(password)?;
        let new_pin = new_pin.trim();
        pin::check(new_pin).map_err(|e| Refusal::new(400, "bad_pin", e))?;
        if self.is_set_up()? {
            return Err(already_set_up());
        }
        let password = pin::hash_with(password, self.pin_cost).map_err(Refusal::inner)?;
        let pin_hash = pin::hash_with(new_pin, self.pin_cost).map_err(Refusal::inner)?;
        let now = self.now();
        let mut st = self.lock();
        // (looked at again under the lock: two set-ups at once make one administrator)
        if st.registry.administrators().map_err(Refusal::inner)? > 0 {
            return Err(already_set_up());
        }
        let id = st
            .registry
            .add_member_as(&name, ADMINISTRATOR, now)
            .map_err(Refusal::inner)?;
        st.registry
            .set_password(id, Some(&password))
            .map_err(Refusal::inner)?;
        st.registry
            .set(PIN_KEY, &pin_hash)
            .map_err(Refusal::inner)?;
        let session = Self::new_session(&mut st, id, now)?;
        drop(st);
        self.log(&format!("member {id} set up as the first administrator"));
        Ok(json!({
            "member": { "id": id, "name": name, "class": ADMINISTRATOR },
            "household": "secured",
            "session": session.as_str(),
            "session_minutes": self.cfg.admin.session_minutes,
        }))
    }

    /// The first set-up of an open household: the first administrator, with no password,
    /// and no household PIN. No session: none is used.
    fn first_setup_open(&self, name: &str, r: &SetupRequest) -> Result<Value, Refusal> {
        if r.password.is_some() || r.pin.is_some() {
            return Err(Refusal::new(
                400,
                "bad_setup",
                "When the computer's sign-in is enough, the first set-up takes no password and no PIN.",
            ));
        }
        let now = self.now();
        let st = self.lock();
        if st.registry.administrators().map_err(Refusal::inner)? > 0 {
            return Err(already_set_up());
        }
        let id = st
            .registry
            .add_member_as(name, ADMINISTRATOR, now)
            .map_err(Refusal::inner)?;
        // (a hub upgraded from stage 7 may hold an old PIN: an open household has none)
        st.registry.remove(PIN_KEY).map_err(Refusal::inner)?;
        st.registry
            .set(HOUSEHOLD_KEY, OPEN)
            .map_err(Refusal::inner)?;
        drop(st);
        self.log(&format!(
            "member {id} set up as the first administrator (open household)"
        ));
        Ok(json!({
            "member": { "id": id, "name": name, "class": ADMINISTRATOR },
            "household": "open",
        }))
    }

    /// `secure`: an open household becomes secured, for good. The named administrator
    /// gets a password, the household gets its PIN, and the answer carries a session.
    /// Other administrators have no password until one who has signed in sets it.
    pub(crate) fn secure(&self, r: &SecureRequest) -> Result<Value, Refusal> {
        if !self.is_open()? {
            return Err(already_secured());
        }
        check_password(&r.password)?;
        let new_pin = r.pin.trim();
        pin::check(new_pin).map_err(|e| Refusal::new(400, "bad_pin", e))?;
        let member = {
            let st = self.lock();
            match Self::administrator_named(&st, &r.name, None)? {
                Some(m) => m,
                None => {
                    let want = r.name.trim().to_lowercase();
                    let standard = st
                        .registry
                        .members()
                        .map_err(Refusal::inner)?
                        .iter()
                        .any(|m| !m.is_guest() && m.name.to_lowercase() == want);
                    return Err(if standard {
                        not_an_administrator()
                    } else {
                        Refusal::new(
                            404,
                            "no_such_member",
                            "There is no administrator with that name in the household.",
                        )
                    });
                }
            }
        };
        let password = pin::hash_with(&r.password, self.pin_cost).map_err(Refusal::inner)?;
        let pin_hash = pin::hash_with(new_pin, self.pin_cost).map_err(Refusal::inner)?;
        let now = self.now();
        let mut st = self.lock();
        // (looked at again under the lock: two at once secure it once)
        if st
            .registry
            .get(HOUSEHOLD_KEY)
            .map_err(Refusal::inner)?
            .as_deref()
            != Some(OPEN)
        {
            return Err(already_secured());
        }
        st.registry
            .secure(member.id, &password, &pin_hash)
            .map_err(Refusal::inner)?;
        let session = Self::new_session(&mut st, member.id, now)?;
        drop(st);
        self.log(&format!("household secured by member {}", member.id));
        Ok(json!({
            "member": shown(&member),
            "household": "secured",
            "session": session.as_str(),
            "session_minutes": self.cfg.admin.session_minutes,
        }))
    }

    fn new_session(st: &mut State, member: u32, now: i64) -> Result<Zeroizing<String>, Refusal> {
        let token = Zeroizing::new(util::hex(&util::random::<32>().map_err(Refusal::inner)?));
        st.sessions.insert(
            session_key(&token),
            Session {
                member,
                last_used: now,
            },
        );
        Ok(token)
    }

    fn session_ms(&self) -> i64 {
        i64::from(self.cfg.admin.session_minutes.max(1)) * 60_000
    }

    /// Sign an administrator in with their name and password: a session.
    pub(crate) fn sign_in(&self, r: &SignInRequest) -> Result<Value, Refusal> {
        let wrong = || {
            Refusal::new(
                403,
                "wrong_password",
                "That name and password don't match an administrator.",
            )
        };
        if self.is_open()? {
            return Err(sign_in_not_used());
        }
        let now = self.now();
        let (member, record) = {
            let mut st = self.lock();
            let want = r.name.trim().to_lowercase();
            let members = st.registry.members().map_err(Refusal::inner)?;
            let Some(member) = Self::administrator_named(&st, &r.name, None)? else {
                if members
                    .iter()
                    .any(|m| !m.is_guest() && m.name.to_lowercase() == want)
                {
                    return Err(Refusal::new(
                        403,
                        "not_an_administrator",
                        "Only an administrator signs in. A standard member has no password on the hub computer.",
                    ));
                }
                return Err(wrong());
            };
            let s = st.sign_ins.entry(member.id).or_default();
            if s.paused_until > now {
                return Err(paused());
            }
            let Some(record) = st.registry.password_of(member.id).map_err(Refusal::inner)? else {
                return Err(Refusal::new(
                    403,
                    "no_password",
                    "This administrator has no password yet. Another administrator sets it first.",
                ));
            };
            (member, record)
        };
        // Slow on purpose (Argon2id), outside the lock.
        let ok = pin::verify(&r.password, &record);
        let mut st = self.lock();
        if !ok {
            let s = st.sign_ins.entry(member.id).or_default();
            s.wrong.retain(|t| now - t < WRONG_WINDOW_MS);
            s.wrong.push_back(now);
            if s.wrong.len() >= MAX_WRONG_PASSWORDS {
                s.wrong.clear();
                s.paused_until = now + PAUSE_MS;
                drop(st);
                self.log(&format!("member {} sign-in paused", member.id));
                return Err(paused());
            }
            return Err(wrong());
        }
        st.sign_ins.remove(&member.id);
        let session = Self::new_session(&mut st, member.id, now)?;
        drop(st);
        self.log(&format!("member {} signed in", member.id));
        Ok(json!({
            "member": shown(&member),
            "session": session.as_str(),
            "session_minutes": self.cfg.admin.session_minutes,
        }))
    }

    /// Sign out: the session ends. Nothing to do without one.
    pub(crate) fn sign_out(&self, session: Option<&str>) {
        if let Some(s) = session {
            self.lock().sessions.remove(&session_key(s));
        }
    }

    /// The administrator whose live session `session` is, for a request marked A. Each use
    /// (any request carrying the session) starts the session's minutes again.
    pub(crate) fn administrator(&self, session: Option<&str>) -> Result<Member, Refusal> {
        let Some(session) = session else {
            return Err(administrator_needed());
        };
        let now = self.now();
        let life = self.session_ms();
        let key = session_key(session);
        let mut st = self.lock();
        st.sessions.retain(|_, s| now - s.last_used < life);
        let Some(id) = st.sessions.get(&key).map(|s| s.member) else {
            return Err(administrator_needed());
        };
        let member = st.registry.member(id).map_err(Refusal::inner)?;
        let Some(member) = member.filter(Member::is_administrator) else {
            st.sessions.remove(&key);
            return Err(administrator_needed());
        };
        if let Some(s) = st.sessions.get_mut(&key) {
            s.last_used = now;
        }
        Ok(member)
    }

    /// End every session of `member`, except `keep`.
    fn end_sessions(st: &mut State, member: u32, keep: Option<&str>) {
        let keep = keep.map(session_key);
        st.sessions
            .retain(|k, s| s.member != member || Some(*k) == keep);
    }

    // ----- members --------------------------------------------------------------------------

    /// Add a household member, a standard member unless `class` says otherwise.
    pub(crate) fn add_member(&self, name: &str, class: Option<&str>) -> Result<Value, Refusal> {
        let name = clean_name(name, "this person")?;
        let class = household_class(class.unwrap_or(STANDARD))?;
        let now = self.now();
        let st = self.lock();
        if class == ADMINISTRATOR {
            Self::name_free_for_administrator(&st, &name, None)?;
        }
        let id = st
            .registry
            .add_member_as(&name, class, now)
            .map_err(Refusal::inner)?;
        Ok(json!({ "id": id, "name": name, "class": class }))
    }

    fn household_member(st: &State, id: u32) -> Result<Member, Refusal> {
        let m = st.registry.member(id).map_err(Refusal::inner)?;
        let Some(m) = m else {
            return Err(no_member());
        };
        if m.is_guest() {
            return Err(Refusal::new(
                409,
                "guest_member",
                "That is a guest: a guest's name and class don't change. Remove the guest instead.",
            ));
        }
        Ok(m)
    }

    pub(crate) fn rename_member(&self, id: u32, name: &str) -> Result<Value, Refusal> {
        let name = clean_name(name, "this person")?;
        let st = self.lock();
        let m = Self::household_member(&st, id)?;
        if m.is_administrator() {
            Self::name_free_for_administrator(&st, &name, Some(id))?;
        }
        st.registry
            .rename_member(id, &name)
            .map_err(Refusal::inner)?;
        Ok(json!({ "ok": true }))
    }

    /// Make a household member an administrator or a standard member. The last
    /// administrator stays one. A new administrator has no password until one is set.
    pub(crate) fn set_class(&self, id: u32, class: &str) -> Result<Value, Refusal> {
        let class = household_class(class)?;
        let mut st = self.lock();
        let m = Self::household_member(&st, id)?;
        if m.class == class {
            return Ok(json!({ "ok": true }));
        }
        if class == ADMINISTRATOR {
            Self::name_free_for_administrator(&st, &m.name, Some(id))?;
        } else if st.registry.administrators().map_err(Refusal::inner)? <= 1 {
            return Err(last_administrator());
        }
        st.registry.set_class(id, class).map_err(Refusal::inner)?;
        if class != ADMINISTRATOR {
            Self::end_sessions(&mut st, id, None);
        }
        drop(st);
        self.log(&format!("member {id} is now {class}"));
        Ok(json!({ "ok": true }))
    }

    /// Set an administrator's password (their own or another's). Another administrator's
    /// sessions end; the caller's own session (`keep`) goes on.
    pub(crate) fn set_password(
        &self,
        id: u32,
        password: &str,
        keep: Option<&str>,
    ) -> Result<Value, Refusal> {
        if self.is_open()? {
            return Err(household_not_secured());
        }
        check_password(password)?;
        {
            let st = self.lock();
            let m = Self::household_member(&st, id)?;
            if !m.is_administrator() {
                return Err(not_an_administrator());
            }
        }
        let record = pin::hash_with(password, self.pin_cost).map_err(Refusal::inner)?;
        let mut st = self.lock();
        if !st
            .registry
            .set_password(id, Some(&record))
            .map_err(Refusal::inner)?
        {
            return Err(not_an_administrator());
        }
        Self::end_sessions(&mut st, id, keep);
        st.sign_ins.remove(&id);
        drop(st);
        self.log(&format!("member {id} has a new password"));
        Ok(json!({ "ok": true }))
    }

    /// Remove a member, of the household or a guest (owner decision 2026-11-19): their
    /// phones are revoked and their grants go. The last administrator stays.
    pub(crate) fn remove_member(&self, id: u32) -> Result<Value, Refusal> {
        let now = self.now();
        let mut st = self.lock();
        let Some(m) = st.registry.member(id).map_err(Refusal::inner)? else {
            return Err(no_member());
        };
        if m.is_administrator() && st.registry.administrators().map_err(Refusal::inner)? <= 1 {
            return Err(last_administrator());
        }
        st.registry.remove_member(id, now).map_err(Refusal::inner)?;
        Self::end_sessions(&mut st, id, None);
        st.sign_ins.remove(&id);
        st.codes.retain(|_, c| c.member != id);
        drop(st);
        self.log(&format!("member {id} removed"));
        Ok(json!({ "ok": true }))
    }
}

fn already_set_up() -> Refusal {
    Refusal::new(
        409,
        "already_set_up",
        "Keep Hub is already set up. An administrator signs in instead.",
    )
}

fn already_secured() -> Refusal {
    Refusal::new(
        409,
        "already_secured",
        "This household is already secured with a password and PIN. A secured household can't be made open again.",
    )
}

fn paused() -> Refusal {
    Refusal::new(
        429,
        "sign_in_paused",
        "Too many wrong passwords: signing in as this administrator is paused for 10 minutes.",
    )
}

fn last_administrator() -> Refusal {
    Refusal::new(
        409,
        "last_administrator",
        "The household needs at least one administrator. Make another member an administrator first.",
    )
}

fn not_an_administrator() -> Refusal {
    Refusal::new(
        409,
        "not_an_administrator",
        "Only an administrator has a password.",
    )
}

/// `keep-hub reset-administrator`: a new password for the administrator `name`, written
/// straight to the registry in `data` (the hub may be running). Members, grants and
/// devices stay as they were.
pub fn reset_administrator(
    data: &std::path::Path,
    name: &str,
    password: &str,
) -> crate::util::StoreResult<u32> {
    check_password(password).map_err(|r| r.message.clone())?;
    let registry = crate::registry::Registry::open(data)?;
    if registry.get(HOUSEHOLD_KEY)?.is_some_and(|v| v == OPEN) {
        return Err("This household is open: the computer's sign-in is enough and no administrator has a password, so there is nothing to reset.".into());
    }
    let want = name.trim().to_lowercase();
    let members = registry.members()?;
    let found = members
        .iter()
        .find(|m| m.is_administrator() && m.name.to_lowercase() == want);
    let Some(m) = found else {
        if members
            .iter()
            .any(|m| !m.is_guest() && m.name.to_lowercase() == want)
        {
            return Err(format!(
                "{} is a standard member, not an administrator: only an administrator has a password.",
                name.trim()
            ));
        }
        return Err(format!("There is no administrator named {}.", name.trim()));
    };
    let record = pin::hash(password)?;
    registry.set_password(m.id, Some(&record))?;
    Ok(m.id)
}
