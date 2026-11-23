//! The admin address (`http://127.0.0.1:16081`, this computer only), for the apps' desktop
//! programs and for keep-launcher (which lists the registered apps before it removes the
//! hub). Every request needs the admin token from the hub's data folder
//! (`Authorization: Bearer`). Requests marked A also need an administrator's live session
//! in `Keep-Admin-Session`, or answer 401 `administrator_needed`; in an open household
//! (Revision 2 B) the admin token alone is an administrator. Until the first set-up every
//! request but the set-up answers 409 `setup_needed`. Started from the admin listener of
//! ShareKeep's hub (`server.rs`).
//!
//! ```text
//!    POST   /admin/v1/setup          {name, password, pin}  first set-up; answers with a session
//!    POST   /admin/v1/setup          {name, sign_in_is_enough: true}  … of an open household
//!    POST   /admin/v1/secure         {name, password, pin}  secure an open household: a session
//!    POST   /admin/v1/session        {name, password}       sign in: a session (409 sign_in_not_used
//!                                                           in an open household)
//!    DELETE /admin/v1/session                               sign out
//!    GET    /admin/v1/status                       hub version, protocol numbers, each app's state
//!    GET    /admin/v1/apps                         the registered apps
//! (A)POST   /admin/v1/apps                         register an app (A the first time, and to
//!                                                  change its `pairing`)
//! A  DELETE /admin/v1/apps/<id>                    unregister
//!    GET    /admin/v1/members                      list, with each member's class
//! A  POST   /admin/v1/members        {name, class?}         add (a standard member by default)
//! A  PUT    /admin/v1/members/<id>   {name}                 rename
//! A  PUT    /admin/v1/members/<id>/class    {class}         administrator or standard
//! A  PUT    /admin/v1/members/<id>/password {password}      an administrator's password
//! A  DELETE /admin/v1/members/<id>                          remove: phones revoked, grants gone
//!    GET    /admin/v1/grants                       list
//! A  POST   /admin/v1/grants         {member, app}  give (no PIN, money or not)
//! A  DELETE /admin/v1/grants/<member>/<app>        remove
//!    GET    /admin/v1/devices                      list
//! A  DELETE /admin/v1/devices/<id>                 revoke
//! A  POST   /admin/v1/pairing-codes  {member, app}  make
//! A  DELETE /admin/v1/pairing-codes/<code>         cancel
//!    GET    /admin/v1/invites                      guest invites not used yet
//! A  POST   /admin/v1/invites        {app, scope}  make
//! A  DELETE /admin/v1/invites/<id>                 cancel
//!    GET    /admin/v1/pin                          whether a household PIN is set
//! A  PUT    /admin/v1/pin            {pin}         set or change (the old PIN is not needed)
//!    GET    /admin/v1/names                        the name's state and certificate
//! A  POST   /admin/v1/names/on       {registration_code?}  turn on (the code the first time)
//! A  POST   /admin/v1/names/off                    turn off (the name and certificate are kept)
//! A  POST   /admin/v1/names/renew                  ask for a new certificate now
//! A  PUT    /admin/v1/names/code-page {code_page}  where a person asks for a registration code
//!    POST   /admin/v1/names/address                send the address to the name service again
//!    GET    /admin/v1/addresses                    this computer's home addresses and adapters
//! A  PUT    /admin/v1/address        {adapter}     which adapter's address to use ("automatic")
//!    POST   /admin/v1/problems                     Find the problem: run the checks
//!    GET    /admin/v1/problems                     the last results
//! A  POST   /admin/v1/problems/fix   {check}       Fix (check 4 only): check 4's new result
//! A  POST   /admin/v1/probe                        a probe nonce and the address to open
//!    GET    /admin/v1/probe/<nonce>                whether the hub saw it, when and how
//! A  PUT    /admin/v1/tunnel         {hostname}    the tunnel's public hostname
//! A  DELETE /admin/v1/tunnel                       clear it
//! A  PUT    /admin/v1/tunnel/moneykeep-name        a tunnel from the name service: its token,
//!                                                  once (only with names on and an address set)
//! A  DELETE /admin/v1/tunnel/moneykeep-name        the name service deletes it
//! ```

use std::io::Read;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::{json, Value};
use tiny_http::{Header, Request, Response};

use crate::hub::household::{SecureRequest, SetupRequest, SignInRequest};
use crate::hub::{Hub, Refusal, Registration};
use crate::registry::PIN_KEY;
use crate::util;

/// The header that carries an administrator's session.
pub const SESSION_HEADER: &str = "Keep-Admin-Session";

const MAX_BODY: u64 = 64 * 1024;

fn send(hub: &Hub, req: Request, status: u16, body: &Value) {
    let method = req.method().as_str().to_string();
    let path = req.url().split('?').next().unwrap_or("").to_string();
    let bytes = serde_json::to_vec(body).unwrap_or_default();
    let mut resp = Response::from_data(bytes).with_status_code(status);
    for (k, v) in [
        ("Content-Type", "application/json"),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
        ("Connection", "close"),
    ] {
        if let Ok(h) = Header::from_bytes(k.as_bytes(), v.as_bytes()) {
            resp.add_header(h);
        }
    }
    let _ = req.respond(resp);
    // A pairing code in a path is a secret: the log names the kind of address only.
    let shown = if path.starts_with("/admin/v1/pairing-codes/") {
        "/admin/v1/pairing-codes/-"
    } else if path.starts_with("/admin/v1/probe/") {
        "/admin/v1/probe/-"
    } else {
        path.as_str()
    };
    hub.log_request(&method, shown, status);
}

fn refuse(hub: &Hub, req: Request, r: &Refusal) {
    send(
        hub,
        req,
        r.status,
        &json!({ "error": r.code, "message": r.message }),
    );
}

fn read_body(req: &mut Request) -> Result<Vec<u8>, Refusal> {
    let bad = |m: &str| Refusal::new(400, "bad_request", m);
    let mut buf = Vec::new();
    req.as_reader()
        .take(MAX_BODY + 1)
        .read_to_end(&mut buf)
        .map_err(|_| bad("The request couldn't be read."))?;
    if buf.len() as u64 > MAX_BODY {
        return Err(bad("The request is too large."));
    }
    Ok(buf)
}

fn read_json<T: for<'de> Deserialize<'de>>(req: &mut Request) -> Result<T, Refusal> {
    parse_json(&read_body(req)?)
}

/// Like [`read_json`], with an empty body meaning every field left out.
fn read_json_or_empty<T: for<'de> Deserialize<'de> + Default>(
    req: &mut Request,
) -> Result<T, Refusal> {
    let buf = read_body(req)?;
    if buf.iter().all(u8::is_ascii_whitespace) {
        return Ok(T::default());
    }
    parse_json(&buf)
}

fn parse_json<T: for<'de> Deserialize<'de>>(buf: &[u8]) -> Result<T, Refusal> {
    // (the reason names a field, never a value: a body may carry a PIN)
    serde_json::from_slice(buf).map_err(|e| {
        Refusal::new(
            400,
            "bad_request",
            format!(
                "The request isn't valid ({:?} at line {}, column {}).",
                e.classify(),
                e.line(),
                e.column()
            ),
        )
    })
}

fn bearer(req: &Request) -> Option<String> {
    req.headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))
        .and_then(|h| h.value.as_str().strip_prefix("Bearer ").map(str::to_string))
}

#[derive(Deserialize)]
struct NameRequest {
    name: String,
}

#[derive(Deserialize)]
struct MemberRequest {
    name: String,
    #[serde(default)]
    class: Option<String>,
}

#[derive(Deserialize)]
struct ClassRequest {
    class: String,
}

#[derive(Deserialize)]
struct PasswordRequest {
    password: String,
}

/// A grant or a pairing code. (A `pin` sent by an older program is ignored: every grant
/// is an administrator's act and asks for no PIN.)
#[derive(Deserialize)]
struct GrantRequest {
    member: u32,
    app: String,
}

#[derive(Deserialize)]
struct InviteRequest {
    app: String,
    scope: String,
}

#[derive(Deserialize, Default)]
struct NamesOnRequest {
    #[serde(default)]
    registration_code: Option<String>,
}

#[derive(Deserialize)]
struct FixRequest {
    check: u8,
}

#[derive(Deserialize)]
struct HostnameRequest {
    hostname: String,
}

#[derive(Deserialize)]
struct CodePageRequest {
    code_page: String,
}

#[derive(Deserialize)]
struct AdapterRequest {
    adapter: String,
}

/// (An `old` PIN sent by an older program is ignored: the old PIN is not needed.)
#[derive(Deserialize)]
struct PinRequest {
    pin: String,
}

fn session(req: &Request) -> Option<String> {
    req.headers()
        .iter()
        .find(|h| h.field.equiv(SESSION_HEADER))
        .map(|h| h.value.as_str().to_string())
}

pub(crate) fn handle(hub: &Arc<Hub>, mut req: Request) {
    let ok = bearer(&req).is_some_and(|t| util::ct_eq(t.as_bytes(), hub.admin_token.as_bytes()));
    if !ok {
        let r = Refusal::new(
            401,
            "no_admin_token",
            "The admin token is missing or wrong.",
        );
        return refuse(hub, req, &r);
    }
    let path = req.url().split('?').next().unwrap_or("").to_string();
    let method = req.method().as_str().to_string();
    let parts: Vec<String> = path
        .strip_prefix("/admin/v1/")
        .unwrap_or("")
        .split('/')
        .map(util::percent_decode)
        .collect();
    let parts: Vec<&str> = parts.iter().map(String::as_str).collect();
    match call(hub, &mut req, &method, &parts) {
        Ok(v) => send(hub, req, 200, &v),
        Err(r) => refuse(hub, req, &r),
    }
}

fn number(text: &str) -> Result<u32, Refusal> {
    text.parse()
        .map_err(|_| Refusal::new(404, "not_found", "There is nothing at that address."))
}

fn found(was: bool, code: &'static str, message: &str) -> Result<Value, Refusal> {
    if was {
        Ok(json!({ "ok": true }))
    } else {
        Err(Refusal::new(404, code, message))
    }
}

fn call(hub: &Arc<Hub>, req: &mut Request, method: &str, parts: &[&str]) -> Result<Value, Refusal> {
    let now = hub.now();
    if let ("POST", ["setup"]) = (method, parts) {
        let b: SetupRequest = read_json(req)?;
        return hub.first_setup(&b);
    }
    // Until the first set-up the hub accepts nothing else.
    hub.needs_setup()?;
    let session = session(req);
    // Any request that carries a live session restarts its minutes (owner decision
    // 2026-11-19: the app is open and in use). One that isn't live is ignored here.
    if session.is_some() {
        let _ = hub.administrator(session.as_deref());
    }
    // A request marked A: an administrator's live session, or an open household.
    let need = || hub.acting_administrator(session.as_deref());
    match (method, parts) {
        ("POST", ["session"]) => {
            let b: SignInRequest = read_json(req)?;
            hub.sign_in(&b)
        }
        ("POST", ["secure"]) => {
            let b: SecureRequest = read_json(req)?;
            hub.secure(&b)
        }
        ("DELETE", ["session"]) => {
            hub.sign_out(session.as_deref());
            Ok(json!({ "ok": true }))
        }

        ("GET", ["status"]) => hub.status(),

        ("GET", ["apps"]) => {
            let apps = hub.lock().registry.apps().map_err(Refusal::inner)?;
            Ok(json!({ "apps": apps }))
        }
        ("POST", ["apps"]) => {
            let r: Registration = read_json(req)?;
            // (asked only when the app is new or changes its `pairing`: an update needs the
            // token alone)
            let administrator = need().is_ok();
            hub.register(&r, administrator)
        }
        ("DELETE", ["apps", id]) => {
            need()?;
            hub.unregister(id).map(|()| json!({ "ok": true }))
        }

        ("GET", ["members"]) => {
            let members = hub.lock().registry.members().map_err(Refusal::inner)?;
            Ok(json!({ "members": members }))
        }
        ("POST", ["members"]) => {
            need()?;
            let b: MemberRequest = read_json(req)?;
            hub.add_member(&b.name, b.class.as_deref())
        }
        ("PUT", ["members", id]) => {
            need()?;
            let id = number(id)?;
            let b: NameRequest = read_json(req)?;
            hub.rename_member(id, &b.name)
        }
        ("PUT", ["members", id, "class"]) => {
            need()?;
            let id = number(id)?;
            let b: ClassRequest = read_json(req)?;
            hub.set_class(id, &b.class)
        }
        ("PUT", ["members", id, "password"]) => {
            need()?;
            let id = number(id)?;
            let b: PasswordRequest = read_json(req)?;
            hub.set_password(id, &b.password, session.as_deref())
        }
        ("DELETE", ["members", id]) => {
            need()?;
            let id = number(id)?;
            hub.remove_member(id)
        }

        ("GET", ["grants"]) => {
            let grants = hub.lock().registry.grants().map_err(Refusal::inner)?;
            Ok(json!({ "grants": grants }))
        }
        ("POST", ["grants"]) => {
            need()?;
            let b: GrantRequest = read_json(req)?;
            hub.give_grant(b.member, &b.app)?;
            Ok(json!({ "ok": true }))
        }
        ("DELETE", ["grants", member, app]) => {
            need()?;
            let member = number(member)?;
            let was = hub
                .lock()
                .registry
                .remove_grant(member, app)
                .map_err(Refusal::inner)?;
            found(
                was,
                "no_such_grant",
                "That person doesn't have access to that app.",
            )
        }

        ("GET", ["devices"]) => {
            let devices = hub.lock().registry.devices().map_err(Refusal::inner)?;
            Ok(json!({ "devices": devices }))
        }
        ("DELETE", ["devices", id]) => {
            need()?;
            let id = number(id)?;
            let was = hub
                .lock()
                .registry
                .revoke_device(id, now)
                .map_err(Refusal::inner)?;
            found(
                was,
                "no_such_device",
                "That phone isn't paired (or was already removed).",
            )
        }

        ("POST", ["pairing-codes"]) => {
            need()?;
            let b: GrantRequest = read_json(req)?;
            hub.make_code(b.member, &b.app)
        }
        ("DELETE", ["pairing-codes", code]) => {
            need()?;
            found(
                hub.cancel_code(code),
                "no_such_code",
                "That pairing code isn't in use.",
            )
        }

        ("GET", ["invites"]) => {
            let invites = hub.lock().registry.invites().map_err(Refusal::inner)?;
            Ok(json!({ "invites": invites }))
        }
        ("POST", ["invites"]) => {
            need()?;
            let b: InviteRequest = read_json(req)?;
            hub.make_invite(&b.app, &b.scope)
        }
        ("DELETE", ["invites", id]) => {
            need()?;
            let id = number(id)?;
            let was = hub
                .lock()
                .registry
                .remove_invite(id)
                .map_err(Refusal::inner)?;
            found(was, "no_such_invite", "That invite isn't in use.")
        }

        ("GET", ["pin"]) => {
            let set = hub
                .lock()
                .registry
                .get(PIN_KEY)
                .map_err(Refusal::inner)?
                .is_some();
            Ok(json!({ "set": set }))
        }
        ("PUT", ["pin"]) => {
            need()?;
            let b: PinRequest = read_json(req)?;
            hub.set_pin(&b.pin)?;
            Ok(json!({ "ok": true }))
        }

        ("GET", ["names"]) => Ok(hub.names.status()),
        ("POST", ["names", "address"]) => {
            hub.names.resend_address();
            Ok(json!({ "ok": true }))
        }
        ("GET", ["addresses"]) => {
            let cfg = crate::config::HubConfig::load(&hub.data).map_err(Refusal::inner)?;
            Ok(json!({
                "current": hub.address(),
                "adapter": cfg.address.adapter,
                "addresses": hub.machine.addresses(),
            }))
        }
        ("PUT", ["address"]) => {
            need()?;
            let b: AdapterRequest = read_json(req)?;
            hub.choose_adapter(&b.adapter)
                .map_err(|m| Refusal::new(400, "bad_adapter", m))?;
            Ok(json!({ "current": hub.address() }))
        }
        ("POST", ["problems"]) => {
            let results = crate::problems::run(hub);
            hub.lock().problems = Some(results.clone());
            Ok(results)
        }
        ("POST", ["problems", "fix"]) => {
            need()?;
            let b: FixRequest = read_json(req)?;
            crate::problems::fix(hub, b.check)
        }
        ("POST", ["probe"]) => {
            need()?;
            hub.issue_probe()
        }
        ("GET", ["probe", nonce]) => hub.probe_seen(nonce),
        ("PUT", ["tunnel"]) => {
            need()?;
            let b: HostnameRequest = read_json(req)?;
            Ok(json!({ "hostname": hub.set_tunnel_hostname(&b.hostname)? }))
        }
        ("DELETE", ["tunnel"]) => {
            need()?;
            Ok(json!({ "hostname": hub.set_tunnel_hostname("")? }))
        }
        ("PUT", ["tunnel", "moneykeep-name"]) => {
            need()?;
            hub.make_moneykeep_tunnel()
        }
        ("DELETE", ["tunnel", "moneykeep-name"]) => {
            need()?;
            hub.remove_moneykeep_tunnel()
        }
        ("GET", ["problems"]) => Ok(hub
            .lock()
            .problems
            .clone()
            .unwrap_or_else(|| json!({ "checks": [], "stopped_at": null, "at": null }))),
        ("POST", ["names", "on"]) => {
            need()?;
            let b: NamesOnRequest = read_json_or_empty(req)?;
            hub.names
                .turn_on(b.registration_code.as_deref())
                .map_err(|m| Refusal::new(409, "names_refused", m))?;
            Ok(hub.names.status())
        }
        ("POST", ["names", "off"]) => {
            need()?;
            hub.names.turn_off().map_err(Refusal::inner)?;
            Ok(hub.names.status())
        }
        ("PUT", ["names", "code-page"]) => {
            need()?;
            let b: CodePageRequest = read_json(req)?;
            hub.names
                .set_code_page(&b.code_page)
                .map_err(|m| Refusal::new(400, "bad_code_page", m))?;
            Ok(hub.names.status())
        }
        ("POST", ["names", "renew"]) => {
            need()?;
            hub.names
                .renew_now()
                .map_err(|m| Refusal::new(409, "names_off", m))?;
            Ok(hub.names.status())
        }

        _ => Err(Refusal::new(
            404,
            "not_found",
            "There is nothing at that address.",
        )),
    }
}
