//! The admin address (`http://127.0.0.1:16081`, this computer only), for the apps' desktop
//! programs and for keep-launcher (which lists the registered apps before it removes the
//! hub). Every request needs the admin token from the hub's data folder
//! (`Authorization: Bearer`). Started from the admin listener of ShareKeep's hub
//! (`server.rs`).
//!
//! ```text
//! GET    /admin/v1/status                       hub version, protocol numbers, each app's state
//! GET    /admin/v1/apps                         the registered apps
//! POST   /admin/v1/apps                         register an app; answers with the shared secret
//! DELETE /admin/v1/apps/<id>                    unregister
//! GET    /admin/v1/members                      list
//! POST   /admin/v1/members        {name}        add
//! PUT    /admin/v1/members/<id>   {name}        rename
//! GET    /admin/v1/grants                       list
//! POST   /admin/v1/grants         {member, app, pin?}   give (pin for an app that declared money)
//! DELETE /admin/v1/grants/<member>/<app>        remove
//! GET    /admin/v1/devices                      list
//! DELETE /admin/v1/devices/<id>                 revoke
//! POST   /admin/v1/pairing-codes  {member, app, pin?}   make
//! DELETE /admin/v1/pairing-codes/<code>         cancel
//! GET    /admin/v1/invites                      guest invites not used yet
//! POST   /admin/v1/invites        {app, scope}  make
//! DELETE /admin/v1/invites/<id>                 cancel
//! GET    /admin/v1/pin                          whether a household PIN is set
//! PUT    /admin/v1/pin            {pin, old?}   set, or change with the old one
//! ```
//!
//! Names, certificates and "find the problem" join this list with their stages.

use std::io::Read;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::{json, Value};
use tiny_http::{Header, Request, Response};

use crate::hub::{clean_name, Hub, Refusal, Registration};
use crate::registry::PIN_KEY;
use crate::util;

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
    let shown = match path.strip_prefix("/admin/v1/pairing-codes/") {
        Some(_) => "/admin/v1/pairing-codes/-",
        None => path.as_str(),
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

fn read_json<T: for<'de> Deserialize<'de>>(req: &mut Request) -> Result<T, Refusal> {
    let bad = |m: String| Refusal::new(400, "bad_request", m);
    let mut buf = Vec::new();
    req.as_reader()
        .take(MAX_BODY + 1)
        .read_to_end(&mut buf)
        .map_err(|_| bad("The request couldn't be read.".into()))?;
    if buf.len() as u64 > MAX_BODY {
        return Err(bad("The request is too large.".into()));
    }
    // (the reason names a field, never a value: a body may carry a PIN)
    serde_json::from_slice(&buf).map_err(|e| {
        bad(format!(
            "The request isn't valid ({:?} at line {}, column {}).",
            e.classify(),
            e.line(),
            e.column()
        ))
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
struct GrantRequest {
    member: u32,
    app: String,
    #[serde(default)]
    pin: Option<String>,
}

#[derive(Deserialize)]
struct InviteRequest {
    app: String,
    scope: String,
}

#[derive(Deserialize)]
struct PinRequest {
    pin: String,
    #[serde(default)]
    old: Option<String>,
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
    match (method, parts) {
        ("GET", ["status"]) => hub.status(),

        ("GET", ["apps"]) => {
            let apps = hub.lock().registry.apps().map_err(Refusal::inner)?;
            Ok(json!({ "apps": apps }))
        }
        ("POST", ["apps"]) => {
            let r: Registration = read_json(req)?;
            hub.register(&r)
        }
        ("DELETE", ["apps", id]) => hub.unregister(id).map(|()| json!({ "ok": true })),

        ("GET", ["members"]) => {
            let members = hub.lock().registry.members().map_err(Refusal::inner)?;
            Ok(json!({ "members": members }))
        }
        ("POST", ["members"]) => {
            let b: NameRequest = read_json(req)?;
            let name = clean_name(&b.name, "this person")?;
            let id = hub
                .lock()
                .registry
                .add_member(&name, now)
                .map_err(Refusal::inner)?;
            Ok(json!({ "id": id, "name": name }))
        }
        ("PUT", ["members", id]) => {
            let id = number(id)?;
            let b: NameRequest = read_json(req)?;
            let name = clean_name(&b.name, "this person")?;
            let was = hub
                .lock()
                .registry
                .rename_member(id, &name)
                .map_err(Refusal::inner)?;
            found(
                was,
                "no_such_member",
                "That person isn't in the household's list.",
            )
        }

        ("GET", ["grants"]) => {
            let grants = hub.lock().registry.grants().map_err(Refusal::inner)?;
            Ok(json!({ "grants": grants }))
        }
        ("POST", ["grants"]) => {
            let b: GrantRequest = read_json(req)?;
            hub.give_grant(b.member, &b.app, b.pin.as_deref())?;
            Ok(json!({ "ok": true }))
        }
        ("DELETE", ["grants", member, app]) => {
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
            let b: GrantRequest = read_json(req)?;
            hub.make_code(b.member, &b.app, b.pin.as_deref())
        }
        ("DELETE", ["pairing-codes", code]) => found(
            hub.cancel_code(code),
            "no_such_code",
            "That pairing code isn't in use.",
        ),

        ("GET", ["invites"]) => {
            let invites = hub.lock().registry.invites().map_err(Refusal::inner)?;
            Ok(json!({ "invites": invites }))
        }
        ("POST", ["invites"]) => {
            let b: InviteRequest = read_json(req)?;
            hub.make_invite(&b.app, &b.scope)
        }
        ("DELETE", ["invites", id]) => {
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
            let b: PinRequest = read_json(req)?;
            hub.set_pin(&b.pin, b.old.as_deref())?;
            Ok(json!({ "ok": true }))
        }

        _ => Err(Refusal::new(
            404,
            "not_found",
            "There is nothing at that address.",
        )),
    }
}
