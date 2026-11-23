//! The app ports: each registered app's public port, where phones connect over TLS.
//! Started from the TLS relay of ShareKeep's hub (`wifi.rs`: the accept loop, the
//! connection limits and the gate for requests without a token), then changed so the hub
//! reads each request's head itself, because here it must decide by path who answers:
//!
//! | Path | Who answers | Needs a device token |
//! |---|---|---|
//! | `/hub/pair` (POST) | the hub: pairing | no |
//! | `/hub/whoami` (GET) | the hub | yes |
//! | `/hub/check` (GET) | the hub: a fixed short answer | no |
//! | `/api/...` | the app's backend | yes, with a grant for this app |
//! | anything else, GET or HEAD only | the app's backend: the web client's files | no |
//!
//! A request passed to a backend has every `Keep-` header and the `Authorization` header a
//! phone sent removed, and the hub's own `Keep-` headers added. The hub reads one request
//! per connection and closes after the answer (`Connection: close` both ways), so nothing
//! reaches a backend that the hub didn't check. Request bodies need `Content-Length`.
//!
//! The limits are ShareKeep's: at most 64 connections and 8 from one address per app port;
//! a request head must arrive within 10 seconds; requests without a token that send a body
//! (pairing) take one of 2 waiting places.
//!
//! Web clients (stage 2): answers are streamed through one buffer, whatever their size, so
//! the hub's memory doesn't grow with a file; a transfer is closed only after [`IDLE`] with
//! no bytes moving. `Accept-Encoding`, `Content-Encoding`, `Content-Type`, `ETag`,
//! `If-None-Match`, `Cache-Control`, 304 answers and the app's own security policy pass
//! through untouched: the hub never compresses, decompresses or caches. It adds its own
//! headers ([`http::HUB_HEADERS`]) to every answer.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::json;

use crate::http::{self, Answer, Head, LengthError};
use crate::hub::{Hub, Identity, Refusal, PROTOCOLS, VERSION};
use crate::probe::{self, Arrived};
use crate::util;

/// Phones connected at once to one app port (each connection has a thread).
pub const MAX_CONNECTIONS: usize = 64;
/// Connections at once from one address, on each app port.
pub const MAX_PER_ADDRESS: usize = 8;
/// Requests without a token that send a body (pairing) handled at once, in all.
pub const MAX_UNAUTH: usize = 2;
/// Such requests handled at once from one address.
pub const MAX_UNAUTH_PER_ADDRESS: usize = 1;
/// The TLS handshake must be done in this time.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// A request's head must arrive in this time; so must the body of a request without a token.
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
/// The largest body of a pairing request.
const MAX_PAIR_BODY: u64 = 4096;
/// An app's backend is on this computer: it accepts at once or it isn't running.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a backend may take to start its answer (an app may need time to work out a
/// report; a file starts at once).
pub const FIRST_BYTE: Duration = Duration::from_secs(120);
/// A transfer with no bytes moving for this long is closed, either way. A transfer that
/// keeps moving has no time limit, however large (a WASM client is several megabytes).
pub const IDLE: Duration = Duration::from_secs(30);
/// The largest answer head a backend may send.
const MAX_ANSWER_HEAD: usize = 64 * 1024;

type Tls = rustls::StreamOwned<rustls::ServerConnection, TcpStream>;

/// Admits requests without a token that send a body: at most [`MAX_UNAUTH`] at a time, and
/// [`MAX_UNAUTH_PER_ADDRESS`] from one address (copied from ShareKeep's hub).
#[derive(Debug, Default)]
pub struct Gate {
    open: Mutex<HashMap<IpAddr, usize>>,
}

/// An admitted request; its place is given back when dropped.
#[derive(Debug)]
pub struct Ticket {
    gate: Arc<Gate>,
    ip: IpAddr,
}

impl Gate {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// A place for a request from `ip`, or `None` when the limits are reached.
    pub fn admit(self: &Arc<Self>, ip: IpAddr) -> Option<Ticket> {
        let mut m = self.open.lock().ok()?;
        let total: usize = m.values().sum();
        let mine = m.get(&ip).copied().unwrap_or(0);
        if total >= MAX_UNAUTH || mine >= MAX_UNAUTH_PER_ADDRESS {
            return None;
        }
        m.insert(ip, mine + 1);
        Some(Ticket {
            gate: self.clone(),
            ip,
        })
    }

    /// Requests admitted now.
    pub fn open(&self) -> usize {
        self.open.lock().map(|m| m.values().sum()).unwrap_or(0)
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if let Ok(mut m) = self.gate.open.lock() {
            if let Some(n) = m.get_mut(&self.ip) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    m.remove(&self.ip);
                }
            }
        }
    }
}

/// One connection's place in the per-address count; given back when dropped.
pub(crate) struct Slot {
    per: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl Slot {
    pub(crate) fn take(per: &Arc<Mutex<HashMap<IpAddr, usize>>>, ip: IpAddr) -> Option<Slot> {
        let mut m = per.lock().ok()?;
        let n = m.entry(ip).or_default();
        if *n >= MAX_PER_ADDRESS {
            return None;
        }
        *n += 1;
        Some(Slot {
            per: per.clone(),
            ip,
        })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        if let Ok(mut m) = self.per.lock() {
            if let Some(n) = m.get_mut(&self.ip) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    m.remove(&self.ip);
                }
            }
        }
    }
}

/// Accept connections on `app`'s public port until the hub stops or the port is closed
/// (`stop`); each connection carries one request.
///
/// The loop waits in `accept` itself, so a phone's connection is taken at once (ShareKeep's
/// loop looked every 50 milliseconds, which, with one request per connection, delayed every
/// file). Closing the port sets `stop` and connects once to wake it ([`wake`]).
pub(crate) fn accept_loop(
    listener: TcpListener,
    hub: Arc<Hub>,
    app: String,
    stop: Arc<AtomicBool>,
    arrived: Arrived,
) {
    let active = Arc::new(AtomicUsize::new(0));
    let per = Arc::new(Mutex::new(HashMap::<IpAddr, usize>::new()));
    if listener.set_nonblocking(false).is_err() {
        return;
    }
    loop {
        let accepted = listener.accept();
        if hub.stopping.load(Ordering::SeqCst) || stop.load(Ordering::SeqCst) {
            return;
        }
        match accepted {
            Ok((tcp, peer)) => {
                if active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                    drop(tcp);
                    continue;
                }
                // On the tunnel's loopback listener every connection comes from the
                // connector: its place is counted by the visitor's address, once the head
                // says it (owner decision 2026-11-22).
                let slot = match arrived {
                    Arrived::Home => match Slot::take(&per, peer.ip()) {
                        Some(s) => Some(s),
                        None => {
                            drop(tcp);
                            continue;
                        }
                    },
                    Arrived::Loopback => None,
                };
                active.fetch_add(1, Ordering::SeqCst);
                let (hub, app, act, per) = (hub.clone(), app.clone(), active.clone(), per.clone());
                let spawned = std::thread::Builder::new()
                    .name("hub-tls".into())
                    .spawn(move || {
                        let _slot = slot;
                        let _ = serve(tcp, peer, &hub, &app, arrived, &per);
                        act.fetch_sub(1, Ordering::SeqCst);
                    });
                if spawned.is_err() {
                    active.fetch_sub(1, Ordering::SeqCst);
                }
            }
            // (e.g. too many open files: wait a moment rather than spin)
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

/// Wake an accept loop waiting on `addr` so it sees its stop flag: one connection that
/// sends nothing. `false` when nothing could connect (the loop then ends with the next
/// connection it accepts).
pub(crate) fn wake(addr: SocketAddr) -> bool {
    let to = match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::from((Ipv4Addr::LOCALHOST, addr.port()))
        }
        _ => addr,
    };
    TcpStream::connect_timeout(&to, Duration::from_secs(2)).is_ok()
}

fn io_err(e: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// Let the next read wait until `until` at most.
fn read_until(tcp: &TcpStream, until: Instant) -> std::io::Result<()> {
    let left = until.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "the request took too long",
        ));
    }
    tcp.set_read_timeout(Some(left))
}

/// Whether this phone asked for the hub name and got its real certificate (then HSTS).
fn by_name(hub: &Hub, tls: &Tls) -> bool {
    hub.resolver.trusted_name(tls.conn.server_name())
}

/// Send one of the hub's own answers and close.
fn finish(hub: &Hub, tls: &mut Tls, method: &str, path: &str, a: &Answer) -> std::io::Result<()> {
    hub.log_request(method, path, a.status);
    let hsts = by_name(hub, tls);
    tls.write_all(&a.to_bytes(method == "HEAD", hsts))?;
    close(tls)
}

fn refuse(hub: &Hub, tls: &mut Tls, head: &Head, r: &Refusal) -> std::io::Result<()> {
    let a = Answer::error(r.status, r.code, &r.message);
    finish(hub, tls, &head.method, head.path(), &a)
}

/// End the TLS connection properly, so the phone knows the answer is whole.
fn close(tls: &mut Tls) -> std::io::Result<()> {
    tls.conn.send_close_notify();
    tls.flush()?;
    let _ = tls.sock.shutdown(Shutdown::Write);
    Ok(())
}

/// A path without a token is passed on only when it can be read one way: no `..`, no empty
/// or dot segments, no backslash, and nothing that decodes to an `/api` or `/hub` path
/// (which a backend might treat as one, though the hub didn't check a token for it).
fn plain_path(path: &str) -> bool {
    let decoded = util::percent_decode(path);
    if decoded.contains('\\') || decoded.chars().any(char::is_control) {
        return false;
    }
    let mut segments = decoded.split('/').skip(1).peekable();
    let first = segments.peek().map(|s| s.to_ascii_lowercase());
    if first.is_some_and(|f| f == "api" || f == "hub") {
        return false;
    }
    let all: Vec<&str> = segments.collect();
    let last = all.len().saturating_sub(1);
    all.iter()
        .enumerate()
        .all(|(i, s)| *s != ".." && *s != "." && (!s.is_empty() || i == last))
}

/// A request id a phone sent, if it can be passed on: up to 128 letters, digits and `-._:~`.
fn request_id(head: &Head) -> Option<&str> {
    head.header("keep-request-id").filter(|v| {
        !v.is_empty()
            && v.len() <= 128
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._:~".contains(&b))
    })
}

/// The head sent to an app's backend: the phone's request line and headers, without any
/// `Keep-` header, `Authorization`, or per-connection header, and with the hub's own.
fn forward_head(head: &Head, secret: &str, who: Option<&Identity>) -> Vec<u8> {
    // headers the phone named as for this connection only (RFC 9110 section 7.6.1)
    let named: Vec<String> = head
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .collect();
    let mut out = format!("{} {} HTTP/1.1\r\n", head.method, head.target);
    for (k, v) in &head.headers {
        let name = k.to_ascii_lowercase();
        let dropped = name.starts_with("keep-")
            || [
                "authorization",
                "proxy-authorization",
                "connection",
                "proxy-connection",
                "upgrade",
                "expect",
                "te",
                "trailer",
            ]
            .contains(&name.as_str())
            || named.contains(&name);
        if !dropped {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
    }
    out.push_str(&format!("Keep-Hub-Auth: {secret}\r\n"));
    if let Some(id) = who {
        out.push_str(&format!("Keep-Member: {}\r\n", id.member.id));
        out.push_str(&format!("Keep-Member-Class: {}\r\n", id.member.class));
        out.push_str(&format!(
            "Keep-Member-Name: {}\r\n",
            util::percent_encode(&id.member.name)
        ));
        out.push_str(&format!("Keep-Device: {}\r\n", id.device.id));
        out.push_str(&format!(
            "Keep-Device-Name: {}\r\n",
            util::percent_encode(&id.device.name)
        ));
        if let Some(scope) = &id.member.guest_scope {
            out.push_str(&format!("Keep-Guest-Scope: {scope}\r\n"));
        }
        if let Some(rid) = request_id(head) {
            out.push_str(&format!("Keep-Request-Id: {rid}\r\n"));
        }
    }
    out.push_str("Connection: close\r\n\r\n");
    out.into_bytes()
}

/// One phone connection: the TLS handshake, one request, its answer.
/// The address a request's limits are counted by: the phone's own, or, on the tunnel's
/// loopback listener, the visitor's address Cloudflare's connector sends (owner decision
/// 2026-11-22: phones away from home don't share one address's limits). The header is
/// believed only there, never on the home address.
pub(crate) fn visitor(peer: IpAddr, arrived: Arrived, head: &Head) -> IpAddr {
    match arrived {
        Arrived::Home => peer,
        Arrived::Loopback => head
            .header(probe::CLOUDFLARE_HEADER)
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
            .unwrap_or(peer),
    }
}

fn serve(
    tcp: TcpStream,
    peer: SocketAddr,
    hub: &Arc<Hub>,
    app: &str,
    arrived: Arrived,
    per: &Arc<Mutex<HashMap<IpAddr, usize>>>,
) -> std::io::Result<()> {
    tcp.set_nonblocking(false)?;
    tcp.set_write_timeout(Some(hub.idle))?;
    let _ = tcp.set_nodelay(true);
    let conn = rustls::ServerConnection::new(hub.tls.clone()).map_err(io_err)?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    let until = Instant::now() + HANDSHAKE_TIMEOUT;
    while tls.conn.is_handshaking() {
        read_until(&tls.sock, until)?;
        tls.conn.complete_io(&mut tls.sock)?;
    }

    // the request's head
    let until = Instant::now() + HEAD_TIMEOUT;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 8 * 1024];
    let end = loop {
        if let Some(end) = http::head_end(&buf) {
            break end;
        }
        if buf.len() >= http::MAX_HEAD {
            let a = Answer::error(
                431,
                "head_too_large",
                "The request's headers are too large.",
            );
            return finish(hub, &mut tls, "-", "-", &a);
        }
        read_until(&tls.sock, until)?;
        match tls.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(n) => buf.extend_from_slice(chunk.get(..n).unwrap_or(&[])),
            Err(e) => return Err(e),
        }
    };
    let rest: Vec<u8> = buf.get(end + 4..).unwrap_or(&[]).to_vec();
    let Some(head) = Head::parse(buf.get(..end).unwrap_or(&[])) else {
        let a = Answer::error(400, "bad_request", "The request can't be read.");
        return finish(hub, &mut tls, "-", "-", &a);
    };
    let path = head.path().to_string();
    let method = head.method.as_str();
    let visitor = visitor(peer.ip(), arrived, &head);
    let _slot = match arrived {
        Arrived::Home => None,
        Arrived::Loopback => match Slot::take(per, visitor) {
            Some(s) => Some(s),
            None => {
                let a = Answer::error(503, "busy", "The hub is busy: try again in a moment.");
                return finish(hub, &mut tls, method, &path, &a);
            }
        },
    };

    // the probe (Revision 4 A): answered here, never forwarded. Nothing but the request
    // line is read, except on the tunnel's loopback listener, where only whether
    // Cloudflare's header is present counts.
    if let Some(nonce) = probe::nonce_of(&head.target) {
        let status = if method == "GET" {
            let cloudflare =
                arrived == Arrived::Loopback && head.header(probe::CLOUDFLARE_HEADER).is_some();
            hub.probe_request(nonce, peer.ip(), visitor, arrived, cloudflare)
        } else {
            404
        };
        hub.log_request(method, "/_probe/-", status);
        tls.write_all(&http::empty_answer(status, by_name(hub, &tls)))?;
        return close(&mut tls);
    }

    // who answers
    if path == "/hub" || path.starts_with("/hub/") {
        return match (method, path.as_str()) {
            ("GET" | "HEAD", "/hub/check") => {
                // (Revision 4: the probe path and the tunnel's hostname, for an app to show)
                let a = Answer::ok(json!({
                    "hub": "keep-hub",
                    "ok": true,
                    "probe": format!("{}<nonce>", probe::PREFIX),
                    "tunnel_hostname": hub.tunnel_hostname(),
                }));
                finish(hub, &mut tls, method, &path, &a)
            }
            ("GET", "/hub/whoami") => {
                let who = head
                    .bearer()
                    .ok_or_else(Refusal::not_paired)
                    .and_then(|t| hub.authorise(app, t));
                match who {
                    Ok(id) => {
                        let title = hub.backend(app).map(|(a, _)| a.title);
                        let a = Answer::ok(json!({
                            "member": {
                                "id": id.member.id,
                                "name": id.member.name,
                                "class": id.member.class,
                            },
                            "device": { "id": id.device.id, "name": id.device.name },
                            "guest_scope": id.member.guest_scope,
                            "app": { "id": app, "title": title },
                            "hub": { "version": VERSION, "protocols": PROTOCOLS },
                        }));
                        finish(hub, &mut tls, method, &path, &a)
                    }
                    Err(r) => refuse(hub, &mut tls, &head, &r),
                }
            }
            ("POST", "/hub/pair") => pair(hub, &mut tls, &head, rest, visitor, app),
            // The person removes the app from this phone: its own device is revoked.
            ("POST", "/hub/unpair") => {
                let done = head
                    .bearer()
                    .ok_or_else(Refusal::not_paired)
                    .and_then(|t| hub.unpair(app, t));
                match done {
                    Ok(()) => {
                        let a = Answer::ok(json!({ "ok": true }));
                        finish(hub, &mut tls, method, &path, &a)
                    }
                    Err(r) => refuse(hub, &mut tls, &head, &r),
                }
            }
            _ => {
                let a = Answer::error(404, "not_found", "The hub has nothing at that address.");
                finish(hub, &mut tls, method, &path, &a)
            }
        };
    }
    let who = if path == "/api" || path.starts_with("/api/") {
        let who = head
            .bearer()
            .ok_or_else(Refusal::not_paired)
            .and_then(|t| hub.authorise(app, t));
        match who {
            Ok(id) => Some(id),
            // the app's backend is not contacted
            Err(r) => return refuse(hub, &mut tls, &head, &r),
        }
    } else if method != "GET" && method != "HEAD" {
        let a = Answer::error(
            405,
            "method_not_allowed",
            "Only an app's /api/ addresses take anything but GET.",
        );
        return finish(hub, &mut tls, method, &path, &a);
    } else if !plain_path(&path) {
        let a = Answer::error(400, "bad_path", "That address can't be used.");
        return finish(hub, &mut tls, method, &path, &a);
    } else {
        None
    };
    forward(hub, &mut tls, &head, rest, app, who.as_ref())
}

/// `/hub/pair`: a place at the gate, the small body within the time limit, then the
/// pairing rules.
fn pair(
    hub: &Arc<Hub>,
    tls: &mut Tls,
    head: &Head,
    mut body: Vec<u8>,
    ip: IpAddr,
    app: &str,
) -> std::io::Result<()> {
    let len = match head.content_length() {
        Ok(n) if n <= MAX_PAIR_BODY => n as usize,
        Ok(_) => {
            let r = Refusal::new(413, "too_large", "The request is too large.");
            return refuse(hub, tls, head, &r);
        }
        Err(_) => {
            let r = Refusal::new(411, "length_needed", "The request must say how long it is.");
            return refuse(hub, tls, head, &r);
        }
    };
    let Some(_ticket) = hub.gate.admit(ip) else {
        let r = Refusal::new(503, "busy", "The hub is busy: try again in a moment.");
        return refuse(hub, tls, head, &r);
    };
    let until = Instant::now() + HEAD_TIMEOUT;
    let mut chunk = vec![0u8; 4096];
    while body.len() < len {
        read_until(&tls.sock, until)?;
        match tls.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(n) => body.extend_from_slice(chunk.get(..n).unwrap_or(&[])),
            Err(e) => return Err(e),
        }
    }
    body.truncate(len);
    match hub.pair(app, &body, ip) {
        Ok(v) => finish(hub, tls, &head.method, head.path(), &Answer::ok(v)),
        Err(r) => refuse(hub, tls, head, &r),
    }
}

/// Pass a checked request to the app's backend on its loopback port and its answer back,
/// streaming both: nothing is held in memory but one buffer.
fn forward(
    hub: &Arc<Hub>,
    tls: &mut Tls,
    head: &Head,
    rest: Vec<u8>,
    app: &str,
    who: Option<&Identity>,
) -> std::io::Result<()> {
    let len = match head.content_length() {
        Ok(n) => n,
        Err(LengthError::Chunked) => {
            let r = Refusal::new(
                411,
                "length_needed",
                "The request must say how long it is (Content-Length).",
            );
            return refuse(hub, tls, head, &r);
        }
        Err(LengthError::Unclear) => {
            let r = Refusal::new(400, "bad_request", "The request can't be read.");
            return refuse(hub, tls, head, &r);
        }
    };
    if who.is_none() && len > 0 {
        // without a token only pairing sends a body (acceptance test 36: a GET with a body
        // is refused as a POST is)
        let r = Refusal::new(
            405,
            "method_not_allowed",
            "Without a paired phone's token, only GET and HEAD without a body pass.",
        );
        return refuse(hub, tls, head, &r);
    }
    let stopped = || {
        Refusal::new(
            503,
            "app_stopped",
            "This app isn't running on the hub computer right now. Try again in a moment.",
        )
    };
    let Some((info, secret)) = hub.backend(app) else {
        return refuse(hub, tls, head, &stopped());
    };
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, info.loopback_port));
    let Ok(mut backend) = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) else {
        return refuse(hub, tls, head, &stopped());
    };
    backend.set_write_timeout(Some(hub.idle))?;
    let _ = backend.set_nodelay(true);
    let failed = || Refusal::new(502, "app_failed", "This app didn't answer properly.");

    // the request: the head, then exactly the body it announced
    let mut chunk = vec![0u8; 64 * 1024];
    let sent = (|| -> std::io::Result<()> {
        backend.write_all(&forward_head(head, &secret, who))?;
        let first = rest.get(..rest.len().min(len as usize)).unwrap_or(&[]);
        backend.write_all(first)?;
        let mut left = len - first.len() as u64;
        tls.sock.set_read_timeout(Some(hub.idle))?;
        while left > 0 {
            let want = chunk.len().min(left as usize);
            let n = tls.read(chunk.get_mut(..want).unwrap_or(&mut []))?;
            if n == 0 {
                return Err(io_err("the phone stopped sending"));
            }
            backend.write_all(chunk.get(..n).unwrap_or(&[]))?;
            left -= n as u64;
        }
        backend.flush()
    })();
    if sent.is_err() && len == 0 {
        return refuse(hub, tls, head, &stopped());
    }
    // (a backend may answer before it has read a whole body; so go on to its answer)

    // the answer's head
    backend.set_read_timeout(Some(hub.first_byte))?;
    let mut buf: Vec<u8> = Vec::new();
    let end = loop {
        if let Some(end) = http::head_end(&buf) {
            break end;
        }
        if buf.len() >= MAX_ANSWER_HEAD {
            return refuse(hub, tls, head, &failed());
        }
        match backend.read(&mut chunk) {
            Ok(n) if n > 0 => buf.extend_from_slice(chunk.get(..n).unwrap_or(&[])),
            _ => return refuse(hub, tls, head, &failed()),
        }
    };
    let hsts = by_name(hub, tls);
    let Some((status, answer)) = http::answer_head(buf.get(..end).unwrap_or(&[]), hsts) else {
        return refuse(hub, tls, head, &failed());
    };
    hub.log_request(&head.method, head.path(), status);
    tls.write_all(&answer)?;
    tls.write_all(buf.get(end + 4..).unwrap_or(&[]))?;

    // the answer's body, as it comes, until the backend closes
    backend.set_read_timeout(Some(hub.idle))?;
    loop {
        match backend.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => tls.write_all(chunk.get(..n).unwrap_or(&[]))?,
            // cut short: close without the TLS goodbye, so the phone can tell
            Err(e) => {
                let _ = tls.sock.shutdown(Shutdown::Both);
                return Err(e);
            }
        }
    }
    close(tls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{Device, Member};

    fn head(text: &str) -> Head {
        Head::parse(text.as_bytes()).unwrap()
    }

    #[test]
    fn the_gate_admits_two_in_all_and_one_per_address() {
        let gate = Gate::new();
        let a: IpAddr = "192.168.1.5".parse().unwrap();
        let b: IpAddr = "192.168.1.6".parse().unwrap();
        let c: IpAddr = "192.168.1.7".parse().unwrap();
        let first = gate.admit(a).unwrap();
        assert!(gate.admit(a).is_none());
        let _second = gate.admit(b).unwrap();
        assert!(gate.admit(c).is_none());
        assert_eq!(gate.open(), 2);
        drop(first);
        assert!(gate.admit(c).is_some());
        assert_eq!(gate.open(), 1);
    }

    #[test]
    fn at_most_eight_connections_from_one_address() {
        let per = Arc::new(Mutex::new(HashMap::new()));
        let ip: IpAddr = "192.168.1.5".parse().unwrap();
        let mut held: Vec<Slot> = (0..MAX_PER_ADDRESS)
            .map(|_| Slot::take(&per, ip).unwrap())
            .collect();
        assert!(Slot::take(&per, ip).is_none());
        assert!(Slot::take(&per, "192.168.1.6".parse().unwrap()).is_some());
        held.pop();
        assert!(Slot::take(&per, ip).is_some());
    }

    #[test]
    fn only_plain_paths_pass_without_a_token() {
        for ok in [
            "/",
            "/index.html",
            "/assets/app-1.2.wasm",
            "/a/b/",
            "/apiary",
            "/hubcap.js",
        ] {
            assert!(plain_path(ok), "{ok}");
        }
        for bad in [
            "/../api/x",
            "/a/../api/x",
            "/a/%2e%2e/api",
            "/%61pi/items",
            "/API/items",
            "/Hub/pair",
            "//api/items",
            "/a//b",
            "/a\\..\\api",
            "/a/./b",
            "/a%0d%0ab",
        ] {
            assert!(!plain_path(bad), "{bad}");
        }
    }

    #[test]
    fn a_forwarded_head_carries_the_hubs_headers_and_none_of_the_phones() {
        let h = head(
            "POST /api/items?x=1 HTTP/1.1\r\nHost: 192.168.1.20:16443\r\nAuthorization: Bearer device-token\r\nKeep-Member: 1\r\nKeep-Member-Class: administrator\r\nkeep-hub-auth: guess\r\nKeep-Alive: timeout=5\r\nConnection: keep-alive, X-Hop\r\nX-Hop: 1\r\nKeep-Request-Id: req-42\r\nContent-Type: application/json\r\nContent-Length: 2",
        );
        let who = Identity {
            member: Member {
                id: 7,
                name: "Zoë".into(),
                guest_app: None,
                guest_scope: None,
                created: 0,
                class: "standard".into(),
                password_set: false,
            },
            device: Device {
                id: 3,
                member: 7,
                app: "alpha".into(),
                name: "Zoë's phone".into(),
                created: 0,
                last_seen: None,
                revoked: None,
            },
        };
        let text = String::from_utf8(forward_head(&h, "the-secret", Some(&who))).unwrap();
        assert_eq!(
            text,
            "POST /api/items?x=1 HTTP/1.1\r\nHost: 192.168.1.20:16443\r\nContent-Type: application/json\r\nContent-Length: 2\r\nKeep-Hub-Auth: the-secret\r\nKeep-Member: 7\r\nKeep-Member-Class: standard\r\nKeep-Member-Name: Zo%C3%AB\r\nKeep-Device: 3\r\nKeep-Device-Name: Zo%C3%AB%27s%20phone\r\nKeep-Request-Id: req-42\r\nConnection: close\r\n\r\n"
        );
        // a web client's file: the shared secret, and nobody's name
        let h = head("GET /app.wasm HTTP/1.1\r\nKeep-Member: 1\r\nKeep-Request-Id: x\r\nAccept-Encoding: br, gzip\r\nIf-None-Match: \"v1\"");
        let text = String::from_utf8(forward_head(&h, "s", None)).unwrap();
        assert_eq!(
            text,
            "GET /app.wasm HTTP/1.1\r\nAccept-Encoding: br, gzip\r\nIf-None-Match: \"v1\"\r\nKeep-Hub-Auth: s\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn a_request_id_that_could_break_a_header_is_left_out() {
        assert_eq!(
            request_id(&head("GET / HTTP/1.1\r\nKeep-Request-Id: a1-B2_c:3")),
            Some("a1-B2_c:3")
        );
        assert_eq!(
            request_id(&head("GET / HTTP/1.1\r\nKeep-Request-Id: a b")),
            None
        );
        let long = format!("GET / HTTP/1.1\r\nKeep-Request-Id: {}", "a".repeat(129));
        assert_eq!(request_id(&head(&long)), None);
        assert_eq!(request_id(&head("GET / HTTP/1.1")), None);
    }
}
