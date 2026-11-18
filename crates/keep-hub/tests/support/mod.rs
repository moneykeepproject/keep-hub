//! What the hub's tests share: a hub in a temporary folder with its keys in memory and a
//! clock the test moves, two kinds of client (a phone over HTTPS trusting only the hub's
//! certificate authority, and an app's desktop program on the admin address), and small
//! test apps: backends on a loopback port that refuse anything without the right
//! `Keep-Hub-Auth` and remember what reached them.
//!
//! Nothing here leaves this computer.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use keep_hub::pin::Cost;
use keep_hub::{HubConfig, HubOptions, KeyStore, Running};
use rustls::pki_types::{CertificateDer, ServerName};
use serde_json::{json, Value};

pub const PIN: &str = "246810";

/// A port for an app's public side: from a range the system doesn't hand out by itself, and
/// never the same one twice in a test run.
pub fn free_port() -> u16 {
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let start = 20_000 + (std::process::id() % 500) as u16 * 16;
    loop {
        let port = start + NEXT.fetch_add(1, Ordering::SeqCst);
        if TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return port;
        }
    }
}

// ----- answers ----------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}", self.text()))
    }

    /// The code of one of the hub's refusals.
    pub fn error(&self) -> String {
        self.json()["error"].as_str().unwrap_or("").to_string()
    }
}

fn parse(answer: &[u8]) -> Reply {
    let split = answer
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no HTTP answer: {:?}", String::from_utf8_lossy(answer)));
    let head = String::from_utf8_lossy(&answer[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .expect("a status");
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    Reply {
        status,
        headers,
        body: answer[split + 4..].to_vec(),
    }
}

fn request(
    method: &str,
    path: &str,
    host: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Vec<u8> {
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    let mut bytes = req.into_bytes();
    bytes.extend_from_slice(body.unwrap_or(&[]));
    bytes
}

/// Bytes sent to an app port over TLS, trusting only `ca_der`; what came back until the
/// hub closed. `Err` when the connection can't be made.
pub fn https_raw(addr: SocketAddr, ca_der: &[u8], bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der.to_vec()))
        .map_err(|e| e.to_string())?;
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let name = ServerName::try_from(addr.ip().to_string()).map_err(|e| e.to_string())?;
    let mut conn =
        rustls::ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())?;
    let mut tcp =
        TcpStream::connect_timeout(&addr, Duration::from_secs(5)).map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| e.to_string())?;
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
    tls.write_all(bytes).map_err(|e| e.to_string())?;
    let mut answer = Vec::new();
    match tls.read_to_end(&mut answer) {
        Ok(_) => {}
        Err(e) if !answer.is_empty() && e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(e) => return Err(e.to_string()),
    }
    Ok(answer)
}

/// A request to the admin address, or straight to a backend (plain HTTP on loopback).
pub fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Reply {
    let mut tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut all = headers.to_vec();
    all.push(("Connection", "close"));
    tcp.write_all(&request(method, path, &addr.to_string(), &all, body))
        .unwrap();
    let mut answer = Vec::new();
    tcp.read_to_end(&mut answer).unwrap();
    parse(&answer)
}

// ----- a test app -------------------------------------------------------------------------------

/// One request that reached a test app's backend.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// It carried the right `Keep-Hub-Auth`.
    pub trusted: bool,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A small app backend on a loopback port. It refuses (403) anything without the secret
/// the hub gave it; `/api/...` answers with what it was sent, anything else with a "file".
pub struct TestApp {
    pub id: String,
    pub port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
    secret: Arc<Mutex<String>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

/// A request as a backend reads it: method, target, headers, body.
type Request = (String, String, Vec<(String, String)>, Vec<u8>);

fn read_request(tcp: &mut TcpStream) -> Option<Request> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        match tcp.read(&mut chunk) {
            Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            _ => return None,
        }
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, target) = (first.next()?.to_string(), first.next()?.to_string());
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let len: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[end + 4..].to_vec();
    while body.len() < len {
        match tcp.read(&mut chunk) {
            Ok(n) if n > 0 => body.extend_from_slice(&chunk[..n]),
            _ => return None,
        }
    }
    Some((method, target, headers, body))
}

impl TestApp {
    pub fn start(id: &str) -> TestApp {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a loopback port");
        Self::on(id, listener)
    }

    /// Start again on the port it had (after `stop`).
    pub fn start_on(id: &str, port: u16, secret: &str) -> TestApp {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).expect("the same port");
        let app = Self::on(id, listener);
        app.set_secret(secret);
        app
    }

    fn on(id: &str, listener: TcpListener) -> TestApp {
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let secret = Arc::new(Mutex::new(String::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (id, seen, secret, stop) =
                (id.to_string(), seen.clone(), secret.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let mut tcp = match listener.accept() {
                        Ok((tcp, _)) => tcp,
                        Err(_) => {
                            std::thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                    };
                    tcp.set_nonblocking(false).unwrap();
                    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    let Some((method, target, headers, body)) = read_request(&mut tcp) else {
                        continue;
                    };
                    let want = secret.lock().unwrap().clone();
                    let got: Vec<&str> = headers
                        .iter()
                        .filter(|(k, _)| k.eq_ignore_ascii_case("keep-hub-auth"))
                        .map(|(_, v)| v.as_str())
                        .collect();
                    let trusted = !want.is_empty() && got == [want.as_str()];
                    let (status, kind, out) = if !trusted {
                        ("403 Forbidden", "text/plain", b"refused".to_vec())
                    } else if target.starts_with("/api/") {
                        let all: serde_json::Map<String, Value> = headers
                            .iter()
                            .map(|(k, v)| (k.to_ascii_lowercase(), json!(v)))
                            .collect();
                        let v = json!({
                            "app": id,
                            "target": target,
                            "headers": all,
                            "body": String::from_utf8_lossy(&body),
                        });
                        (
                            "200 OK",
                            "application/json",
                            serde_json::to_vec(&v).unwrap(),
                        )
                    } else {
                        (
                            "200 OK",
                            "text/plain",
                            format!("{id} file {target}").into_bytes(),
                        )
                    };
                    seen.lock().unwrap().push(Seen {
                        method: method.clone(),
                        target,
                        headers,
                        body,
                        trusted,
                    });
                    // (says keep-alive on purpose: the hub must still close after each answer)
                    let head = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: keep-alive\r\nX-App: {id}\r\n\r\n",
                        out.len()
                    );
                    let _ = tcp.write_all(head.as_bytes());
                    if method != "HEAD" {
                        let _ = tcp.write_all(&out);
                    }
                    let _ = tcp.shutdown(Shutdown::Both);
                }
            })
        };
        TestApp {
            id: id.to_string(),
            port,
            seen,
            secret,
            stop,
            thread: Some(thread),
        }
    }

    pub fn set_secret(&self, secret: &str) {
        *self.secret.lock().unwrap() = secret.to_string();
    }

    pub fn secret(&self) -> String {
        self.secret.lock().unwrap().clone()
    }

    /// What has reached this backend so far.
    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    pub fn addr(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, self.port))
    }

    /// Stop the backend: its loopback port closes.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            t.join().unwrap();
        }
    }
}

impl Drop for TestApp {
    fn drop(&mut self) {
        self.stop();
    }
}

// ----- a hub ------------------------------------------------------------------------------------

/// A hub on 127.0.0.1 in a temporary folder.
pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub keys: KeyStore,
    /// The hub's clock (milliseconds); a test moves it.
    pub clock: Arc<AtomicI64>,
    /// Every line the hub logged.
    pub log: Arc<Mutex<Vec<String>>>,
    pub admin_token: String,
    hub: Option<Running>,
}

impl Fixture {
    pub fn new() -> Fixture {
        Self::with(|_| {})
    }

    /// A hub whose settings the test changes first.
    pub fn with(settings: impl FnOnce(&mut HubConfig)) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyStore::memory();
        // (the real time: the phone in these tests checks the certificate's dates by its own clock)
        let clock = Arc::new(AtomicI64::new(keep_hub::util::now_ms()));
        let mut cfg = HubConfig::new(Ipv4Addr::LOCALHOST);
        cfg.ports.admin = 0; // any free port
        settings(&mut cfg);
        keep_hub::setup(
            dir.path(),
            &cfg,
            &keys,
            "test computer",
            clock.load(Ordering::SeqCst),
        )
        .unwrap();
        let admin_token = keep_hub::admin_token(dir.path()).unwrap();
        let mut f = Fixture {
            dir,
            keys,
            clock,
            log: Arc::new(Mutex::new(Vec::new())),
            admin_token,
            hub: None,
        };
        f.start();
        f
    }

    fn start(&mut self) {
        let (clock, log) = (self.clock.clone(), self.log.clone());
        let hub = keep_hub::start(HubOptions {
            data: self.dir.path().to_path_buf(),
            keys: self.keys.clone(),
            clock: Arc::new(move || clock.load(Ordering::SeqCst)),
            log: Arc::new(move |l: &str| log.lock().unwrap().push(l.to_string())),
            pin_cost: Cost { m: 64, t: 1, p: 1 },
        })
        .unwrap();
        self.hub = Some(hub);
    }

    /// Stop the hub and start it again on the same folder and keys.
    pub fn restart(&mut self) {
        self.hub.take().unwrap().stop();
        self.start();
    }

    pub fn hub(&self) -> &Running {
        self.hub.as_ref().unwrap()
    }

    pub fn advance_minutes(&self, minutes: i64) {
        self.clock.fetch_add(minutes * 60_000, Ordering::SeqCst);
    }

    pub fn log_lines(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    // ----- as an app's desktop program, on the admin address ------------------------------------

    pub fn admin(&self, method: &str, path: &str, body: Option<Value>) -> Reply {
        let bytes = body.map(|b| serde_json::to_vec(&b).unwrap());
        let auth = format!("Bearer {}", self.admin_token);
        http(
            self.hub().admin,
            method,
            path,
            &[("Authorization", &auth)],
            bytes.as_deref(),
        )
    }

    /// Like [`Fixture::admin`], for a request that must work: its JSON.
    pub fn admin_ok(&self, method: &str, path: &str, body: Option<Value>) -> Value {
        let r = self.admin(method, path, body);
        assert_eq!(r.status, 200, "{method} {path}: {}", r.text());
        r.json()
    }

    pub fn registration(app: &TestApp, public_port: u16, money: bool, guests: bool) -> Value {
        json!({
            "id": app.id,
            "title": format!("Test {}", app.id),
            "version": "0.1.0",
            "protocol": 1,
            "public_port": public_port,
            "loopback_port": app.port,
            "money": money,
            "guests": guests,
        })
    }

    /// Register a test app on a free public port and give it its shared secret.
    pub fn register(&self, app: &TestApp, money: bool, guests: bool) -> u16 {
        let port = free_port();
        let v = self.admin_ok(
            "POST",
            "/admin/v1/apps",
            Some(Self::registration(app, port, money, guests)),
        );
        app.set_secret(v["secret"].as_str().unwrap());
        port
    }

    pub fn set_pin(&self) {
        self.admin_ok("PUT", "/admin/v1/pin", Some(json!({ "pin": PIN })));
    }

    pub fn add_member(&self, name: &str) -> u32 {
        self.admin_ok("POST", "/admin/v1/members", Some(json!({ "name": name })))["id"]
            .as_u64()
            .unwrap() as u32
    }

    /// A pairing code for a member and an app (making the grant; `PIN` is sent for it).
    pub fn code(&self, member: u32, app: &str) -> String {
        self.admin_ok(
            "POST",
            "/admin/v1/pairing-codes",
            Some(json!({ "member": member, "app": app, "pin": PIN })),
        )["code"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Pair a phone for a member and an app, all the way: its device token.
    pub fn pair(&self, member: u32, app: &str, device: &str) -> String {
        let code = self.code(member, app);
        let r = self.phone_json(
            app,
            "POST",
            "/hub/pair",
            &[],
            &json!({ "code": code, "pin": PIN, "device": device }),
        );
        assert_eq!(r.status, 200, "{}", r.text());
        r.json()["token"].as_str().unwrap().to_string()
    }

    // ----- as a phone, on an app's port ---------------------------------------------------------

    pub fn port(&self, app: &str) -> SocketAddr {
        self.hub()
            .app_port(app)
            .unwrap_or_else(|| panic!("{app} has no open port"))
    }

    pub fn phone(
        &self,
        app: &str,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Reply {
        let addr = self.port(app);
        let bytes = request(method, path, &addr.to_string(), headers, body);
        parse(&https_raw(addr, &self.hub().ca_der, &bytes).expect("an answer from the hub"))
    }

    pub fn phone_json(
        &self,
        app: &str,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &Value,
    ) -> Reply {
        let bytes = serde_json::to_vec(body).unwrap();
        let mut all = headers.to_vec();
        all.push(("Content-Type", "application/json"));
        self.phone(app, method, path, &all, Some(&bytes))
    }

    /// A request with a device token.
    pub fn api(&self, app: &str, token: &str, method: &str, path: &str) -> Reply {
        let auth = format!("Bearer {token}");
        self.phone(app, method, path, &[("Authorization", &auth)], None)
    }

    /// Bytes exactly as given to an app's port.
    pub fn phone_raw(&self, app: &str, bytes: &[u8]) -> Reply {
        parse(
            &https_raw(self.port(app), &self.hub().ca_der, bytes).expect("an answer from the hub"),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(h) = self.hub.take() {
            h.stop();
        }
    }
}
