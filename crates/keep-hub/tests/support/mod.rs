//! What the hub's tests share: a hub in a temporary folder with its keys in memory and a
//! clock the test moves, two kinds of client (a phone over HTTPS trusting only the hub's
//! certificate authority, and an app's desktop program on the admin address), and small
//! test apps: backends on a loopback port that refuse anything without the right
//! `Keep-Hub-Auth` and remember what reached them.
//!
//! Nothing here leaves this computer.

#![allow(dead_code)]

pub mod machine;
pub mod world;

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
use world::{World, ACME_DIR, CODE, SERVICE};

pub const PIN: &str = "246810";
/// The first administrator every test hub is set up with (not a real password).
pub const ADMIN_NAME: &str = "Avery";
pub const ADMIN_PASSWORD: &str = "test-password-1";

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

/// A TLS client for an app port, trusting only `ca_der`.
fn tls_client(addr: SocketAddr, ca_der: &[u8]) -> Result<rustls::ClientConnection, String> {
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
    rustls::ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())
}

/// Bytes sent to an app port over TLS asking for the name `sni` (not the address),
/// trusting only `roots`: the answer, and the certificate the hub answered with.
pub fn https_named(
    addr: SocketAddr,
    roots: &[Vec<u8>],
    sni: &str,
    bytes: &[u8],
) -> Result<(Reply, Vec<u8>), String> {
    let mut store = rustls::RootCertStore::empty();
    for r in roots {
        store
            .add(CertificateDer::from(r.clone()))
            .map_err(|e| e.to_string())?;
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_root_certificates(store)
    .with_no_client_auth();
    let name = ServerName::try_from(sni.to_string()).map_err(|e| e.to_string())?;
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
    let cert = conn
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|c| c.to_vec())
        .unwrap_or_default();
    Ok((parse(&answer), cert))
}

/// The certificate an app port answers with for a connection by address.
pub fn cert_by_address(addr: SocketAddr, ca_der: &[u8]) -> Vec<u8> {
    let mut conn = tls_client(addr, ca_der).expect("a TLS client");
    let mut tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).expect("connect");
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
    tls.write_all(b"GET /hub/check HTTP/1.1\r\nHost: x\r\n\r\n")
        .expect("send");
    let mut answer = Vec::new();
    let _ = tls.read_to_end(&mut answer);
    conn.peer_certificates()
        .and_then(|c| c.first())
        .map(|c| c.to_vec())
        .unwrap_or_default()
}

/// Bytes sent to an app port over TLS, trusting only `ca_der`; what came back until the
/// hub closed. `Err` when the connection can't be made.
pub fn https_raw(addr: SocketAddr, ca_der: &[u8], bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut conn = tls_client(addr, ca_der)?;
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

/// An answer read as it arrives, its body hashed and counted, never kept.
#[derive(Debug)]
pub struct Streamed {
    /// The status and headers (no body).
    pub head: Reply,
    pub body_len: u64,
    pub sha256: Vec<u8>,
    /// `Ok` when the hub ended the connection properly; `Err` when it was cut short.
    pub end: Result<(), String>,
    pub elapsed: Duration,
}

/// Send `bytes` to an app port and stream the answer (a phone downloading a large file).
pub fn https_stream(addr: SocketAddr, ca_der: &[u8], bytes: &[u8]) -> Streamed {
    use sha2::{Digest, Sha256};
    let started = std::time::Instant::now();
    let mut conn = tls_client(addr, ca_der).expect("a TLS client");
    let mut tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
    tls.write_all(bytes).expect("send");
    let mut buf = vec![0u8; 64 * 1024];
    let mut head: Vec<u8> = Vec::new();
    let mut parsed: Option<Reply> = None;
    let mut hash = Sha256::new();
    let mut body_len = 0u64;
    let end = loop {
        let n = match tls.read(&mut buf) {
            Ok(0) => break Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break Err("cut short".to_string())
            }
            Err(e) => break Err(e.to_string()),
        };
        let mut data = &buf[..n];
        if parsed.is_none() {
            head.extend_from_slice(data);
            let Some(p) = head.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let rest = head.split_off(p + 4);
            parsed = Some(parse(&head));
            hash.update(&rest);
            body_len += rest.len() as u64;
            data = &[];
        }
        hash.update(data);
        body_len += data.len() as u64;
    };
    Streamed {
        head: parsed.expect("an answer's head"),
        body_len,
        sha256: hash.finalize().to_vec(),
        end,
        elapsed: started.elapsed(),
    }
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

/// The large WASM client's size (MoneyKeep's is about 12 MB before compression).
pub const WASM_LEN: usize = 12 * 1024 * 1024;
pub const WASM_ETAG: &str = "\"wasm-v1\"";

/// Byte `i` of the large client: made as it is sent, so the test app never holds the file.
pub fn wasm_byte(i: usize) -> u8 {
    ((i ^ (i >> 9)).wrapping_mul(131) % 251) as u8
}

/// The large client's SHA-256, worked out the same way.
pub fn wasm_sha256() -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    let mut chunk = vec![0u8; 64 * 1024];
    let mut i = 0;
    while i < WASM_LEN {
        let n = chunk.len().min(WASM_LEN - i);
        for (k, b) in chunk[..n].iter_mut().enumerate() {
            *b = wasm_byte(i + k);
        }
        h.update(&chunk[..n]);
        i += n;
    }
    h.finalize().to_vec()
}

/// The plain client's page and its security policy.
pub const PLAIN_HTML: &str = "<!doctype html><title>Plain</title><script src=app.js></script>";
pub const PLAIN_CSP: &str = "default-src 'self'; script-src 'self'; object-src 'none'";

/// A small app backend on a loopback port. It refuses (403) anything without the secret
/// the hub gave it; `/api/...` answers with what it was sent. Its files:
///
/// - `/app.wasm`: the large client, [`WASM_LEN`] bytes, `application/wasm`, `br` when the
///   phone accepts it, an `ETag` (304 for `If-None-Match`);
/// - `/plain/index.html`, `/plain/app.js`: a plain client, with a security policy;
/// - `/stall`: announces 1000 bytes, sends 10, then nothing;
/// - `/trickle?n=<bytes>&ms=<pause>`: one byte, a pause, the next;
/// - `/slow?ms=<wait>`: nothing for `ms`, then a short answer carrying its own
///   `X-Content-Type-Options`, `Referrer-Policy` and `Strict-Transport-Security` (which
///   the hub replaces);
/// - anything else: one line naming the app and the path.
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

fn query_number(target: &str, key: &str) -> Option<u64> {
    target
        .split_once('?')?
        .1
        .split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")))?
        .parse()
        .ok()
}

/// One connection to a test app: read the request, answer, close.
fn answer(
    mut tcp: TcpStream,
    id: &str,
    seen: &Mutex<Vec<Seen>>,
    secret: &Mutex<String>,
    stop: &AtomicBool,
) {
    tcp.set_nonblocking(false).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let Some((method, target, headers, body)) = read_request(&mut tcp) else {
        return;
    };
    let header = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };
    let want = secret.lock().unwrap().clone();
    let got: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("keep-hub-auth"))
        .map(|(_, v)| v.as_str())
        .collect();
    let trusted = !want.is_empty() && got == [want.as_str()];
    seen.lock().unwrap().push(Seen {
        method: method.clone(),
        target: target.clone(),
        headers: headers.clone(),
        body: body.clone(),
        trusted,
    });
    let path = target.split('?').next().unwrap_or("").to_string();
    // (says keep-alive on purpose: the hub must still close after each answer)
    let send_head = |tcp: &mut TcpStream, status: &str, lines: &[(&str, String)]| {
        let mut h = format!("HTTP/1.1 {status}\r\nConnection: keep-alive\r\nX-App: {id}\r\n");
        for (k, v) in lines {
            h.push_str(&format!("{k}: {v}\r\n"));
        }
        h.push_str("\r\n");
        tcp.write_all(h.as_bytes())
    };
    let small =
        |tcp: &mut TcpStream, status: &str, kind: &str, out: &[u8], extra: &[(&str, String)]| {
            let mut lines = vec![
                ("Content-Type", kind.to_string()),
                ("Content-Length", out.len().to_string()),
            ];
            lines.extend(extra.iter().cloned());
            send_head(tcp, status, &lines)?;
            if method != "HEAD" {
                tcp.write_all(out)?;
            }
            Ok::<(), std::io::Error>(())
        };
    let _ = (|| -> std::io::Result<()> {
        if !trusted {
            return small(&mut tcp, "403 Forbidden", "text/plain", b"refused", &[]);
        }
        if target.starts_with("/api/") {
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
            let out = serde_json::to_vec(&v).unwrap();
            return small(&mut tcp, "200 OK", "application/json", &out, &[]);
        }
        match path.as_str() {
            "/app.wasm" => {
                let etag = ("ETag", WASM_ETAG.to_string());
                let cache = ("Cache-Control", "no-cache".to_string());
                if header("if-none-match").as_deref() == Some(WASM_ETAG) {
                    return send_head(&mut tcp, "304 Not Modified", &[etag, cache]);
                }
                let encoding = match header("accept-encoding") {
                    Some(a) if a.contains("br") => "br",
                    _ => "gzip",
                };
                send_head(
                    &mut tcp,
                    "200 OK",
                    &[
                        ("Content-Type", "application/wasm".into()),
                        ("Content-Encoding", encoding.into()),
                        ("Vary", "Accept-Encoding".into()),
                        ("Content-Length", WASM_LEN.to_string()),
                        etag,
                        cache,
                    ],
                )?;
                if method == "HEAD" {
                    return Ok(());
                }
                let mut chunk = vec![0u8; 64 * 1024];
                let mut i = 0;
                while i < WASM_LEN {
                    let n = chunk.len().min(WASM_LEN - i);
                    for (k, b) in chunk[..n].iter_mut().enumerate() {
                        *b = wasm_byte(i + k);
                    }
                    tcp.write_all(&chunk[..n])?;
                    i += n;
                }
                Ok(())
            }
            "/plain/index.html" => small(
                &mut tcp,
                "200 OK",
                "text/html; charset=utf-8",
                PLAIN_HTML.as_bytes(),
                &[
                    ("Content-Security-Policy", PLAIN_CSP.to_string()),
                    // a weaker one of the hub's own: the hub puts its own in its place
                    ("Referrer-Policy", "origin".to_string()),
                ],
            ),
            "/plain/app.js" => small(
                &mut tcp,
                "200 OK",
                "text/javascript",
                b"document.title = 'Plain';",
                &[("Content-Security-Policy", PLAIN_CSP.to_string())],
            ),
            "/stall" => {
                send_head(
                    &mut tcp,
                    "200 OK",
                    &[
                        ("Content-Type", "application/octet-stream".into()),
                        ("Content-Length", "1000".into()),
                    ],
                )?;
                tcp.write_all(&[7u8; 10])?;
                let until = std::time::Instant::now() + Duration::from_secs(60);
                while !stop.load(Ordering::SeqCst) && std::time::Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Ok(())
            }
            "/trickle" => {
                let n = query_number(&target, "n").unwrap_or(10);
                let ms = query_number(&target, "ms").unwrap_or(100);
                send_head(
                    &mut tcp,
                    "200 OK",
                    &[
                        ("Content-Type", "application/octet-stream".into()),
                        ("Content-Length", n.to_string()),
                    ],
                )?;
                for _ in 0..n {
                    tcp.write_all(&[1u8])?;
                    std::thread::sleep(Duration::from_millis(ms));
                }
                Ok(())
            }
            "/slow" => {
                let ms = query_number(&target, "ms").unwrap_or(100);
                let until = std::time::Instant::now() + Duration::from_millis(ms);
                while !stop.load(Ordering::SeqCst) && std::time::Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(20));
                }
                small(
                    &mut tcp,
                    "200 OK",
                    "text/plain",
                    b"worked it out",
                    &[
                        ("X-Content-Type-Options", "sniff".to_string()),
                        ("Referrer-Policy", "unsafe-url".to_string()),
                        ("Strict-Transport-Security", "max-age=31536000".to_string()),
                    ],
                )
            }
            _ => small(
                &mut tcp,
                "200 OK",
                "text/plain",
                format!("{id} file {target}").as_bytes(),
                &[],
            ),
        }
    })();
    let _ = tcp.shutdown(Shutdown::Both);
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
                    let tcp = match listener.accept() {
                        Ok((tcp, _)) => tcp,
                        Err(_) => {
                            std::thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                    };
                    // one thread per connection: a stalled download must not hold the app
                    let (id, seen, secret, stop) =
                        (id.clone(), seen.clone(), secret.clone(), stop.clone());
                    std::thread::spawn(move || answer(tcp, &id, &seen, &secret, &stop));
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
    /// The hub's limit for a transfer with no bytes moving.
    pub idle: Duration,
    /// The internet as the hub sees it: none, unless a test gives a fake world.
    pub outside: keep_hub::names::Outside,
    /// This computer as the hub sees it: at 127.0.0.1 until a test moves it.
    pub machine: Arc<machine::FakeMachine>,
    /// How often the hub looks for a new address (short in tests).
    pub address_poll: Duration,
    /// How long a backend may take to start its answer.
    pub first_byte: Duration,
    /// Where app ports listen for a tunnel's connector (the home address, 127.0.0.1, unless
    /// a test moves it).
    pub tunnel_listen: Ipv4Addr,
    /// The test administrator's session, once the hub is set up.
    session: Mutex<Option<String>>,
    hub: Option<Running>,
}

impl Fixture {
    /// A hub set up with the test administrator ([`ADMIN_NAME`]) and the household PIN
    /// ([`PIN`]), signed in.
    pub fn new() -> Fixture {
        Self::with(|_| {})
    }

    /// A hub as installed: no first set-up yet.
    pub fn not_set_up() -> Fixture {
        Self::build(|_| {}, keep_hub::relay::IDLE, false)
    }

    /// A hub whose settings the test changes first.
    pub fn with(settings: impl FnOnce(&mut HubConfig)) -> Fixture {
        Self::build(settings, keep_hub::relay::IDLE, true)
    }

    /// A hub that closes a transfer after `idle` with no bytes moving (instead of 30
    /// seconds), so a test of the rule doesn't wait minutes.
    pub fn with_idle(idle: Duration) -> Fixture {
        Self::build(|_| {}, idle, true)
    }

    /// A hub whose outside world is a fake (`world::World`), sharing the hub's clock.
    pub fn with_world(settings: impl FnOnce(&mut HubConfig)) -> (Fixture, Arc<world::World>) {
        let mut f = Self::build(settings, keep_hub::relay::IDLE, true);
        let w = world::World::new(f.clock.clone());
        f.outside = w.outside();
        f.restart();
        (f, w)
    }

    fn build(settings: impl FnOnce(&mut HubConfig), idle: Duration, set_up: bool) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyStore::memory();
        // (the real time: the phone in these tests checks the certificate's dates by its own clock)
        let clock = Arc::new(AtomicI64::new(keep_hub::util::now_ms()));
        let mut cfg = HubConfig::new(Ipv4Addr::LOCALHOST);
        cfg.ports.admin = 0; // any free port
        cfg.ports.helper = 0;
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
            idle,
            outside: keep_hub::names::Outside::unavailable("the tests have no network"),
            machine: Arc::new(machine::FakeMachine::at(Ipv4Addr::LOCALHOST)),
            address_poll: Duration::from_millis(100),
            first_byte: keep_hub::relay::FIRST_BYTE,
            tunnel_listen: Ipv4Addr::LOCALHOST,
            session: Mutex::new(None),
            hub: None,
        };
        f.start();
        if set_up {
            let v = f.admin_with(
                None,
                "POST",
                "/admin/v1/setup",
                Some(json!({ "name": ADMIN_NAME, "password": ADMIN_PASSWORD, "pin": PIN })),
            );
            assert_eq!(v.status, 200, "first set-up: {}", v.text());
            *f.session.lock().unwrap() = Some(v.json()["session"].as_str().unwrap().to_string());
        }
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
            idle: self.idle,
            outside: Some(self.outside.clone()),
            machine: Some(self.machine.clone()),
            address_poll: self.address_poll,
            first_byte: self.first_byte,
            tunnel_listen: self.tunnel_listen,
        })
        .unwrap();
        self.hub = Some(hub);
    }

    /// The same hub, letting a backend take `first_byte` to start its answer (instead of
    /// 120 seconds), so a test of the rule doesn't wait minutes.
    pub fn with_first_byte(first_byte: Duration) -> Fixture {
        let mut f = Self::new();
        f.first_byte = first_byte;
        f.restart();
        f
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

    /// A request with the admin token and the test administrator's session. A session the
    /// hub no longer knows (a restart, the clock moved on) is replaced by signing in again.
    pub fn admin(&self, method: &str, path: &str, body: Option<Value>) -> Reply {
        let session = self.session.lock().unwrap().clone();
        let r = self.admin_with(session.as_deref(), method, path, body.clone());
        if r.status == 401 && r.error() == "administrator_needed" && session.is_some() {
            let s = self.sign_in(ADMIN_NAME, ADMIN_PASSWORD);
            assert_eq!(s.status, 200, "signing in again: {}", s.text());
            let s = s.json()["session"].as_str().unwrap().to_string();
            *self.session.lock().unwrap() = Some(s.clone());
            return self.admin_with(Some(&s), method, path, body);
        }
        r
    }

    /// A request with the admin token, and `session` in `Keep-Admin-Session` when given.
    pub fn admin_with(
        &self,
        session: Option<&str>,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Reply {
        let bytes = body.map(|b| serde_json::to_vec(&b).unwrap());
        let auth = format!("Bearer {}", self.admin_token);
        let mut headers = vec![("Authorization", auth.as_str())];
        if let Some(s) = session {
            headers.push(("Keep-Admin-Session", s));
        }
        http(self.hub().admin, method, path, &headers, bytes.as_deref())
    }

    /// Sign in on the admin address (the answer, whatever it is).
    pub fn sign_in(&self, name: &str, password: &str) -> Reply {
        self.admin_with(
            None,
            "POST",
            "/admin/v1/session",
            Some(json!({ "name": name, "password": password })),
        )
    }

    /// Sign in, which must work: the session.
    pub fn session_of(&self, name: &str, password: &str) -> String {
        let r = self.sign_in(name, password);
        assert_eq!(r.status, 200, "signing in as {name}: {}", r.text());
        r.json()["session"].as_str().unwrap().to_string()
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

    /// Add a standard member.
    pub fn add_member(&self, name: &str) -> u32 {
        self.admin_ok("POST", "/admin/v1/members", Some(json!({ "name": name })))["id"]
            .as_u64()
            .unwrap() as u32
    }

    /// Add an administrator with a password.
    pub fn add_administrator(&self, name: &str, password: &str) -> u32 {
        let id = self.admin_ok(
            "POST",
            "/admin/v1/members",
            Some(json!({ "name": name, "class": "administrator" })),
        )["id"]
            .as_u64()
            .unwrap() as u32;
        self.admin_ok(
            "PUT",
            &format!("/admin/v1/members/{id}/password"),
            Some(json!({ "password": password })),
        );
        id
    }

    /// A pairing code for a member and an app (making the grant if needed).
    pub fn code(&self, member: u32, app: &str) -> String {
        self.admin_ok(
            "POST",
            "/admin/v1/pairing-codes",
            Some(json!({ "member": member, "app": app })),
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
        parse(&https_raw(addr, &self.hub().ca_der(), &bytes).expect("an answer from the hub"))
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

    /// As [`Fixture::phone_json`], on the app port's listener for a tunnel's connector
    /// (`tunnel_listen`), as a request through the tunnel arrives.
    pub fn tunnel_json(
        &self,
        app: &str,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &Value,
    ) -> Reply {
        let addr = SocketAddr::from((self.tunnel_listen, self.port(app).port()));
        let bytes = serde_json::to_vec(body).unwrap();
        let mut all = headers.to_vec();
        all.push(("Content-Type", "application/json"));
        let req = request(method, path, &addr.to_string(), &all, Some(&bytes));
        // (the hub's own certificate is for its home address)
        let home = self.hub().address().expect("a home address").to_string();
        https_named(addr, &[self.hub().ca_der()], &home, &req)
            .expect("an answer from the hub")
            .0
    }

    /// A request with a device token.
    pub fn api(&self, app: &str, token: &str, method: &str, path: &str) -> Reply {
        let auth = format!("Bearer {token}");
        self.phone(app, method, path, &[("Authorization", &auth)], None)
    }

    /// A GET for a file, streamed (nothing kept but its hash).
    /// The current answer of an app port to a phone that asks for the hub name `name`,
    /// trusting `roots` (the certificate authority of the name's certificate).
    pub fn phone_by_name(
        &self,
        app: &str,
        roots: &[Vec<u8>],
        name: &str,
        path: &str,
    ) -> Result<(Reply, Vec<u8>), String> {
        let bytes = request("GET", path, name, &[], None);
        https_named(self.port(app), roots, name, &bytes)
    }

    pub fn download(&self, app: &str, path: &str, headers: &[(&str, &str)]) -> Streamed {
        let addr = self.port(app);
        let bytes = request("GET", path, &addr.to_string(), headers, None);
        https_stream(addr, &self.hub().ca_der(), &bytes)
    }

    /// Bytes exactly as given to an app's port.
    pub fn phone_raw(&self, app: &str, bytes: &[u8]) -> Reply {
        parse(
            &https_raw(self.port(app), &self.hub().ca_der(), bytes)
                .expect("an answer from the hub"),
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

/// A hub whose name is ready, with one app; the name.
pub fn named_hub(staging: bool) -> (Fixture, Arc<World>, TestApp, String) {
    let (f, world) = Fixture::with_world(|cfg| {
        cfg.names.service = SERVICE.into();
        cfg.names.acme = ACME_DIR.into();
        cfg.names.staging = staging;
    });
    world.allow_loopback.store(true, Ordering::SeqCst);
    let app = TestApp::start("vacapick");
    f.register(&app, false, false);
    f.admin_ok(
        "POST",
        "/admin/v1/names/on",
        Some(json!({ "registration_code": CODE })),
    );
    let mut st = Value::Null;
    for _ in 0..200 {
        st = f.admin_ok("GET", "/admin/v1/names", None);
        if st["state"] == "ready" {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(st["state"], "ready", "{st}");
    let name = st["name"].as_str().unwrap().to_string();
    // the app ports take the certificate right after the work
    let roots = [world.acme_ca()];
    for _ in 0..200 {
        if f.phone_by_name("vacapick", &roots, &name, "/hub/check")
            .is_ok()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    (f, world, app, name)
}
