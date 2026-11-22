//! Acceptance test 22: end to end in a headless browser against a real hub, with a test WASM
//! client and a test plain client: open by name, pair, call `/api/`, go offline, come back.
//!
//! Skipped unless run with `cargo test -p keep-hub --test browser -- --ignored` and these set
//! (as test 13 in `names.rs`):
//!
//! - `KEEP_HUB_E2E_SERVICE`: the staging name service, e.g. `https://<host>/v1`
//! - `KEEP_HUB_E2E_CODE`: a registration code for it
//!
//! It needs this computer on a home network (the hub publishes its real home address), and
//! Python with Playwright and its Chromium (`pip install playwright && playwright install
//! chromium`, or `KEEP_HUB_E2E_CHROME` set to a Chrome program). It asks Let's Encrypt's
//! staging service for one certificate, never the real one. The browser's part is
//! `tests/e2e/browser.py`; the clients are in `tests/e2e/client/`.
//!
//! `the_browser_part_against_a_local_hub` runs the same browser steps against a test hub on
//! 127.0.0.1, by a stand-in name, with the hub's own certificate: it needs Playwright only.

mod support;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use keep_hub::{HubConfig, HubOptions, KeyStore};
use keep_hub_app::{ensure_registered, HubAuth, HubClient, Registration};
use serde_json::{json, Value};
use support::{free_port, PIN};

const CLIENT_HTML: &str = include_str!("e2e/client/index.html");
const CLIENT_JS: &str = include_str!("e2e/client/app.js");
const CLIENT_SW: &str = include_str!("e2e/client/sw.js");
/// A WebAssembly module whose `answer()` returns 42 (written by hand: a type, a function, its
/// export and its code).
const ANSWER_WASM: [u8; 39] = [
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f, 0x03,
    0x02, 0x01, 0x00, 0x07, 0x0a, 0x01, 0x06, 0x61, 0x6e, 0x73, 0x77, 0x65, 0x72, 0x00, 0x00, 0x0a,
    0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b,
];

/// A test app's backend, made with the small library: its web client's files, and `/api/hello`
/// with the member's name.
struct Backend {
    port: u16,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Backend {
    fn start(kind: &'static str, app_data: &Path) -> Backend {
        let listener = keep_hub_app::listen(0).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let (data, flag) = (app_data.to_path_buf(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((s, _)) => serve(s, kind, &data),
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        });
        Backend {
            port,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn serve(mut s: TcpStream, kind: &str, data: &Path) {
    s.set_nonblocking(false).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && s.read(&mut b).unwrap_or(0) == 1 {
        head.push(b[0]);
    }
    let text = String::from_utf8_lossy(&head).to_string();
    let mut lines = text.split("\r\n");
    let path = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/")
        .to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let csp = if kind == "wasm" {
        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'"
    } else {
        "default-src 'self'"
    };
    let (status, ctype, body): (u16, &str, Vec<u8>) = match HubAuth::load(data) {
        Err(_) => (500, "text/plain", b"not registered".to_vec()),
        Ok(auth) => {
            if path.starts_with("/api/") {
                match auth.caller(&headers) {
                    Ok(c) => (
                        200,
                        "application/json",
                        json!({ "member_name": c.member_name, "device_name": c.device_name, "app": kind })
                            .to_string()
                            .into_bytes(),
                    ),
                    Err(r) => (r.status, "application/json", json!({ "error": r.code }).to_string().into_bytes()),
                }
            } else if auth.check(&headers).is_err() {
                (403, "text/plain", b"not from the hub".to_vec())
            } else {
                match path.as_str() {
                    "/" | "/index.html" => (
                        200,
                        "text/html; charset=utf-8",
                        CLIENT_HTML.replace("@KIND@", kind).into_bytes(),
                    ),
                    "/app.js" => (200, "text/javascript", CLIENT_JS.as_bytes().to_vec()),
                    "/sw.js" => (200, "text/javascript", CLIENT_SW.as_bytes().to_vec()),
                    "/answer.wasm" => (200, "application/wasm", ANSWER_WASM.to_vec()),
                    _ => (404, "text/plain", b"not found".to_vec()),
                }
            }
        }
    };
    let _ = write!(
        s,
        "HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Security-Policy: {csp}\r\nCache-Control: no-cache\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = s.write_all(&body);
}

#[test]
fn the_test_clients_wasm_module_is_well_formed() {
    // (the browser test itself is ignored by default; this keeps its pieces honest)
    assert_eq!(&ANSWER_WASM[..4], b"\0asm");
    assert!(CLIENT_HTML.contains("@KIND@"));
    assert!(CLIENT_JS.contains("/hub/pair") && CLIENT_JS.contains("/api/hello"));
    assert!(CLIENT_SW.contains("caches"));
}

#[test]
#[ignore = "end to end: needs the staging name service, a home network and Playwright"]
fn at22_end_to_end_in_a_headless_browser() {
    let (Ok(service), Ok(code)) = (
        std::env::var("KEEP_HUB_E2E_SERVICE"),
        std::env::var("KEEP_HUB_E2E_CODE"),
    ) else {
        panic!("set KEEP_HUB_E2E_SERVICE and KEEP_HUB_E2E_CODE (see this test's comment)");
    };
    let address: Ipv4Addr =
        keep_hub::machine::default_route_address().expect("this computer is on a home network");

    // a real hub on this computer, names on against the staging services
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = HubConfig::new(address);
    cfg.ports.admin = 0;
    cfg.ports.helper = 0;
    cfg.names.service = service;
    cfg.names.staging = true;
    let keys = KeyStore::memory();
    keep_hub::setup(
        dir.path(),
        &cfg,
        &keys,
        "e2e computer",
        keep_hub::util::now_ms(),
    )
    .unwrap();
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    let l = log.clone();
    let mut opts = HubOptions::new(dir.path().to_path_buf());
    opts.keys = keys;
    opts.log = Arc::new(move |line: &str| l.lock().unwrap().push(line.to_string()));
    opts.outside = Some(keep_hub::names::Outside::system().unwrap());
    let running = keep_hub::start(opts).unwrap();
    let token = keep_hub::admin_token(dir.path()).unwrap();
    let hub = HubClient::at(running.admin, &token);
    hub.set_up(support::ADMIN_NAME, support::ADMIN_PASSWORD, PIN)
        .unwrap();
    hub.names_on(Some(&code)).unwrap();
    let mut st = Value::Null;
    for _ in 0..120 {
        st = hub.names().unwrap();
        if st["state"] == "ready" || st["state"] == "blocked" {
            break;
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    assert!(
        st["state"] == "ready" || st["state"] == "blocked",
        "{st:#}\n{:#?}",
        log.lock().unwrap()
    );
    let name = st["name"].as_str().unwrap().to_string();

    // two test apps, made with the library
    let member = "Ann";
    let ann = hub.add_member(member).unwrap();
    let mut keep = Vec::new();
    let mut clients = Vec::new();
    for kind in ["plain", "wasm"] {
        let data = tempfile::tempdir().unwrap();
        let backend = Backend::start(kind, data.path());
        let public = free_port();
        let reg = Registration::new(
            &format!("e2e{kind}"),
            &format!("E2E {kind}"),
            "1.0.0",
            public,
            backend.port,
        );
        ensure_registered(&hub, &reg, data.path()).unwrap();
        let pairing = hub.make_pairing_code(ann, &reg.id).unwrap();
        clients.push(json!({
            "kind": kind,
            "url": format!("https://{name}:{public}/#pair={}", pairing.code),
        }));
        keep.push((data, backend));
    }
    // the apps' ports take the name's certificate after the work
    std::thread::sleep(Duration::from_secs(2));

    run_browser(
        dir.path(),
        json!({
            "name": name,
            "certificate_name": name,
            "address": address.to_string(),
            "pin": PIN,
            "member": member,
            "clients": clients,
        }),
    );
    drop(keep);
    running.stop();
}

/// Write the job and run `tests/e2e/browser.py` on it.
fn run_browser(dir: &Path, job: Value) {
    let job_file: PathBuf = dir.join("e2e-job.json");
    std::fs::write(&job_file, job.to_string()).unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/e2e/browser.py");
    let out = std::process::Command::new(if cfg!(windows) { "python" } else { "python3" })
        .arg(&script)
        .arg(&job_file)
        .output()
        .expect("Python is installed");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!("{said}");
    assert!(out.status.success(), "the browser test failed:\n{said}");
}

#[test]
#[ignore = "needs Playwright and a Chrome or Chromium"]
fn the_browser_part_against_a_local_hub() {
    let f = support::Fixture::new();
    let hub = HubClient::at(f.hub().admin, &f.admin_token);
    hub.sign_in(support::ADMIN_NAME, support::ADMIN_PASSWORD)
        .unwrap();
    let member = "Ann";
    let ann = hub.add_member(member).unwrap();
    // a stand-in name, mapped to the hub's address in the browser
    let name = "hub.e2e.invalid";
    let mut keep = Vec::new();
    let mut clients = Vec::new();
    for kind in ["plain", "wasm"] {
        let data = tempfile::tempdir().unwrap();
        let backend = Backend::start(kind, data.path());
        let reg = Registration::new(
            &format!("e2e{kind}"),
            &format!("E2E {kind}"),
            "1.0.0",
            free_port(),
            backend.port,
        );
        ensure_registered(&hub, &reg, data.path()).unwrap();
        let pairing = hub.make_pairing_code(ann, &reg.id).unwrap();
        clients.push(json!({
            "kind": kind,
            "url": format!("https://{name}:{}/#pair={}", reg.public_port, pairing.code),
        }));
        keep.push((data, backend));
    }
    run_browser(
        f.dir.path(),
        json!({
            "name": name,
            "address": "127.0.0.1",
            "pin": PIN,
            "member": member,
            "clients": clients,
        }),
    );
    drop(keep);
}
