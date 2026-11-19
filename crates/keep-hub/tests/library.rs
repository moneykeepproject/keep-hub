//! Stage 6: the small library apps copy (`crates/keep-hub-app`), against a real hub.
//!
//! The test app here is built only from the library: its desktop side finds the hub and
//! registers with it; its backend listens with `keep_hub_app::listen` and checks every
//! request with the secret the library kept.

mod support;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use keep_hub_app::{
    ensure_registered, find, make_this_the_hub, offer, Found, HubAuth, HubClient, Launcher, Next,
    Offer, Registration, RECORD_FILE, SECRET_FILE,
};
use serde_json::{json, Value};
use support::{free_port, Fixture, PIN};

/// A backend made with the library: it answers with who called, or the refusal.
struct LibBackend {
    port: u16,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl LibBackend {
    fn start(app_data: &Path) -> LibBackend {
        let listener = keep_hub_app::listen(0).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let (data, flag) = (app_data.to_path_buf(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((s, _)) => answer(s, &data),
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        });
        LibBackend {
            port,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for LibBackend {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn answer(mut s: TcpStream, data: &Path) {
    s.set_nonblocking(false).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
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
        .to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    // the secret is loaded for each request, so a new registration takes effect at once
    let (status, body) = match HubAuth::load(data) {
        Err(e) => (500, json!({ "error": e.code })),
        Ok(auth) => {
            let checked = if path.starts_with("/api/") {
                auth.caller(&headers).map(Some)
            } else {
                auth.check(&headers)
            };
            match checked {
                Ok(Some(c)) => (
                    200,
                    json!({
                        "member": c.member, "member_name": c.member_name,
                        "device": c.device, "device_name": c.device_name,
                        "guest_scope": c.guest_scope, "request_id": c.request_id,
                    }),
                ),
                Ok(None) => (200, json!({ "files": path })),
                Err(r) => (r.status, json!({ "error": r.code })),
            }
        }
    };
    let body = body.to_string();
    let _ = write!(
        s,
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

/// A request straight to the backend (as another program on this computer could).
fn direct(port: u16, headers: &[(&str, &str)]) -> (u16, Value) {
    let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    let mut req = "GET /api/items HTTP/1.1\r\nHost: x\r\n".to_string();
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("Connection: close\r\n\r\n");
    s.write_all(req.as_bytes()).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let status = out[9..12].parse().unwrap();
    let body = out.split("\r\n\r\n").nth(1).unwrap_or("");
    (status, serde_json::from_str(body).unwrap_or(Value::Null))
}

/// A hub whose admin port is written in its `hub.json`, as an installed hub's is.
fn hub_on_known_port() -> Fixture {
    let port = free_port();
    Fixture::with(|cfg| cfg.ports.admin = port)
}

fn client(f: &Fixture) -> HubClient {
    HubClient::at(f.hub().admin, &f.admin_token)
}

struct App {
    data: tempfile::TempDir,
    backend: LibBackend,
    reg: Registration,
}

impl App {
    fn new(id: &str, title: &str) -> App {
        let data = tempfile::tempdir().unwrap();
        let backend = LibBackend::start(data.path());
        let reg = Registration::new(id, title, "1.0.0", free_port(), backend.port);
        App { data, backend, reg }
    }

    fn data(&self) -> PathBuf {
        self.data.path().to_path_buf()
    }
}

// ----- finding the hub ----------------------------------------------------------------------------

#[test]
fn an_app_finds_no_hub_a_stopped_hub_and_a_running_one() {
    let empty = tempfile::tempdir().unwrap();
    assert!(matches!(find(empty.path()), Found::NotInstalled));

    let f = hub_on_known_port();
    match find(f.dir.path()) {
        Found::Running(hub, status) => {
            assert_eq!(hub.addr(), f.hub().admin);
            assert!(status.accepts(keep_hub_app::PROTOCOL));
            assert_eq!(status.address.as_deref(), Some("127.0.0.1"));
            assert!(status.apps.is_empty());
        }
        other => panic!("{other:?}"),
    }
    // stopped: found, and offered to start
    let admin = f.hub().admin;
    let stopped = tempfile::tempdir().unwrap();
    for file in ["hub.json", "admin.token"] {
        std::fs::copy(f.dir.path().join(file), stopped.path().join(file)).unwrap();
    }
    drop(f); // the hub stops
    std::thread::sleep(Duration::from_millis(100));
    match find(stopped.path()) {
        Found::Stopped(hub) => {
            assert_eq!(hub.addr(), admin);
            assert_eq!(hub.status().unwrap_err().code, "hub_unreachable");
        }
        other => panic!("{other:?}"),
    }
}

/// keep-launcher, faked: how often the app opened it at the hub's entry.
struct FakeLauncher {
    installed: bool,
    opened: std::cell::Cell<u32>,
}

impl Launcher for FakeLauncher {
    fn installed(&self) -> bool {
        self.installed
    }
    fn open_hub_entry(&self) -> Result<(), String> {
        self.opened.set(self.opened.get() + 1);
        Ok(())
    }
}

/// Every file in a folder, with its size and bytes' hash (to see that nothing changed).
fn snapshot(dir: &Path) -> Vec<(PathBuf, u64, Vec<u8>)> {
    let mut out = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                todo.push(p);
            } else {
                let bytes = std::fs::read(&p).unwrap();
                out.push((p, bytes.len() as u64, bytes));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn at23_no_hub_offers_the_launchers_entry_and_a_stopped_hub_is_offered_a_start() {
    // no hub on the computer: offered, and yes opens keep-launcher at the hub's entry
    let empty = tempfile::tempdir().unwrap();
    assert!(matches!(offer(empty.path()), Offer::MakeThisTheHub));
    let launcher = FakeLauncher {
        installed: true,
        opened: std::cell::Cell::new(0),
    };
    assert_eq!(make_this_the_hub(&launcher).unwrap(), Next::LauncherOpened);
    assert_eq!(launcher.opened.get(), 1);
    // without keep-launcher: the hub's download page
    let none = FakeLauncher {
        installed: false,
        opened: std::cell::Cell::new(0),
    };
    assert!(matches!(
        make_this_the_hub(&none).unwrap(),
        Next::DownloadPage(p) if p.starts_with("https://")
    ));
    assert_eq!(none.opened.get(), 0);
    assert!(
        std::fs::read_dir(empty.path()).unwrap().next().is_none(),
        "nothing installed"
    );

    // a running hub: on with the phone setup
    let f = hub_on_known_port();
    assert!(matches!(offer(f.dir.path()), Offer::Ready(_, _)));

    // a stopped hub counts as found: offered a start, the launcher isn't opened and nothing
    // in the hub's folder changes
    let stopped = tempfile::tempdir().unwrap();
    for file in ["hub.json", "admin.token"] {
        std::fs::copy(f.dir.path().join(file), stopped.path().join(file)).unwrap();
    }
    drop(f);
    std::thread::sleep(Duration::from_millis(100));
    let before = snapshot(stopped.path());
    let launcher = FakeLauncher {
        installed: true,
        opened: std::cell::Cell::new(0),
    };
    match offer(stopped.path()) {
        Offer::StartHub(hub) => assert_eq!(hub.status().unwrap_err().code, "hub_unreachable"),
        other => panic!("{other:?}"),
    }
    assert_eq!(launcher.opened.get(), 0, "the launcher isn't opened");
    assert_eq!(
        snapshot(stopped.path()),
        before,
        "nothing installed or changed"
    );
}

#[test]
fn a_wrong_admin_token_is_refused_and_the_error_holds_no_token() {
    let f = Fixture::new();
    let hub = HubClient::at(f.hub().admin, "not-the-token");
    let e = hub.members().unwrap_err();
    assert_eq!(e.status, Some(401));
    assert!(!e.to_string().contains("not-the-token"));
    assert!(!format!("{hub:?}").contains("not-the-token"));
}

// ----- registering --------------------------------------------------------------------------------

#[test]
fn registering_happens_once_per_version_and_the_secret_is_kept_sealed() {
    let f = Fixture::new();
    let hub = client(&f);
    let mut app = App::new("vacapick", "VacaPick");

    let first = ensure_registered(&hub, &app.reg, &app.data()).unwrap();
    assert!(first.now);
    assert!(app.data.path().join(RECORD_FILE).is_file());
    let sealed = std::fs::read(app.data.path().join(SECRET_FILE)).unwrap();
    assert!(!sealed.is_empty());
    assert!(!std::fs::read_to_string(app.data.path().join(RECORD_FILE))
        .unwrap()
        .contains("secret"));
    let port = f.port("vacapick");
    assert_eq!(port.port(), app.reg.public_port);
    let lines_before = f
        .log_lines()
        .iter()
        .filter(|l| l.contains("registered"))
        .count();

    // again, same version: nothing sent, the same secret
    let again = ensure_registered(&hub, &app.reg, &app.data()).unwrap();
    assert!(!again.now);
    assert_eq!(
        f.log_lines()
            .iter()
            .filter(|l| l.contains("registered"))
            .count(),
        lines_before
    );
    assert_eq!(
        f.phone("vacapick", "GET", "/index.html", &[], None).status,
        200
    );

    // a new version registers again, with a new secret the backend picks up
    let old_secret = std::fs::read(app.data.path().join(SECRET_FILE)).unwrap();
    app.reg.version = "1.1.0".into();
    assert!(ensure_registered(&hub, &app.reg, &app.data()).unwrap().now);
    assert_ne!(
        std::fs::read(app.data.path().join(SECRET_FILE)).unwrap(),
        old_secret
    );
    assert_eq!(hub.apps().unwrap()[0].version, "1.1.0");
    let r = f.phone("vacapick", "GET", "/index.html", &[], None);
    assert_eq!(
        (r.status, r.json()["files"].as_str()),
        (200, Some("/index.html"))
    );

    // the secret lost here: registered again
    std::fs::remove_file(app.data.path().join(SECRET_FILE)).unwrap();
    assert!(ensure_registered(&hub, &app.reg, &app.data()).unwrap().now);
    // the app unregistered at the hub: registered again
    hub.unregister("vacapick").unwrap();
    assert!(hub.apps().unwrap().is_empty());
    assert!(ensure_registered(&hub, &app.reg, &app.data()).unwrap().now);
    assert_eq!(f.phone("vacapick", "GET", "/", &[], None).status, 200);
}

#[test]
fn a_hub_refuses_what_it_cant_take_with_its_own_words() {
    let f = Fixture::new();
    let hub = client(&f);
    let a = App::new("vacapick", "VacaPick");
    let mut newer = a.reg.clone();
    newer.protocol = 99;
    let e = ensure_registered(&hub, &newer, &a.data()).unwrap_err();
    assert_eq!(e.code, "hub_too_old");
    assert!(e.message.contains("keep-launcher"));
    assert!(!a.data.path().join(SECRET_FILE).exists());

    let both = a.reg.clone().money().guests();
    let e = ensure_registered(&hub, &both, &a.data()).unwrap_err();
    assert_eq!(e.status, Some(409));
    assert!(e.message.contains("guests"), "{e}");

    ensure_registered(&hub, &a.reg, &a.data()).unwrap();
    let b = App::new("carpick", "CarPick");
    let mut clash = b.reg.clone();
    clash.public_port = a.reg.public_port;
    let e = ensure_registered(&hub, &clash, &b.data()).unwrap_err();
    assert_eq!((e.status, e.code.as_str()), (Some(409), "port_taken"));
}

// ----- the backend --------------------------------------------------------------------------------

#[test]
fn at05_a_backend_made_with_the_library_refuses_requests_without_the_right_keep_hub_auth() {
    let f = Fixture::new();
    let hub = client(&f);
    let app = App::new("vacapick", "VacaPick");
    ensure_registered(&hub, &app.reg, &app.data()).unwrap();
    let port = app.backend.port;

    // straight to the backend: no secret, a guess, a phone's own identity
    let (s, b) = direct(port, &[]);
    assert_eq!((s, b["error"].as_str()), (403, Some("not_from_hub")));
    let (s, _) = direct(port, &[("Keep-Hub-Auth", "guess")]);
    assert_eq!(s, 403);
    let (s, _) = direct(
        port,
        &[
            ("Keep-Member", "1"),
            ("Keep-Device", "1"),
            ("Keep-Member-Name", "A"),
            ("Keep-Device-Name", "B"),
        ],
    );
    assert_eq!(s, 403);

    // through the hub, from a paired phone: who it is
    f.set_pin();
    let ann = f.add_member("Zoë Ann");
    let token = f.pair(ann, "vacapick", "Zoë's phone");
    let r = f.phone(
        "vacapick",
        "GET",
        "/api/items",
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Keep-Request-Id", "req-7"),
            ("Keep-Member", "99"),
        ],
        None,
    );
    assert_eq!(r.status, 200, "{}", r.text());
    let who = r.json();
    assert_eq!(who["member"], ann);
    assert_eq!(who["member_name"], "Zoë Ann");
    assert_eq!(who["device_name"], "Zoë's phone");
    assert_eq!(who["request_id"], "req-7");
    assert_eq!(who["guest_scope"], Value::Null);
    let devices = hub.devices().unwrap();
    assert_eq!(who["device"], devices[0].id);

    // after a new registration the old secret is refused
    let mut app2 = app.reg.clone();
    app2.version = "2.0.0".into();
    let old = std::fs::read(app.data.path().join(SECRET_FILE)).unwrap();
    ensure_registered(&hub, &app2, &app.data()).unwrap();
    let new = std::fs::read(app.data.path().join(SECRET_FILE)).unwrap();
    assert_ne!(old, new);
    assert_eq!(f.api("vacapick", &token, "GET", "/api/items").status, 200);
}

#[test]
fn a_guest_is_seen_with_its_scope() {
    let f = Fixture::new();
    let hub = client(&f);
    let app = App::new("vacapick", "VacaPick");
    ensure_registered(&hub, &app.reg.clone().guests(), &app.data()).unwrap();
    let invite = hub.make_invite("vacapick", "trip-12").unwrap();
    assert!(invite.id.is_some());
    assert_eq!(hub.invites().unwrap().len(), 1);
    let r = f.phone_json(
        "vacapick",
        "POST",
        "/hub/pair",
        &[],
        &json!({ "invite": invite.code, "name": "Bo" }),
    );
    assert_eq!(r.status, 200, "{}", r.text());
    let token = r.json()["token"].as_str().unwrap().to_string();
    let who = f.api("vacapick", &token, "GET", "/api/trip").json();
    assert_eq!(who["guest_scope"], "trip-12");
    assert!(hub.invites().unwrap().is_empty(), "used");
}

// ----- the Phones screen's requests -----------------------------------------------------------------

#[test]
fn the_phones_screen_works_through_the_library() {
    let f = Fixture::new();
    let hub = client(&f);
    let money = App::new("moneykeep", "MoneyKeep");
    ensure_registered(&hub, &money.reg.clone().money(), &money.data()).unwrap();

    // the PIN
    assert!(!hub.pin_is_set().unwrap());
    hub.set_pin(PIN, None).unwrap();
    assert!(hub.pin_is_set().unwrap());
    let e = hub.set_pin("13579135", Some("000000")).unwrap_err();
    assert_eq!(e.status.map(|s| s / 100), Some(4));
    assert!(!e.message.contains("000000") && !e.message.contains("13579135"));

    // members and grants
    let ann = hub.add_member("Ann").unwrap();
    hub.rename_member(ann, "Annie").unwrap();
    assert_eq!(hub.members().unwrap()[0].name, "Annie");
    let e = hub.give_grant(ann, "moneykeep", None).unwrap_err();
    assert_eq!(e.status.map(|s| s / 100), Some(4), "money needs the PIN");
    hub.give_grant(ann, "moneykeep", Some(PIN)).unwrap();
    assert_eq!(hub.grants().unwrap().len(), 1);

    // a pairing code: shown and opened, never printed
    let p = hub.make_pairing_code(ann, "moneykeep", Some(PIN)).unwrap();
    assert_eq!(p.code.len(), 9);
    assert!(p.url.contains(&format!(":{}", money.reg.public_port)));
    assert!(p.certificate_page.starts_with("http://"));
    assert!(!format!("{p:?}").contains(&p.code));
    hub.cancel_pairing_code(&p.code).unwrap();
    assert_eq!(
        hub.cancel_pairing_code(&p.code).unwrap_err().status,
        Some(404)
    );

    // a phone, then removed
    let code = hub
        .make_pairing_code(ann, "moneykeep", Some(PIN))
        .unwrap()
        .code;
    let r = f.phone_json(
        "moneykeep",
        "POST",
        "/hub/pair",
        &[],
        &json!({ "code": code, "pin": PIN, "device": "Ann's phone" }),
    );
    assert_eq!(r.status, 200);
    let token = r.json()["token"].as_str().unwrap().to_string();
    let d = hub.devices().unwrap();
    assert_eq!((d.len(), d[0].revoked), (1, None));
    hub.revoke_device(d[0].id).unwrap();
    assert!(hub.devices().unwrap()[0].revoked.is_some());
    assert_eq!(f.api("moneykeep", &token, "GET", "/api/x").status, 401);
    hub.remove_grant(ann, "moneykeep").unwrap();
    assert!(hub.grants().unwrap().is_empty());

    // the name, the address and Find the problem
    assert_eq!(hub.names().unwrap()["state"], "off");
    assert_eq!(hub.addresses().unwrap()["current"], "127.0.0.1");
    let problems = hub.find_problems().unwrap();
    assert_eq!(problems.stopped_at, None, "{problems:?}");
    assert_eq!(problems.checks.len(), 10);
    assert!(problems.failure().is_none());
    assert_eq!(hub.last_problems().unwrap(), problems);
    let status = hub.status().unwrap();
    assert_eq!(status.app("moneykeep").unwrap().state, "running");
    assert_eq!(status.names, "off");

    // anything else
    assert_eq!(hub.request("GET", "/pin", None).unwrap()["set"], true);
}

#[test]
fn a_stopped_backend_shows_in_the_status_and_in_find_the_problem() {
    let f = Fixture::new();
    let hub = client(&f);
    let app = App::new("vacapick", "VacaPick");
    ensure_registered(&hub, &app.reg, &app.data()).unwrap();
    let App { backend, .. } = app;
    drop(backend);
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(hub.status().unwrap().apps[0].state, "app_stopped");
    let p = hub.find_problems().unwrap();
    let failed = p.failure().unwrap();
    assert_eq!((failed.number, failed.code.as_str()), (9, "app_stopped"));
    assert_eq!(failed.action.as_ref().unwrap()["app"], "vacapick");
}
