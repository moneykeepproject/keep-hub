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
                        "class": c.class,
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

/// The library's client on the fixture's hub, signed in as its administrator.
fn client(f: &Fixture) -> HubClient {
    let hub = HubClient::at(f.hub().admin, &f.admin_token);
    hub.sign_in(support::ADMIN_NAME, support::ADMIN_PASSWORD)
        .unwrap();
    hub
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

/// On Windows an app believes a hub's folder only when the administrators, SYSTEM or a
/// service own it (stage 7). A test's temporary folder belongs to whoever runs the test: on a
/// person's computer it is theirs, so it is refused as a folder someone else could have
/// planted; when the tests run elevated (GitHub's Windows runner) the administrators own it,
/// so it is believed. This shows the refusal where there is one and answers whether the
/// folder is believed. Elsewhere it always is.
fn believed(data: &Path) -> bool {
    if keep_hub::owner::protected(data).is_ok() {
        return true;
    }
    match find(data) {
        Found::NoAccess(e) => assert_eq!(e.code, "not_the_hubs_folder", "{e}"),
        other => panic!("a folder the person owns must be refused on Windows: {other:?}"),
    }
    assert!(matches!(offer(data), Offer::CantUse(e) if e.code == "not_the_hubs_folder"));
    false
}

#[test]
fn an_app_finds_no_hub_a_stopped_hub_and_a_running_one() {
    let empty = tempfile::tempdir().unwrap();
    assert!(matches!(find(empty.path()), Found::NotInstalled));

    let f = hub_on_known_port();
    if believed(f.dir.path()) {
        match find(f.dir.path()) {
            Found::Running(hub, status) => {
                assert_eq!(hub.addr(), f.hub().admin);
                assert!(status.accepts(keep_hub_app::PROTOCOL));
                assert_eq!(status.address.as_deref(), Some("127.0.0.1"));
                assert!(status.apps.is_empty());
            }
            other => panic!("{other:?}"),
        }
    }
    // (what `find` does after the owner check, on every system)
    let hub = HubClient::open(f.dir.path()).unwrap();
    assert_eq!(hub.addr(), f.hub().admin);
    assert!(hub.status().unwrap().accepts(keep_hub_app::PROTOCOL));
    // stopped: found, and offered to start
    let admin = f.hub().admin;
    let stopped = tempfile::tempdir().unwrap();
    for file in ["hub.json", "admin.token"] {
        std::fs::copy(f.dir.path().join(file), stopped.path().join(file)).unwrap();
    }
    drop(f); // the hub stops
    std::thread::sleep(Duration::from_millis(100));
    if !believed(stopped.path()) {
        let hub = HubClient::open(stopped.path()).unwrap();
        assert_eq!(hub.addr(), admin);
        assert_eq!(hub.status().unwrap_err().code, "hub_unreachable");
        return;
    }
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
    if believed(f.dir.path()) {
        assert!(matches!(offer(f.dir.path()), Offer::Ready(_, _)));
    }

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
    if believed(stopped.path()) {
        match offer(stopped.path()) {
            Offer::StartHub(hub) => {
                assert_eq!(hub.status().unwrap_err().code, "hub_unreachable")
            }
            other => panic!("{other:?}"),
        }
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
    assert_eq!(who["class"], "standard");
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
    assert_eq!(who["class"], "guest");
    assert!(hub.invites().unwrap().is_empty(), "used");
}

// ----- the Phones screen's requests -----------------------------------------------------------------

#[test]
fn the_phones_screen_works_through_the_library() {
    let f = Fixture::new();
    let hub = client(&f);
    let money = App::new("moneykeep", "MoneyKeep");
    ensure_registered(&hub, &money.reg.clone().money(), &money.data()).unwrap();

    // the PIN (set at the first set-up; an administrator sets a new one without the old)
    assert!(hub.pin_is_set().unwrap());
    hub.set_pin(PIN).unwrap();
    let e = hub.set_pin("12ab").unwrap_err();
    assert_eq!(e.status, Some(400));
    assert!(!e.message.contains("12ab"));

    // members and grants
    let ann = hub.add_member("Ann").unwrap();
    hub.rename_member(ann, "Annie").unwrap();
    let members = hub.members().unwrap();
    assert_eq!(
        (members[1].name.as_str(), members[1].class.as_str()),
        ("Annie", "standard")
    );
    assert_eq!(members[0].class, keep_hub_app::ADMINISTRATOR);
    assert!(members[0].password_set);
    hub.give_grant(ann, "moneykeep").unwrap();
    assert_eq!(hub.grants().unwrap().len(), 1);

    // a pairing code: shown and opened, never printed
    let p = hub.make_pairing_code(ann, "moneykeep").unwrap();
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
    let code = hub.make_pairing_code(ann, "moneykeep").unwrap().code;
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

// ----- stage 9: Revisions 2 and 3 through the library ---------------------------------------------

/// An open household, a `code` app, then `secure` and a `code_and_pin` app (tests 45, 47,
/// 49, 50 and 54 as an app's desktop program meets them).
#[test]
fn an_open_household_and_a_code_app_through_the_library() {
    let f = Fixture::not_set_up();
    let hub = HubClient::at(f.hub().admin, &f.admin_token);
    let first = hub.set_up_open(support::ADMIN_NAME).unwrap();
    assert_eq!(first.class, keep_hub_app::ADMINISTRATOR);
    assert!(!hub.signed_in(), "no session in an open household");
    let status = hub.status().unwrap();
    assert!(status.household_is_open());
    assert_eq!(
        status.code_page.as_deref(),
        Some("https://getmoneykeep.org/phone-access/")
    );
    assert_eq!(status.code_needed, Some(true));

    let ez = App::new("ez", "Test EZ");
    let ez_reg = ez.reg.clone().by_code_alone();
    ensure_registered(&hub, &ez_reg, &ez.data()).unwrap();
    let status = hub.status().unwrap();
    assert_eq!(
        status.app("ez").unwrap().app.pairing.as_deref(),
        Some(keep_hub_app::CODE)
    );
    // nothing changed: not registered again
    assert!(!ensure_registered(&hub, &ez_reg, &ez.data()).unwrap().now);
    let sam = hub.add_member("Sam").unwrap();
    let code = hub.make_pairing_code(sam, "ez").unwrap().code;
    let r = f.phone_json(
        "ez",
        "POST",
        "/hub/pair",
        &[],
        &json!({ "code": code, "device": "phone" }),
    );
    assert_eq!(r.status, 200, "{}", r.text());

    // a code_and_pin app waits for a secured household
    let trips = App::new("trips", "Test Trips");
    let e = ensure_registered(&hub, &trips.reg, &trips.data()).unwrap_err();
    assert_eq!(e.code, "household_not_secured");
    hub.secure(support::ADMIN_NAME, support::ADMIN_PASSWORD, PIN)
        .unwrap();
    assert!(hub.signed_in());
    assert!(!hub.status().unwrap().household_is_open());
    ensure_registered(&hub, &trips.reg, &trips.data()).unwrap();
}

/// A hub older than Revision 2, faked: its answers carry no `pairing`.
fn older_hub() -> (std::net::SocketAddr, Arc<AtomicBool>) {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    let registered = Arc::new(AtomicBool::new(false));
    let seen = registered.clone();
    std::thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { break };
            let mut buf = [0u8; 8192];
            let n = s.read(&mut buf).unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            let body = if head.starts_with("GET /admin/v1/status") {
                json!({ "hub": "keep-hub", "version": "0.1.0", "protocols": [1],
                        "address": "127.0.0.1", "names": "off", "apps": [] })
            } else if head.starts_with("POST /admin/v1/apps") {
                seen.store(true, Ordering::SeqCst);
                json!({ "id": "ez", "secret": "ab".repeat(32), "protocol": 1,
                        "hub_version": "0.1.0" })
            } else {
                json!({ "error": "not_found", "message": "no" })
            };
            let body = body.to_string();
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (addr, registered)
}

/// Revision 2 A: an app that asked for `code` and gets an answer without `pairing` is
/// talking to an older hub, and must not offer pairing.
#[test]
fn a_code_app_on_an_older_hub_is_told_to_update_it() {
    let (addr, registered) = older_hub();
    let hub = HubClient::at(addr, "token");
    let data = tempfile::tempdir().unwrap();
    let r = Registration::new("ez", "Test EZ", "1.0.0", 14444, 24444).by_code_alone();
    let e = ensure_registered(&hub, &r, data.path()).unwrap_err();
    assert_eq!(e.code, "hub_too_old");
    assert!(e.message.contains("Update it"), "{e}");
    assert!(registered.load(Ordering::SeqCst));
    // the secret is kept, so the backend still checks what the hub forwards
    assert!(data.path().join(SECRET_FILE).is_file());
    // a code_and_pin app is fine with that hub
    let r = Registration::new("trips", "Test Trips", "1.0.0", 16443, 26443);
    ensure_registered(&hub, &r, data.path()).unwrap();
}

/// Revision 3, through the library: the code page can be changed, and a bad one isn't.
#[test]
fn the_code_page_through_the_library() {
    let f = hub_on_known_port();
    let hub = client(&f);
    let e = hub.set_code_page("http://example.org/").unwrap_err();
    assert_eq!(e.code, "bad_code_page");
    hub.set_code_page("https://example.org/codes").unwrap();
    assert_eq!(
        hub.status().unwrap().code_page.as_deref(),
        Some("https://example.org/codes")
    );
}

// ----- stage 10: Revision 4 through the library ---------------------------------------------------

/// What ServicesKeep calls: a probe and whether it was seen, the tunnel hostname, and Fix.
#[test]
fn the_probe_the_tunnel_hostname_and_fix_through_the_library() {
    let f = hub_on_known_port();
    let hub = client(&f);
    let p = hub.probe().unwrap();
    assert_eq!(p.minutes, 10);
    assert!(!hub.probe_seen(&p.nonce).unwrap().seen);
    let r = support::http(
        f.hub().helper().unwrap(),
        "GET",
        &format!("/_probe/{}", p.nonce),
        &[],
        None,
    );
    assert_eq!(r.status, 204);
    let s = hub.probe_seen(&p.nonce).unwrap();
    assert!(s.seen);
    assert_eq!(s.source.as_deref(), Some("this_computer"));
    assert_eq!(
        hub.probe_seen("0123456789abcdef0123").unwrap_err().code,
        "no_such_probe"
    );

    assert_eq!(
        hub.set_tunnel_hostname("hub.example.org")
            .unwrap()
            .as_deref(),
        Some("hub.example.org")
    );
    let st = hub.status().unwrap();
    assert_eq!(
        st.tunnel.and_then(|t| t.hostname).as_deref(),
        Some("hub.example.org")
    );
    assert_eq!(
        hub.set_tunnel_hostname("bad name").unwrap_err().code,
        "bad_hostname"
    );
    hub.clear_tunnel_hostname().unwrap();
    assert_eq!(hub.status().unwrap().tunnel.unwrap().hostname, None);

    // on Windows Fix needs Windows' prompt (owner decision 2026-11-22)
    *f.machine.firewall.lock().unwrap() = Some(keep_hub::machine::FirewallScan::default());
    assert_eq!(hub.fix(4).unwrap_err().code, "permission_needed");
    // a Mac: no firewall the hub manages, nothing to fix
    *f.machine.os.lock().unwrap() = keep_hub::machine::Os::Mac;
    *f.machine.firewall.lock().unwrap() = None;
    let c = hub.fix(4).unwrap();
    assert_eq!((c.number, c.status.as_str()), (4, "ok"));
    assert_eq!(hub.fix(9).unwrap_err().code, "no_fix");
    // names off: no tunnel from the name service
    assert_eq!(hub.make_moneykeep_tunnel().unwrap_err().code, "not_found");
}
