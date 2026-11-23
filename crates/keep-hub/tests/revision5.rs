//! Stage 11: Revision 5 of `docs/specs/keep-hub.md` (other programs on this computer; fixes
//! from the code review). The test names give the acceptance test they cover (66 to 79).
//! Elsewhere: 67 in the library (`keep-hub-app`'s `auth.rs`), 71 to 73 in `addresses.rs`,
//! 74 in `registry.rs`, 78 in `linux.rs` (with 62, end to end) and 79 in `service.rs`
//! (end to end on Windows).

mod support;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use keep_hub_app::HubAuth;
use serde_json::{json, Value};
use support::{free_port, Fixture, TestApp};

// ----- a protocol 2 backend, and a program that only pretends to be one ---------------------

/// A program on an app's loopback port. With `auth` it is the app's backend made with the
/// library; without, a program that doesn't hold the secret and answers the hello anyway.
/// Every byte it receives is kept.
struct Backend {
    port: u16,
    received: Arc<Mutex<Vec<u8>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Backend {
    fn start(port: u16, auth: Option<HubAuth>) -> Backend {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let received = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (received, stop) = (received.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((s, peer)) => {
                            let (received, auth) = (received.clone(), auth.clone());
                            std::thread::spawn(move || serve(s, peer, auth.as_ref(), &received));
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(5)),
                    }
                }
            })
        };
        Backend {
            port,
            received,
            stop,
            thread: Some(thread),
        }
    }

    fn received(&self) -> Vec<u8> {
        self.received.lock().unwrap().clone()
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

/// One request's head and body from `s`, kept in `received`.
fn read_one(
    s: &mut TcpStream,
    received: &Mutex<Vec<u8>>,
) -> Option<(String, Vec<(String, String)>)> {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).unwrap_or(0) != 1 {
            received.lock().unwrap().extend(&head);
            return None;
        }
        head.push(b[0]);
    }
    received.lock().unwrap().extend(&head);
    let text = String::from_utf8_lossy(&head).to_string();
    let mut lines = text.split("\r\n");
    let path = lines.next()?.split(' ').nth(1)?.to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let len: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    if s.read_exact(&mut body).is_ok() {
        received.lock().unwrap().extend(&body);
    }
    Some((path, headers))
}

fn serve(mut s: TcpStream, peer: SocketAddr, auth: Option<&HubAuth>, received: &Mutex<Vec<u8>>) {
    // (on Windows an accepted connection inherits the listener's non-blocking mode)
    s.set_nonblocking(false).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let Some((mut path, mut headers)) = read_one(&mut s, received) else {
        return;
    };
    let Some(auth) = auth else {
        // the impostor: a 204 with a made-up proof, then it keeps listening
        let _ = s.write_all(
            format!(
                "HTTP/1.1 204 No Content\r\nKeep-Hub-Proof: {}\r\nKeep-Hub-Challenge: {}\r\nConnection: keep-alive\r\n\r\n",
                "00".repeat(32),
                "11".repeat(32)
            )
            .as_bytes(),
        );
        while read_one(&mut s, received).is_some() {}
        return;
    };
    if let Some(hello) = auth.hello(peer, &path, &headers) {
        let Ok(h) = hello else {
            let _ = s.write_all(b"HTTP/1.1 403 X\r\nContent-Length: 0\r\n\r\n");
            return;
        };
        let mut out = format!("HTTP/1.1 {} No Content\r\n", h.status);
        for (k, v) in &h.headers {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str("\r\n");
        let _ = s.write_all(out.as_bytes());
        match read_one(&mut s, received) {
            Some((p, h)) => (path, headers) = (p, h),
            None => return,
        }
    }
    let (status, body) = match auth.check_from(peer, &headers) {
        Ok(Some(c)) => (200, json!({ "member": c.member, "path": path })),
        Ok(None) => (200, json!({ "files": path })),
        Err(r) => (r.status, json!({ "error": r.code })),
    };
    let body = body.to_string();
    let _ = write!(
        s,
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Register `id` at `protocol` with its backend on `loopback`: the answer's secret.
fn register_at(f: &Fixture, id: &str, loopback: u16, public: u16, protocol: u32) -> String {
    let v = f.admin_ok(
        "POST",
        "/admin/v1/apps",
        Some(json!({
            "id": id, "title": format!("Test {id}"), "version": "0.1.0",
            "protocol": protocol, "public_port": public, "loopback_port": loopback,
            "money": false, "guests": false,
        })),
    );
    v["secret"].as_str().unwrap().to_string()
}

fn check_9(f: &Fixture) -> Value {
    let r = f.admin_ok("POST", "/admin/v1/problems", None);
    r["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["number"] == 9)
        .cloned()
        .unwrap_or(Value::Null)
}

// ----- A: protocol 2 ----------------------------------------------------------------------

/// Acceptance test 66.
#[test]
fn at66_a_program_without_the_secret_gets_the_hello_and_nothing_else() {
    let f = Fixture::new();
    f.set_pin();
    let impostor = Backend::start(0, None);
    let loopback = impostor.port;
    let secret = register_at(&f, "trips", loopback, free_port(), 2);
    let member = f.add_member("Sam");
    let token = f.pair(member, "trips", "Sam's phone");
    let bearer = format!("Bearer {token}");

    let r = f.phone(
        "trips",
        "POST",
        "/api/items?from=phone",
        &[("Authorization", &bearer), ("X-From-Phone", "yes")],
        Some(b"the phone's body"),
    );
    assert_eq!((r.status, r.error().as_str()), (502, "app_unverified"));
    assert!(r.json()["message"].as_str().unwrap().contains("Test trips"));
    let got = impostor.received();
    let text = String::from_utf8_lossy(&got);
    assert!(
        text.starts_with("GET /_keep-hub/hello HTTP/1.1\r\n"),
        "{text}"
    );
    for never in [
        secret.as_bytes(),
        b"/api/items",
        b"the phone's body",
        b"X-From-Phone",
        token.as_bytes(),
        b"Keep-Hub-Auth",
        b"Keep-Member",
    ] {
        assert!(!contains(&got, never), "{}", String::from_utf8_lossy(never));
    }
    // one line naming the app, without the challenge or the proof
    let lines: Vec<String> = f
        .log_lines()
        .into_iter()
        .filter(|l| l.contains("a program that is not Test trips"))
        .collect();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(!lines[0].contains(&"00".repeat(32)) && !lines[0].contains(&"11".repeat(32)));
    // a request without a token is refused the same way
    assert_eq!(
        f.phone("trips", "GET", "/index.html", &[], None).error(),
        "app_unverified"
    );
    // check 9 fails for that app
    let c9 = check_9(&f);
    assert_eq!(
        (c9["status"].as_str(), c9["code"].as_str()),
        (Some("failed"), Some("app_unverified")),
        "{c9}"
    );

    // the real backend on the same port
    drop(impostor);
    let real = Backend::start(loopback, Some(HubAuth::with_protocol(&secret, 2)));
    let r = f.phone(
        "trips",
        "POST",
        "/api/items",
        &[("Authorization", &bearer)],
        Some(b"the phone's body"),
    );
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json()["member"], member);
    assert_eq!(
        f.phone("trips", "GET", "/index.html", &[], None).status,
        200
    );
    let got = real.received();
    assert!(contains(&got, b"the phone's body"));
    assert!(contains(&got, b"Keep-Hub-Auth: 2 "));
    assert!(
        !contains(&got, secret.as_bytes()),
        "the secret never crosses"
    );
    assert_eq!(check_9(&f)["status"], "ok");
}

/// Acceptance test 68: a protocol 1 app works as before, with no hello; a protocol 2 app
/// registered again at protocol 1 with the admin token alone is refused.
#[test]
fn at68_protocol_1_works_as_before_and_going_down_needs_an_administrator() {
    let f = Fixture::new();
    let app = TestApp::start("vacapick");
    f.register(&app, false, false);
    assert_eq!(
        f.phone("vacapick", "GET", "/index.html", &[], None).status,
        200
    );
    let seen = app.seen();
    assert!(seen.iter().all(|s| s.target != "/_keep-hub/hello"));
    assert!(
        seen.iter().all(|s| s.trusted),
        "the secret in Keep-Hub-Auth"
    );
    let status = f.admin_ok("GET", "/admin/v1/status", None);
    assert_eq!(status["protocols"], json!([1, 2]));

    let real = Backend::start(0, None);
    let public = free_port();
    register_at(&f, "trips", real.port, public, 2);
    let down = json!({
        "id": "trips", "title": "Test trips", "version": "0.1.0", "protocol": 1,
        "public_port": public, "loopback_port": real.port, "money": false, "guests": false,
    });
    let r = f.admin_with(None, "POST", "/admin/v1/apps", Some(down.clone()));
    assert_eq!(
        (r.status, r.error().as_str()),
        (401, "administrator_needed")
    );
    let apps = f.admin_ok("GET", "/admin/v1/apps", None);
    let trips = apps["apps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == "trips")
        .unwrap()
        .clone();
    assert_eq!(trips["protocol"], 2, "unchanged");
    // with an administrator it may
    assert_eq!(
        f.admin_ok("POST", "/admin/v1/apps", Some(down))["protocol"],
        1
    );
}

// ----- C: registering again ------------------------------------------------------------------

/// Acceptance test 70.
#[test]
fn at70_moving_an_apps_ports_or_flags_needs_an_administrator() {
    let f = Fixture::new();
    let app = TestApp::start("vacapick");
    let public = f.register(&app, false, false);
    let base = Fixture::registration(&app, public, false, false);
    let before = f.admin_ok("GET", "/admin/v1/apps", None);
    for (key, value) in [
        ("public_port", json!(free_port())),
        ("loopback_port", json!(free_port())),
        ("money", json!(true)),
        ("guests", json!(true)),
        ("pairing", json!("code")),
    ] {
        let mut changed = base.clone();
        changed[key] = value;
        let r = f.admin_with(None, "POST", "/admin/v1/apps", Some(changed));
        assert_eq!(
            (r.status, r.error().as_str()),
            (401, "administrator_needed"),
            "{key}"
        );
    }
    assert_eq!(
        f.admin_ok("GET", "/admin/v1/apps", None),
        before,
        "nothing changed"
    );
    assert!(app.seen().is_empty() || app.seen().iter().all(|s| s.trusted));
    // only a new version (and title): the token alone
    let mut update = base.clone();
    update["version"] = json!("0.2.0");
    update["title"] = json!("Test vacapick 2");
    let r = f.admin_with(None, "POST", "/admin/v1/apps", Some(update));
    assert_eq!(r.status, 200, "{}", r.text());
    // and a higher protocol too
    let mut up = base;
    up["version"] = json!("0.3.0");
    up["protocol"] = json!(2);
    let r = f.admin_with(None, "POST", "/admin/v1/apps", Some(up));
    assert_eq!(r.status, 200, "{}", r.text());
}

// ----- B: the library checks who listens on the admin address ----------------------------

/// A program on a loopback port that keeps whatever is sent to it.
fn listening_program() -> (SocketAddr, Arc<Mutex<Vec<u8>>>) {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = l.local_addr().unwrap();
    let got = Arc::new(Mutex::new(Vec::new()));
    let kept = got.clone();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { break };
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            kept.lock().unwrap().extend(buf);
        }
    });
    (addr, got)
}

/// Acceptance test 69: told to expect another account than the one listening (this test's
/// own program is not Keep Hub's service), the library sends nothing at all and answers the
/// plain error. (A Mac isn't checked yet: owner decision 2026-11-23.)
#[cfg(any(windows, target_os = "linux"))]
#[test]
fn at69_the_library_sends_nothing_to_a_program_that_isnt_the_hubs_service() {
    use keep_hub_app::{HubClient, Listener};
    let (addr, got) = listening_program();
    let hub = HubClient::at(addr, "the-admin-token").expecting(Listener::KeepHub);
    for e in [
        hub.status().unwrap_err(),
        hub.sign_in("Ann", "a password of hers").unwrap_err(),
        hub.set_up("Ann", "a password of hers", "246810")
            .unwrap_err(),
    ] {
        assert_eq!(e.code, "hub_not_confirmed");
        assert_eq!(
            e.message,
            format!(
                "Can't confirm that the program on this computer's port {} is Keep Hub.",
                addr.port()
            )
        );
    }
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        got.lock().unwrap().is_empty(),
        "no token, no name, no password"
    );
    // told to expect this account (development), the same program gets the request
    let dev = HubClient::at(addr, "the-admin-token").expecting(Listener::ThisAccount);
    let _ = dev.status();
    std::thread::sleep(Duration::from_millis(300));
    assert!(contains(&got.lock().unwrap(), b"Bearer the-admin-token"));
}

// ----- E: administrator sessions -----------------------------------------------------------

/// An A request with `session`: whether it was taken.
fn a_request_works(f: &Fixture, session: &str) -> bool {
    let r = f.admin_with(
        Some(session),
        "PUT",
        "/admin/v1/pin",
        Some(json!({ "pin": support::PIN })),
    );
    match r.status {
        200 => true,
        401 => {
            assert_eq!(r.error(), "administrator_needed");
            false
        }
        _ => panic!("{}", r.text()),
    }
}

/// `keep-hub reset-administrator`, as a person runs it on the computer.
fn reset(f: &Fixture, name: &str, password: &str) {
    use std::process::{Command, Stdio};
    let mut child = Command::new(env!("CARGO_BIN_EXE_keep-hub"))
        .args(["reset-administrator", "--name", name, "--data"])
        .arg(f.dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{password}\n").as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Acceptance test 75.
#[test]
fn at75_a_reset_ends_the_session_and_a_session_lasts_at_most_12_hours() {
    let f = Fixture::new();
    let s = f.session_of(support::ADMIN_NAME, support::ADMIN_PASSWORD);
    let other = f.session_of(support::ADMIN_NAME, support::ADMIN_PASSWORD);
    assert!(a_request_works(&f, &s));
    // someone else's wrong passwords pause the administrator's sign-in
    for _ in 0..5 {
        f.sign_in(support::ADMIN_NAME, "not the password");
    }
    assert_eq!(
        f.sign_in(support::ADMIN_NAME, support::ADMIN_PASSWORD)
            .status,
        429
    );

    // the person resets the password on the computer, with the hub running throughout
    reset(&f, support::ADMIN_NAME, "a-new-password-75");
    assert!(!a_request_works(&f, &s), "ended at its next use");
    assert!(!a_request_works(&f, &other));
    // the pause is cleared too, and the new password signs in
    let s = f.session_of(support::ADMIN_NAME, "a-new-password-75");
    assert!(a_request_works(&f, &s));

    // used every few minutes, a session still ends 12 hours after sign-in
    let s = f.session_of(support::ADMIN_NAME, "a-new-password-75");
    for _ in 0..71 {
        f.advance_minutes(10);
        assert!(a_request_works(&f, &s));
    }
    f.advance_minutes(9);
    assert!(a_request_works(&f, &s), "11 hours 59 minutes");
    f.advance_minutes(1);
    assert!(!a_request_works(&f, &s), "12 hours after sign-in");
}

/// Revision 5 E: setting an administrator's password at the admin address ends their other
/// sessions; the caller's own session goes on.
#[test]
fn setting_a_password_ends_that_administrators_other_sessions() {
    let f = Fixture::new();
    let mine = f.session_of(support::ADMIN_NAME, support::ADMIN_PASSWORD);
    let elsewhere = f.session_of(support::ADMIN_NAME, support::ADMIN_PASSWORD);
    let me = f.admin_ok("GET", "/admin/v1/members", None)["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["name"] == support::ADMIN_NAME)
        .unwrap()["id"]
        .clone();
    let r = f.admin_with(
        Some(&mine),
        "PUT",
        &format!("/admin/v1/members/{me}/password"),
        Some(json!({ "password": "another-password-1" })),
    );
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(a_request_works(&f, &mine));
    assert!(!a_request_works(&f, &elsewhere));
}

// ----- F: wrong pairing tries through the tunnel ---------------------------------------------

/// Acceptance test 76. (127.0.0.2 stands for the tunnel's loopback listener, so the home
/// address 127.0.0.1 is a listener of its own; a Mac has no 127.0.0.2 unless it is added.)
#[cfg(not(target_os = "macos"))]
#[test]
fn at76_the_tunnels_wrong_tries_and_the_homes_are_counted_apart() {
    use keep_hub::hub::{MAX_FAILURES, MAX_FAILURES_ALL};
    let mut f = Fixture::new();
    f.tunnel_listen = Ipv4Addr::new(127, 0, 0, 2);
    f.restart();
    let app = TestApp::start("vacapick");
    f.register(&app, false, false);
    f.set_pin();
    let sam = f.add_member("Sam");
    let wrong = json!({ "code": "ZZZZ-ZZZZ", "pin": support::PIN, "device": "phone" });
    // a hundred wrong tries through the tunnel, from visitors who stay under ten each
    for i in 0..MAX_FAILURES_ALL {
        let visitor = format!("198.51.{}.{}", 100 + i / MAX_FAILURES, i % MAX_FAILURES);
        let r = f.tunnel_json(
            "vacapick",
            "POST",
            "/hub/pair",
            &[("CF-Connecting-IP", &visitor)],
            &wrong,
        );
        assert_eq!(r.status, 403, "{i}: {}", r.text());
    }
    // pairing through the tunnel is paused for everyone there
    let code = f.code(sam, "vacapick");
    let pair = json!({ "code": code, "pin": support::PIN, "device": "phone" });
    let r = f.tunnel_json(
        "vacapick",
        "POST",
        "/hub/pair",
        &[("CF-Connecting-IP", "203.0.113.9")],
        &pair,
    );
    assert_eq!((r.status, r.error().as_str()), (429, "pairing_paused"));
    // a phone on the home address still pairs
    let r = f.phone_json("vacapick", "POST", "/hub/pair", &[], &pair);
    assert_eq!(r.status, 200, "{}", r.text());

    // the other way: a hundred on the home address don't pause the tunnel
    let mut f = Fixture::new();
    f.tunnel_listen = Ipv4Addr::new(127, 0, 0, 2);
    f.restart();
    let app = TestApp::start("vacapick");
    f.register(&app, false, false);
    f.set_pin();
    let sam = f.add_member("Sam");
    for _ in 0..MAX_FAILURES_ALL {
        f.phone_json("vacapick", "POST", "/hub/pair", &[], &wrong);
    }
    let code = f.code(sam, "vacapick");
    let pair = json!({ "code": code, "pin": support::PIN, "device": "phone" });
    assert_eq!(
        f.phone_json("vacapick", "POST", "/hub/pair", &[], &pair)
            .error(),
        "pairing_paused"
    );
    let r = f.tunnel_json(
        "vacapick",
        "POST",
        "/hub/pair",
        &[("CF-Connecting-IP", "203.0.113.9")],
        &pair,
    );
    assert_eq!(r.status, 200, "{}", r.text());
}

// ----- G: a code-alone app on the certificate page ------------------------------------------

/// Acceptance test 77.
#[test]
fn at77_a_code_alone_apps_code_stays_off_the_certificate_page() {
    let f = Fixture::new();
    let app = TestApp::start("ez");
    let mut reg = Fixture::registration(&app, free_port(), false, false);
    reg["pairing"] = json!("code");
    let v = f.admin_ok("POST", "/admin/v1/apps", Some(reg));
    app.set_secret(v["secret"].as_str().unwrap());
    let sam = f.add_member("Sam");
    let made = f.admin_ok(
        "POST",
        "/admin/v1/pairing-codes",
        Some(json!({ "member": sam, "app": "ez" })),
    );
    let code = made["code"].as_str().unwrap().to_string();
    let page_url = made["certificate_page"].as_str().unwrap();
    assert!(page_url.ends_with("/?app=ez"), "{page_url}");
    assert!(!page_url.contains(&code) && !page_url.contains(&code.replace('-', "")));
    // the HTTPS addresses (by name, by address) still carry it after `#`
    assert!(made["url_by_address"]
        .as_str()
        .unwrap()
        .contains(&format!("#pair={code}")));

    // the page given `pair=` for that app: its link opens the app without the code
    let helper = f.hub().helper().unwrap();
    let html = support::http(
        helper,
        "GET",
        &format!("/?app=ez&pair={code}"),
        &[("User-Agent", "Android")],
        None,
    )
    .text();
    assert!(html.contains("Step 2"), "{html}");
    assert!(!html.contains(&code), "the code isn't echoed");
    assert!(!html.contains("#pair="));
    assert!(html.contains("type the code shown on the hub computer"));

    // an app that pairs with the code and the PIN keeps the code in the page, as before
    let trips = TestApp::start("trips");
    f.register(&trips, false, false);
    f.set_pin();
    let made = f.admin_ok(
        "POST",
        "/admin/v1/pairing-codes",
        Some(json!({ "member": sam, "app": "trips" })),
    );
    let code = made["code"].as_str().unwrap();
    assert!(made["certificate_page"]
        .as_str()
        .unwrap()
        .ends_with(&format!("pair={code}")));
}
