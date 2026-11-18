//! Stage 1 of the hub, proven with two small test apps: the relay, the registry (apps,
//! members, grants, devices), pairing, guests and the admin address. The test names give
//! the acceptance test of `docs/specs/keep-hub.md` they cover.
//!
//! Everything runs on 127.0.0.1 with keys in memory; nothing leaves this computer.

mod support;

use serde_json::{json, Value};
use support::{free_port, Fixture, TestApp, PIN};

/// A hub with two registered test apps, a PIN, and one member.
fn two_apps() -> (Fixture, TestApp, TestApp, u32) {
    let f = Fixture::new();
    let alpha = TestApp::start("alpha");
    let beta = TestApp::start("beta");
    f.register(&alpha, false, false);
    f.register(&beta, false, false);
    f.set_pin();
    let sam = f.add_member("Sam");
    (f, alpha, beta, sam)
}

fn pair_request(code: &str, pin: &str) -> Value {
    json!({ "code": code, "pin": pin, "device": "Sam's phone" })
}

// ----- the relay --------------------------------------------------------------------------------

#[test]
fn at01_each_port_reaches_its_own_app_and_never_the_other() {
    let (f, alpha, beta, _) = two_apps();
    assert_ne!(f.port("alpha"), f.port("beta"));

    let a = f.phone("alpha", "GET", "/index.html", &[], None);
    assert_eq!(
        (a.status, a.text().as_str()),
        (200, "alpha file /index.html")
    );
    assert_eq!(a.header("x-app"), Some("alpha"));
    let b = f.phone("beta", "GET", "/index.html?v=2", &[], None);
    assert_eq!(
        (b.status, b.text().as_str()),
        (200, "beta file /index.html?v=2")
    );

    assert_eq!(alpha.seen().len(), 1);
    assert_eq!(beta.seen().len(), 1);
    assert_eq!(alpha.seen()[0].target, "/index.html");
    assert_eq!(beta.seen()[0].target, "/index.html?v=2");
    // the backend trusted the request: the hub sent the secret it shares with that app only
    assert!(alpha.seen()[0].trusted && beta.seen()[0].trusted);
    assert_ne!(alpha.secret(), beta.secret());
    // a file needs no token, and carries nobody's name
    assert_eq!(alpha.seen()[0].header("keep-member"), None);
    // whatever the backend says, the hub closes after each answer
    assert_eq!(a.header("connection"), Some("close"));
    // HEAD passes too, without a body
    let h = f.phone("alpha", "HEAD", "/index.html", &[], None);
    assert_eq!((h.status, h.body.len()), (200, 0));
}

#[test]
fn at02_a_token_for_one_app_is_refused_on_the_other_and_its_backend_gets_nothing() {
    let (f, alpha, beta, sam) = two_apps();
    let token = f.pair(sam, "alpha", "Sam's phone");
    let ok = f.api("alpha", &token, "GET", "/api/items");
    assert_eq!(ok.status, 200);
    assert_eq!(ok.json()["app"], "alpha");

    let r = f.api("beta", &token, "GET", "/api/items");
    assert_eq!((r.status, r.error().as_str()), (403, "no_access"));
    assert!(beta.seen().is_empty());
    // whoami follows the same rule
    assert_eq!(f.api("beta", &token, "GET", "/hub/whoami").status, 403);
    // even with a grant for beta, the device was paired for alpha only
    f.admin_ok(
        "POST",
        "/admin/v1/grants",
        Some(json!({ "member": sam, "app": "beta" })),
    );
    assert_eq!(f.api("beta", &token, "GET", "/api/items").status, 403);
    assert!(beta.seen().is_empty());
    assert_eq!(alpha.seen().len(), 1);
}

#[test]
fn at03_api_without_a_token_or_with_a_revoked_one_is_not_paired() {
    let (f, alpha, _beta, sam) = two_apps();
    let r = f.phone("alpha", "GET", "/api/items", &[], None);
    assert_eq!((r.status, r.error().as_str()), (401, "not_paired"));
    let r = f.api("alpha", "not-a-token", "GET", "/api/items");
    assert_eq!((r.status, r.error().as_str()), (401, "not_paired"));
    let r = f.phone(
        "alpha",
        "POST",
        "/api/items",
        &[("Authorization", "Basic abc")],
        Some(b"{}"),
    );
    assert_eq!(r.status, 401);
    // the hub's own answers carry its headers
    assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(r.header("referrer-policy"), Some("no-referrer"));

    let token = f.pair(sam, "alpha", "Sam's phone");
    assert_eq!(f.api("alpha", &token, "GET", "/api/items").status, 200);
    let devices = f.admin_ok("GET", "/admin/v1/devices", None);
    let id = devices["devices"][0]["id"].as_u64().unwrap();
    f.admin_ok("DELETE", &format!("/admin/v1/devices/{id}"), None);
    let r = f.api("alpha", &token, "GET", "/api/items");
    assert_eq!((r.status, r.error().as_str()), (401, "not_paired"));
    // the row stays for the list
    let devices = f.admin_ok("GET", "/admin/v1/devices", None);
    assert!(devices["devices"][0]["revoked"].is_i64());
    assert_eq!(
        f.admin("DELETE", &format!("/admin/v1/devices/{id}"), None)
            .status,
        404
    );
    // only the one good request reached the backend
    assert_eq!(alpha.seen().len(), 1);
}

#[test]
fn at04_a_forwarded_request_carries_the_hubs_headers_and_not_the_phones() {
    let (f, alpha, _beta, _) = two_apps();
    let zoe = f.add_member("Zoë");
    let token = f.pair(zoe, "alpha", "Zoë's phone");
    let auth = format!("Bearer {token}");
    let r = f.phone(
        "alpha",
        "POST",
        "/api/items?list=1",
        &[
            ("Authorization", &auth),
            ("Keep-Member", "1"),
            ("keep-member-name", "Admin"),
            ("Keep-Hub-Auth", "a-guess"),
            ("Keep-Guest-Scope", "everything"),
            ("Keep-Request-Id", "req-0042"),
            ("Content-Type", "application/json"),
            ("X-Client", "test"),
        ],
        Some(br#"{"note":"milk"}"#),
    );
    assert_eq!(r.status, 200, "{}", r.text());
    let got = &r.json()["headers"];
    assert_eq!(got["keep-hub-auth"], alpha.secret());
    assert_eq!(got["keep-member"], zoe.to_string());
    assert_eq!(got["keep-member-name"], "Zo%C3%AB");
    assert_eq!(got["keep-device-name"], "Zo%C3%AB%27s%20phone");
    assert_eq!(got["keep-request-id"], "req-0042");
    assert!(got["keep-device"].is_string());
    assert!(got.get("authorization").is_none());
    assert!(got.get("keep-guest-scope").is_none());
    assert_eq!(got["x-client"], "test");
    assert_eq!(got["content-type"], "application/json");
    assert_eq!(r.json()["body"], r#"{"note":"milk"}"#);
    assert_eq!(r.json()["target"], "/api/items?list=1");

    // exactly one of each reached the backend, and the token never did
    let seen = alpha.seen();
    let s = seen.last().unwrap();
    for name in [
        "keep-hub-auth",
        "keep-member",
        "keep-member-name",
        "keep-device",
    ] {
        let n = s
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .count();
        assert_eq!(n, 1, "{name}");
    }
    assert!(s
        .headers
        .iter()
        .all(|(_, v)| !v.contains(&token) && v != "a-guess"));

    // whoami: the member's name, the app, the hub's version
    let who = f.api("alpha", &token, "GET", "/hub/whoami");
    assert_eq!(who.status, 200);
    let who = who.json();
    assert_eq!(who["member"]["name"], "Zoë");
    assert_eq!(who["app"]["id"], "alpha");
    assert_eq!(who["hub"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        f.phone("alpha", "GET", "/hub/whoami", &[], None).status,
        401
    );
}

#[test]
fn a_backend_refuses_a_local_program_without_the_shared_secret() {
    let (_f, alpha, _beta, _) = two_apps();
    let r = support::http(
        alpha.addr(),
        "GET",
        "/api/items",
        &[("Keep-Member", "1")],
        None,
    );
    assert_eq!(r.status, 403);
    let r = support::http(
        alpha.addr(),
        "GET",
        "/api/items",
        &[("Keep-Hub-Auth", "a-guess"), ("Keep-Member", "1")],
        None,
    );
    assert_eq!(r.status, 403);
    assert!(alpha.seen().iter().all(|s| !s.trusted));
}

#[test]
fn only_what_the_hub_checked_reaches_a_backend() {
    let (f, alpha, _beta, sam) = two_apps();
    let token = f.pair(sam, "alpha", "Sam's phone");
    // paths that might be read as /api by a backend, sent without a token
    for path in [
        "/a/../api/items",
        "/%61pi/items",
        "//api/items",
        "/API/items",
        "/a/%2e%2e/api/x",
    ] {
        let r = f.phone("alpha", "GET", path, &[], None);
        assert_eq!((r.status, r.error().as_str()), (400, "bad_path"), "{path}");
    }
    // without a token only GET and HEAD pass, and without a body
    let r = f.phone("alpha", "POST", "/upload", &[], Some(b"x"));
    assert_eq!((r.status, r.error().as_str()), (405, "method_not_allowed"));
    let r = f.phone("alpha", "GET", "/index.html", &[], Some(b"x"));
    assert_eq!(r.status, 400);
    // a body must say how long it is
    let auth = format!("Bearer {token}");
    let r = f.phone(
        "alpha",
        "POST",
        "/api/items",
        &[("Authorization", &auth), ("Transfer-Encoding", "chunked")],
        None,
    );
    assert_eq!((r.status, r.error().as_str()), (411, "length_needed"));
    // a request that isn't HTTP as the hub reads it
    let r = f.phone_raw("alpha", b"GET /index.html HTTP/1.1\r\nHost : x\r\n\r\n");
    assert_eq!(r.status, 400);
    assert!(alpha.seen().is_empty());

    // a second request hidden behind the first one's body is not passed on
    let hidden = "GET /api/secret HTTP/1.1\r\nKeep-Member: 1\r\n\r\n";
    let raw = format!(
        "POST /api/items HTTP/1.1\r\nHost: x\r\nAuthorization: {auth}\r\nContent-Length: 2\r\n\r\nok{hidden}"
    );
    let r = f.phone_raw("alpha", raw.as_bytes());
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["body"], "ok");
    let seen = alpha.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].body, b"ok");

    // the hub's own addresses
    let r = f.phone("alpha", "GET", "/hub/check", &[], None);
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), json!({ "hub": "keep-hub", "ok": true }));
    assert_eq!(
        f.phone("alpha", "GET", "/hub/nothing", &[], None).status,
        404
    );
    assert_eq!(alpha.seen().len(), 1);
}

#[test]
fn at19_a_stopped_app_answers_app_stopped_while_the_other_keeps_working() {
    let (f, mut alpha, beta, sam) = two_apps();
    let token_a = f.pair(sam, "alpha", "Sam's phone");
    let token_b = f.pair(sam, "beta", "Sam's phone");
    let (port, secret) = (alpha.port, alpha.secret());
    alpha.stop();

    let r = f.api("alpha", &token_a, "GET", "/api/items");
    assert_eq!((r.status, r.error().as_str()), (503, "app_stopped"));
    let r = f.phone("alpha", "GET", "/index.html", &[], None);
    assert_eq!((r.status, r.error().as_str()), (503, "app_stopped"));
    // the hub still answers for itself on that port
    assert_eq!(f.phone("alpha", "GET", "/hub/check", &[], None).status, 200);
    assert_eq!(f.api("beta", &token_b, "GET", "/api/items").status, 200);
    assert_eq!(beta.seen().len(), 1);

    let states = |f: &Fixture| -> Vec<(String, String)> {
        f.admin_ok("GET", "/admin/v1/status", None)["apps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                (
                    a["app"]["id"].as_str().unwrap().to_string(),
                    a["state"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    };
    let mut now = states(&f);
    now.sort();
    assert_eq!(
        now,
        [
            ("alpha".to_string(), "app_stopped".to_string()),
            ("beta".to_string(), "running".to_string())
        ]
    );

    // the app comes back (an update restarted it): phones carry on
    let alpha = TestApp::start_on("alpha", port, &secret);
    assert_eq!(f.api("alpha", &token_a, "GET", "/api/items").status, 200);
    assert_eq!(alpha.seen().len(), 1);
}

// ----- pairing ----------------------------------------------------------------------------------

#[test]
fn at06_a_code_for_one_app_is_refused_on_the_other_apps_port() {
    let (f, alpha, beta, sam) = two_apps();
    f.admin_ok(
        "POST",
        "/admin/v1/grants",
        Some(json!({ "member": sam, "app": "beta" })),
    );
    let code = f.code(sam, "alpha");
    assert_eq!(code.len(), 9, "shown as ABCD-EFGH");
    assert_eq!(code.as_bytes()[4], b'-');

    let r = f.phone_json("beta", "POST", "/hub/pair", &[], &pair_request(&code, PIN));
    assert_eq!((r.status, r.error().as_str()), (403, "wrong_code"));
    // the code still works where it belongs, typed forgivingly, and only once
    let typed = code.to_lowercase().replace('-', " ");
    let r = f.phone_json(
        "alpha",
        "POST",
        "/hub/pair",
        &[],
        &pair_request(&typed, PIN),
    );
    assert_eq!(r.status, 200, "{}", r.text());
    let token = r.json()["token"].as_str().unwrap().to_string();
    assert_eq!(token.len(), 64);
    assert_eq!(r.json()["member"]["name"], "Sam");
    let again = f.phone_json("alpha", "POST", "/hub/pair", &[], &pair_request(&code, PIN));
    assert_eq!(again.status, 403);

    // the token works for alpha only
    assert_eq!(f.api("alpha", &token, "GET", "/api/items").status, 200);
    assert_eq!(f.api("beta", &token, "GET", "/api/items").status, 403);
    assert_eq!((alpha.seen().len(), beta.seen().len()), (1, 0));
    // pairing never reaches a backend, and only the token's hash is kept
    let registry = std::fs::read(f.dir.path().join("hub.sqlite")).unwrap();
    assert!(!registry.windows(token.len()).any(|w| w == token.as_bytes()));
}

#[test]
fn at06_five_wrong_pins_burn_a_code() {
    let (f, _alpha, _beta, sam) = two_apps();
    let code = f.code(sam, "alpha");
    for _ in 0..5 {
        let r = f.phone_json(
            "alpha",
            "POST",
            "/hub/pair",
            &[],
            &pair_request(&code, "000000"),
        );
        assert_eq!((r.status, r.error().as_str()), (403, "wrong_code"));
    }
    // the right PIN no longer helps
    let r = f.phone_json("alpha", "POST", "/hub/pair", &[], &pair_request(&code, PIN));
    assert_eq!((r.status, r.error().as_str()), (403, "wrong_code"));
    // a new code does
    f.pair(sam, "alpha", "Sam's phone");
}

#[test]
fn at06_ten_failures_pause_pairing_for_ten_minutes() {
    // Owner decision 2026-11-18: counted per address, as ShareKeep (ten from one address
    // pause that address; a hundred from everywhere pause everyone).
    let (f, _alpha, _beta, sam) = two_apps();
    for _ in 0..10 {
        let r = f.phone_json(
            "alpha",
            "POST",
            "/hub/pair",
            &[],
            &pair_request("AAAA-AAAA", PIN),
        );
        assert_eq!(r.status, 403);
    }
    let code = f.code(sam, "alpha");
    let r = f.phone_json("alpha", "POST", "/hub/pair", &[], &pair_request(&code, PIN));
    assert_eq!((r.status, r.error().as_str()), (429, "pairing_paused"));
    // the pause covers the other app's port and guests too
    let r = f.phone_json(
        "beta",
        "POST",
        "/hub/pair",
        &[],
        &json!({ "invite": "AAAA-AAAA", "name": "Kim" }),
    );
    assert_eq!(r.status, 429);

    f.advance_minutes(9);
    let r = f.phone_json("alpha", "POST", "/hub/pair", &[], &pair_request(&code, PIN));
    assert_eq!(r.status, 429);
    f.advance_minutes(2);
    // (the first code has run out by now: codes live 10 minutes)
    let r = f.phone_json("alpha", "POST", "/hub/pair", &[], &pair_request(&code, PIN));
    assert_eq!((r.status, r.error().as_str()), (403, "wrong_code"));
    f.pair(sam, "alpha", "Sam's phone");
}

#[test]
fn pairing_needs_a_pin_a_live_code_and_a_name() {
    let f = Fixture::new();
    let alpha = TestApp::start("alpha");
    f.register(&alpha, false, false);
    let sam = f.add_member("Sam");
    // no household PIN yet: no code can be made
    let r = f.admin(
        "POST",
        "/admin/v1/pairing-codes",
        Some(json!({ "member": sam, "app": "alpha" })),
    );
    assert_eq!((r.status, r.error().as_str()), (409, "pin_not_set"));
    // a PIN is 6 to 12 digits
    for bad in ["12345", "1234567890123", "12345a"] {
        let r = f.admin("PUT", "/admin/v1/pin", Some(json!({ "pin": bad })));
        assert_eq!((r.status, r.error().as_str()), (400, "bad_pin"), "{bad}");
    }
    assert_eq!(f.admin_ok("GET", "/admin/v1/pin", None)["set"], false);
    f.set_pin();
    assert_eq!(f.admin_ok("GET", "/admin/v1/pin", None)["set"], true);
    // changing it needs the old one
    let r = f.admin("PUT", "/admin/v1/pin", Some(json!({ "pin": "135790" })));
    assert_eq!((r.status, r.error().as_str()), (403, "pin_needed"));
    let r = f.admin(
        "PUT",
        "/admin/v1/pin",
        Some(json!({ "pin": "135790", "old": "000000" })),
    );
    assert_eq!((r.status, r.error().as_str()), (403, "pin_wrong"));
    // only a hash is kept
    let registry = std::fs::read(f.dir.path().join("hub.sqlite")).unwrap();
    assert!(!registry.windows(PIN.len()).any(|w| w == PIN.as_bytes()));

    // unknown members and apps
    let r = f.admin(
        "POST",
        "/admin/v1/pairing-codes",
        Some(json!({ "member": 99, "app": "alpha" })),
    );
    assert_eq!((r.status, r.error().as_str()), (404, "no_such_member"));
    let r = f.admin(
        "POST",
        "/admin/v1/pairing-codes",
        Some(json!({ "member": sam, "app": "gamma" })),
    );
    assert_eq!((r.status, r.error().as_str()), (404, "no_such_app"));

    // the code made the grant
    let code = f.code(sam, "alpha");
    assert_eq!(
        f.admin_ok("GET", "/admin/v1/grants", None)["grants"][0]["app"],
        "alpha"
    );
    // a phone must give itself a name
    let r = f.phone_json(
        "alpha",
        "POST",
        "/hub/pair",
        &[],
        &json!({ "code": code, "pin": PIN, "device": " " }),
    );
    assert_eq!((r.status, r.error().as_str()), (400, "bad_name"));
    // a cancelled code is refused
    f.admin_ok("DELETE", &format!("/admin/v1/pairing-codes/{code}"), None);
    let r = f.phone_json("alpha", "POST", "/hub/pair", &[], &pair_request(&code, PIN));
    assert_eq!(r.status, 403);
    // a code lives 10 minutes
    let code = f.code(sam, "alpha");
    f.advance_minutes(11);
    let r = f.phone_json("alpha", "POST", "/hub/pair", &[], &pair_request(&code, PIN));
    assert_eq!(r.status, 403);
    // an oversized or lengthless pairing request is refused before the PIN is looked at
    let big = vec![b' '; 5000];
    assert_eq!(
        f.phone("alpha", "POST", "/hub/pair", &[], Some(&big))
            .status,
        413
    );
    // after the PIN is changed the new one pairs
    f.admin_ok(
        "PUT",
        "/admin/v1/pin",
        Some(json!({ "pin": "135790", "old": PIN })),
    );
    let code = f.code(sam, "alpha");
    let r = f.phone_json("alpha", "POST", "/hub/pair", &[], &pair_request(&code, PIN));
    assert_eq!(r.status, 403);
    let code = f.code(sam, "alpha");
    let r = f.phone_json(
        "alpha",
        "POST",
        "/hub/pair",
        &[],
        &pair_request(&code, "135790"),
    );
    assert_eq!(r.status, 200);
}

#[test]
fn the_lives_of_codes_and_invites_are_settings() {
    let f = Fixture::with(|cfg| {
        cfg.pair.code_minutes = 2;
        cfg.guest.invite_days = 1;
    });
    let trips = TestApp::start("trips");
    f.register(&trips, false, true);
    f.set_pin();
    let sam = f.add_member("Sam");
    let code = f.code(sam, "trips");
    let invite = f.admin_ok(
        "POST",
        "/admin/v1/invites",
        Some(json!({ "app": "trips", "scope": "t" })),
    );
    f.advance_minutes(3);
    let r = f.phone_json("trips", "POST", "/hub/pair", &[], &pair_request(&code, PIN));
    assert_eq!(r.status, 403);
    f.advance_minutes(24 * 60);
    let r = f.phone_json(
        "trips",
        "POST",
        "/hub/pair",
        &[],
        &json!({ "invite": invite["code"], "name": "Kim" }),
    );
    assert_eq!(r.status, 403);
}

// ----- grants -----------------------------------------------------------------------------------

#[test]
fn at07_removing_a_grant_makes_the_members_tokens_answer_no_access() {
    let (f, alpha, beta, sam) = two_apps();
    let ana = f.add_member("Ana");
    let sam_a = f.pair(sam, "alpha", "Sam's phone");
    let sam_a2 = f.pair(sam, "alpha", "Sam's tablet");
    let sam_b = f.pair(sam, "beta", "Sam's phone");
    let ana_a = f.pair(ana, "alpha", "Ana's phone");
    assert_eq!(f.api("alpha", &sam_a, "GET", "/api/items").status, 200);

    f.admin_ok("DELETE", &format!("/admin/v1/grants/{sam}/alpha"), None);
    let before = alpha.seen().len();
    for token in [&sam_a, &sam_a2] {
        let r = f.api("alpha", token, "GET", "/api/items");
        assert_eq!((r.status, r.error().as_str()), (403, "no_access"));
    }
    assert_eq!(alpha.seen().len(), before, "the backend is not contacted");
    // Sam's other app and Ana are untouched
    assert_eq!(f.api("beta", &sam_b, "GET", "/api/items").status, 200);
    assert_eq!(f.api("alpha", &ana_a, "GET", "/api/items").status, 200);
    assert_eq!(beta.seen().len(), 1);
    assert_eq!(
        f.admin("DELETE", &format!("/admin/v1/grants/{sam}/alpha"), None)
            .status,
        404
    );

    // Owner decision 2026-11-18: the devices are not revoked; with the grant back they work.
    f.admin_ok(
        "POST",
        "/admin/v1/grants",
        Some(json!({ "member": sam, "app": "alpha" })),
    );
    assert_eq!(f.api("alpha", &sam_a, "GET", "/api/items").status, 200);
    assert_eq!(f.api("alpha", &sam_a2, "GET", "/api/items").status, 200);
}

#[test]
fn at08_granting_an_app_that_declared_money_needs_the_pin() {
    let f = Fixture::new();
    let books = TestApp::start("books");
    let trips = TestApp::start("trips");
    f.register(&books, true, false);
    f.register(&trips, false, false);
    let sam = f.add_member("Sam");
    let grant = |app: &str, pin: Option<&str>| {
        let mut b = json!({ "member": sam, "app": app });
        if let Some(p) = pin {
            b["pin"] = json!(p);
        }
        f.admin("POST", "/admin/v1/grants", Some(b))
    };
    // an app without money: no PIN, even before one is set
    assert_eq!(grant("trips", None).status, 200);
    // an app with money: a PIN must exist, be given, and be right
    let r = grant("books", None);
    assert_eq!((r.status, r.error().as_str()), (409, "pin_not_set"));
    f.set_pin();
    let r = grant("books", None);
    assert_eq!((r.status, r.error().as_str()), (403, "pin_needed"));
    let r = grant("books", Some("000000"));
    assert_eq!((r.status, r.error().as_str()), (403, "pin_wrong"));
    // the same when a pairing code would make the grant
    let r = f.admin(
        "POST",
        "/admin/v1/pairing-codes",
        Some(json!({ "member": sam, "app": "books" })),
    );
    assert_eq!((r.status, r.error().as_str()), (403, "pin_needed"));
    let grants = f.admin_ok("GET", "/admin/v1/grants", None);
    assert_eq!(grants["grants"].as_array().unwrap().len(), 1);

    assert_eq!(grant("books", Some(PIN)).status, 200);
    let grants = f.admin_ok("GET", "/admin/v1/grants", None);
    assert_eq!(grants["grants"].as_array().unwrap().len(), 2);
    // with the grant there, a code needs no PIN on the hub computer (the phone still does)
    let code = f.admin_ok(
        "POST",
        "/admin/v1/pairing-codes",
        Some(json!({ "member": sam, "app": "books" })),
    );
    let r = f.phone_json(
        "books",
        "POST",
        "/hub/pair",
        &[],
        &pair_request(code["code"].as_str().unwrap(), PIN),
    );
    assert_eq!(r.status, 200);
}

// ----- guests -----------------------------------------------------------------------------------

#[test]
fn at09_a_guest_invite_pairs_without_a_pin_once_and_carries_its_scope() {
    let f = Fixture::new();
    let trips = TestApp::start("trips");
    let plain = TestApp::start("plain");
    f.register(&trips, false, true);
    f.register(&plain, false, false);
    // no household PIN is needed for a guest
    let invite = f.admin_ok(
        "POST",
        "/admin/v1/invites",
        Some(json!({ "app": "trips", "scope": "trip-7" })),
    );
    let code = invite["code"].as_str().unwrap().to_string();
    assert_eq!(code.len(), 9);
    assert_eq!(
        f.admin_ok("GET", "/admin/v1/invites", None)["invites"][0]["scope"],
        "trip-7"
    );

    // not on another app's port
    let r = f.phone_json(
        "plain",
        "POST",
        "/hub/pair",
        &[],
        &json!({ "invite": code, "name": "Kim" }),
    );
    assert_eq!((r.status, r.error().as_str()), (403, "wrong_code"));
    let r = f.phone_json(
        "trips",
        "POST",
        "/hub/pair",
        &[],
        &json!({ "invite": code, "name": "Kim" }),
    );
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json()["guest_scope"], "trip-7");
    let token = r.json()["token"].as_str().unwrap().to_string();
    // once: the first person to use it holds the device
    let r = f.phone_json(
        "trips",
        "POST",
        "/hub/pair",
        &[],
        &json!({ "invite": code, "name": "Lee" }),
    );
    assert_eq!((r.status, r.error().as_str()), (403, "wrong_code"));
    assert!(f.admin_ok("GET", "/admin/v1/invites", None)["invites"]
        .as_array()
        .unwrap()
        .is_empty());

    // the guest's requests carry the scope, whatever the phone says
    let auth = format!("Bearer {token}");
    let r = f.phone(
        "trips",
        "GET",
        "/api/trip",
        &[("Authorization", &auth), ("Keep-Guest-Scope", "trip-1")],
        None,
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["headers"]["keep-guest-scope"], "trip-7");
    assert_eq!(r.json()["headers"]["keep-member-name"], "Kim");
    assert_eq!(trips.seen().len(), 1);
    // a guest is no household member: no grants or codes for other apps
    let guest = f.admin_ok("GET", "/admin/v1/members", None)["members"][0].clone();
    assert_eq!(guest["guest_app"], "trips");
    let r = f.admin(
        "POST",
        "/admin/v1/grants",
        Some(json!({ "member": guest["id"], "app": "plain" })),
    );
    assert_eq!((r.status, r.error().as_str()), (404, "no_such_member"));
    // and can be revoked like any device
    let id = f.admin_ok("GET", "/admin/v1/devices", None)["devices"][0]["id"]
        .as_u64()
        .unwrap();
    f.admin_ok("DELETE", &format!("/admin/v1/devices/{id}"), None);
    assert_eq!(f.api("trips", &token, "GET", "/api/trip").status, 401);
}

#[test]
fn at09_an_expired_or_cancelled_invite_is_refused() {
    let f = Fixture::new();
    let trips = TestApp::start("trips");
    f.register(&trips, false, true);
    let make = || {
        f.admin_ok(
            "POST",
            "/admin/v1/invites",
            Some(json!({ "app": "trips", "scope": "trip-7" })),
        )
    };
    let use_it = |code: &Value| {
        f.phone_json(
            "trips",
            "POST",
            "/hub/pair",
            &[],
            &json!({ "invite": code, "name": "Kim" }),
        )
    };
    // valid 7 days
    let late = make();
    f.advance_minutes(7 * 24 * 60 + 1);
    let r = use_it(&late["code"]);
    assert_eq!((r.status, r.error().as_str()), (403, "wrong_code"));
    let in_time = make();
    f.advance_minutes(7 * 24 * 60 - 1);
    assert_eq!(use_it(&in_time["code"]).status, 200);
    // cancelled
    let gone = make();
    f.admin_ok("DELETE", &format!("/admin/v1/invites/{}", gone["id"]), None);
    assert_eq!(use_it(&gone["code"]).status, 403);
    // a scope that couldn't travel in a header is refused when the invite is made
    for scope in ["", "two words", "line\nbreak", "é"] {
        let r = f.admin(
            "POST",
            "/admin/v1/invites",
            Some(json!({ "app": "trips", "scope": scope })),
        );
        assert_eq!(
            (r.status, r.error().as_str()),
            (400, "bad_scope"),
            "{scope:?}"
        );
    }
}

#[test]
fn at09_an_app_with_money_cannot_accept_guests() {
    let f = Fixture::new();
    let books = TestApp::start("books");
    let r = f.admin(
        "POST",
        "/admin/v1/apps",
        Some(Fixture::registration(&books, free_port(), true, true)),
    );
    assert_eq!((r.status, r.error().as_str()), (409, "money_with_guests"));
    assert!(f.admin_ok("GET", "/admin/v1/apps", None)["apps"]
        .as_array()
        .unwrap()
        .is_empty());
    // and an app that didn't declare guests can't invite any
    f.register(&books, true, false);
    let r = f.admin(
        "POST",
        "/admin/v1/invites",
        Some(json!({ "app": "books", "scope": "x" })),
    );
    assert_eq!((r.status, r.error().as_str()), (409, "no_guests"));
}

// ----- registering apps, the admin address ------------------------------------------------------

#[test]
fn registering_refuses_a_taken_port_and_an_unknown_protocol_with_plain_messages() {
    let f = Fixture::new();
    let alpha = TestApp::start("alpha");
    let beta = TestApp::start("beta");
    let port = f.register(&alpha, false, false);

    // two apps ask for one port: the second is refused and told who holds it
    let r = f.admin(
        "POST",
        "/admin/v1/apps",
        Some(Fixture::registration(&beta, port, false, false)),
    );
    assert_eq!((r.status, r.error().as_str()), (409, "port_taken"));
    assert!(r.json()["message"].as_str().unwrap().contains("Test alpha"));
    // a protocol the hub doesn't know
    let mut reg = Fixture::registration(&beta, free_port(), false, false);
    reg["protocol"] = json!(2);
    let r = f.admin("POST", "/admin/v1/apps", Some(reg));
    assert_eq!((r.status, r.error().as_str()), (409, "unknown_protocol"));
    // ids, and the hub's own ports
    let mut reg = Fixture::registration(&beta, free_port(), false, false);
    reg["id"] = json!("Beta App");
    assert_eq!(f.admin("POST", "/admin/v1/apps", Some(reg)).status, 400);
    let reg = Fixture::registration(&beta, f.hub().admin.port(), false, false);
    assert_eq!(f.admin("POST", "/admin/v1/apps", Some(reg)).status, 400);
    // a port another program holds can't be opened
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let reg = Fixture::registration(&beta, busy.local_addr().unwrap().port(), false, false);
    let r = f.admin("POST", "/admin/v1/apps", Some(reg));
    assert_eq!((r.status, r.error().as_str()), (409, "port_unavailable"));
    let apps = f.admin_ok("GET", "/admin/v1/apps", None);
    assert_eq!(apps["apps"].as_array().unwrap().len(), 1);
    assert!(f.hub().app_port("beta").is_none());

    // the port opened at once, on registering
    assert_eq!(f.phone("alpha", "GET", "/hub/check", &[], None).status, 200);
    let status = f.admin_ok("GET", "/admin/v1/status", None);
    assert_eq!(status["protocols"], json!([1]));
    assert_eq!(status["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(status["apps"][0]["state"], "running");
}

/// Acceptance test 24, the part stage 1 can show: the hub installed alone, with no app
/// registered, runs and listens on the admin address. (The service is stage 7 and the
/// certificate page stage 4.)
#[test]
fn at24_a_hub_with_no_app_registered_listens_on_the_admin_address_only() {
    let mut f = Fixture::new();
    let status = f.admin_ok("GET", "/admin/v1/status", None);
    assert_eq!(status["hub"], "keep-hub");
    assert_eq!(status["apps"], json!([]));
    assert_eq!(f.admin_ok("GET", "/admin/v1/apps", None)["apps"], json!([]));
    assert!(f.hub().app_port("vacapick").is_none());
    // an app that finds the hub can register at once, and the hub can go back to none
    let alpha = TestApp::start("alpha");
    f.register(&alpha, false, false);
    assert_eq!(f.phone("alpha", "GET", "/hub/check", &[], None).status, 200);
    f.admin_ok("DELETE", "/admin/v1/apps/alpha", None);
    assert_eq!(
        f.admin_ok("GET", "/admin/v1/status", None)["apps"],
        json!([])
    );
    // and it starts again with none
    f.restart();
    assert_eq!(
        f.admin_ok("GET", "/admin/v1/status", None)["apps"],
        json!([])
    );
}

#[test]
fn registering_again_keeps_the_phones_and_gives_a_new_secret() {
    let (f, alpha, _beta, sam) = two_apps();
    let token = f.pair(sam, "alpha", "Sam's phone");
    let old_port = f.port("alpha");
    let old_secret = alpha.secret();

    // an update registers again on the same port
    let mut reg = Fixture::registration(&alpha, old_port.port(), false, false);
    reg["version"] = json!("0.2.0");
    let v = f.admin_ok("POST", "/admin/v1/apps", Some(reg));
    assert_ne!(v["secret"], old_secret);
    alpha.set_secret(v["secret"].as_str().unwrap());
    assert_eq!(f.port("alpha"), old_port);
    assert_eq!(f.api("alpha", &token, "GET", "/api/items").status, 200);
    assert!(alpha.seen().last().unwrap().trusted);
    let apps = f.admin_ok("GET", "/admin/v1/apps", None);
    let me = apps["apps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == "alpha")
        .unwrap()
        .clone();
    assert_eq!(me["version"], "0.2.0");

    // and on another port: the old one closes
    let reg = Fixture::registration(&alpha, free_port(), false, false);
    let v = f.admin_ok("POST", "/admin/v1/apps", Some(reg));
    alpha.set_secret(v["secret"].as_str().unwrap());
    assert_ne!(f.port("alpha"), old_port);
    assert!(support::https_raw(
        old_port,
        &f.hub().ca_der,
        b"GET /hub/check HTTP/1.1\r\n\r\n"
    )
    .is_err());
    assert_eq!(f.api("alpha", &token, "GET", "/api/items").status, 200);
}

#[test]
fn unregistering_closes_the_port_and_revokes_the_apps_devices() {
    let (f, alpha, beta, sam) = two_apps();
    let token_a = f.pair(sam, "alpha", "Sam's phone");
    let token_b = f.pair(sam, "beta", "Sam's phone");
    let port = f.port("alpha");

    f.admin_ok("DELETE", "/admin/v1/apps/alpha", None);
    assert!(f.hub().app_port("alpha").is_none());
    assert!(support::https_raw(port, &f.hub().ca_der, b"GET /hub/check HTTP/1.1\r\n\r\n").is_err());
    assert_eq!(f.admin("DELETE", "/admin/v1/apps/alpha", None).status, 404);
    // the other app carries on
    assert_eq!(f.api("beta", &token_b, "GET", "/api/items").status, 200);
    assert_eq!(beta.seen().len(), 1);

    // registered again later, the old phones must pair again
    f.register(&alpha, false, false);
    let r = f.api("alpha", &token_a, "GET", "/api/items");
    assert_eq!((r.status, r.error().as_str()), (401, "not_paired"));
    assert!(alpha.seen().is_empty());
}

#[test]
fn the_admin_address_needs_the_admin_token_and_keeps_the_members_list() {
    let (f, _alpha, _beta, sam) = two_apps();
    let admin = f.hub().admin;
    assert!(admin.ip().is_loopback());
    let r = support::http(admin, "GET", "/admin/v1/status", &[], None);
    assert_eq!((r.status, r.error().as_str()), (401, "no_admin_token"));
    let r = support::http(
        admin,
        "GET",
        "/admin/v1/members",
        &[("Authorization", "Bearer guess")],
        None,
    );
    assert_eq!(r.status, 401);
    // the admin token opens nothing on an app's port
    let r = f.api("alpha", &f.admin_token, "GET", "/api/items");
    assert_eq!(r.status, 401);

    f.admin_ok(
        "PUT",
        &format!("/admin/v1/members/{sam}"),
        Some(json!({ "name": "Samira" })),
    );
    assert_eq!(
        f.admin("PUT", "/admin/v1/members/99", Some(json!({ "name": "X" })))
            .status,
        404
    );
    assert_eq!(
        f.admin("POST", "/admin/v1/members", Some(json!({ "name": "  " })))
            .status,
        400
    );
    let members = f.admin_ok("GET", "/admin/v1/members", None);
    let list = members["members"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(
        (&list[0]["id"], &list[0]["name"]),
        (&json!(sam), &json!("Samira"))
    );
    assert!(list[0]["guest_app"].is_null() && list[0]["guest_scope"].is_null());
    assert_eq!(f.admin("GET", "/admin/v1/nothing", None).status, 404);
    assert_eq!(
        f.admin("POST", "/admin/v1/members", Some(json!({ "nome": "x" })))
            .status,
        400
    );
}

#[test]
fn pairings_grants_and_apps_survive_a_hub_restart() {
    let (mut f, alpha, beta, sam) = two_apps();
    let token = f.pair(sam, "alpha", "Sam's phone");
    let (port_a, port_b) = (f.port("alpha"), f.port("beta"));
    f.restart();
    assert_eq!((f.port("alpha"), f.port("beta")), (port_a, port_b));
    let r = f.api("alpha", &token, "GET", "/api/items");
    assert_eq!(r.status, 200, "{}", r.text());
    // the same shared secrets: the backends still trust the hub
    assert!(alpha.seen().last().unwrap().trusted);
    assert_eq!(f.phone("beta", "GET", "/index.html", &[], None).status, 200);
    assert!(beta.seen().last().unwrap().trusted);
    // the PIN is still the PIN
    f.pair(sam, "beta", "Sam's phone");
}

// ----- secrets ----------------------------------------------------------------------------------

#[test]
fn logs_carry_the_method_path_and_status_and_no_secret() {
    let f = Fixture::new();
    let alpha = TestApp::start("alpha");
    let trips = TestApp::start("trips");
    f.register(&alpha, false, false);
    f.register(&trips, false, true);
    f.set_pin();
    let sam = f.add_member("Sam");
    let code = f.code(sam, "alpha");
    let wrong = f.phone_json(
        "alpha",
        "POST",
        "/hub/pair",
        &[],
        &pair_request(&code, "000000"),
    );
    assert_eq!(wrong.status, 403);
    let token = {
        let r = f.phone_json("alpha", "POST", "/hub/pair", &[], &pair_request(&code, PIN));
        r.json()["token"].as_str().unwrap().to_string()
    };
    let invite = f.admin_ok(
        "POST",
        "/admin/v1/invites",
        Some(json!({ "app": "trips", "scope": "trip-7" })),
    );
    let invite = invite["code"].as_str().unwrap().to_string();
    let cancelled = f.code(sam, "alpha");
    f.admin_ok(
        "DELETE",
        &format!("/admin/v1/pairing-codes/{cancelled}"),
        None,
    );
    f.api("alpha", &token, "GET", &format!("/api/items?token={token}"));
    f.api("alpha", "a-wrong-token-value", "GET", "/api/items");
    f.phone("alpha", "GET", "/index.html", &[], None);
    f.admin(
        "PUT",
        "/admin/v1/pin",
        Some(json!({ "pin": "135790", "old": PIN })),
    );

    let lines = f.log_lines();
    assert!(
        lines.contains(&"POST /hub/pair 403".to_string()),
        "{lines:?}"
    );
    assert!(lines.contains(&"POST /hub/pair 200".to_string()));
    assert!(lines.contains(&"GET /api/items 200".to_string()));
    assert!(lines.contains(&"GET /api/items 401".to_string()));
    assert!(lines.contains(&"GET /index.html 200".to_string()));
    assert!(lines.contains(&"PUT /admin/v1/pin 200".to_string()));
    assert!(lines.contains(&"DELETE /admin/v1/pairing-codes/- 200".to_string()));
    let secrets = [
        token.as_str(),
        "a-wrong-token-value",
        PIN,
        "135790",
        "000000",
        &code,
        &code.replace('-', ""),
        &cancelled,
        &invite,
        &f.admin_token,
        &alpha.secret(),
        &trips.secret(),
    ];
    for line in &lines {
        for s in secrets {
            assert!(!line.contains(s), "a secret in the log: {line}");
        }
    }
    // and none in the hub's public file
    let public = std::fs::read_to_string(f.dir.path().join("hub.json")).unwrap();
    for s in secrets {
        assert!(!public.contains(s));
    }
}
