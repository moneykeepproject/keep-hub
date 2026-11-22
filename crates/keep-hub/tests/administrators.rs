//! Stage 8: administrators and standard members (the spec, "Administrators and standard
//! members" and "The admin address"). The test names give the acceptance test of
//! `docs/specs/keep-hub.md` they cover (27 to 35, and 38).
//!
//! Everything runs on 127.0.0.1 with keys in memory. The passwords here are test values,
//! not secrets.

mod support;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{json, Value};
use support::{Fixture, TestApp, ADMIN_NAME, ADMIN_PASSWORD, PIN};

const BLAKE_PASSWORD: &str = "another-test-pass";

fn members(f: &Fixture) -> Vec<Value> {
    f.admin_ok("GET", "/admin/v1/members", None)["members"]
        .as_array()
        .unwrap()
        .clone()
}

fn member_named(f: &Fixture, name: &str) -> Value {
    members(f)
        .into_iter()
        .find(|m| m["name"] == name)
        .unwrap_or_else(|| panic!("no member {name}"))
}

/// The first administrator's id (the first set-up makes them first).
fn avery(f: &Fixture) -> u32 {
    member_named(f, ADMIN_NAME)["id"].as_u64().unwrap() as u32
}

fn code_of(r: &support::Reply) -> (u16, String) {
    (r.status, r.error())
}

// ----- 27: the first set-up ----------------------------------------------------------------------

#[test]
fn at27_first_setup_makes_the_first_administrator_and_the_pin_once() {
    let f = Fixture::not_set_up();
    // before it, every other admin request is refused (status and lists too)
    for (method, path, body) in [
        ("GET", "/admin/v1/status", None),
        ("GET", "/admin/v1/apps", None),
        ("GET", "/admin/v1/members", None),
        ("GET", "/admin/v1/devices", None),
        ("GET", "/admin/v1/pin", None),
        ("GET", "/admin/v1/names", None),
        ("POST", "/admin/v1/problems", None),
        ("POST", "/admin/v1/members", Some(json!({ "name": "Sam" }))),
        ("PUT", "/admin/v1/pin", Some(json!({ "pin": PIN }))),
        (
            "POST",
            "/admin/v1/session",
            Some(json!({ "name": ADMIN_NAME, "password": ADMIN_PASSWORD })),
        ),
    ] {
        let r = f.admin_with(None, method, path, body);
        assert_eq!(code_of(&r), (409, "setup_needed".into()), "{method} {path}");
    }
    // still the admin token first
    let r = support::http(
        f.hub().admin,
        "POST",
        "/admin/v1/setup",
        &[],
        Some(br#"{"name":"X","password":"long-enough","pin":"246810"}"#),
    );
    assert_eq!(code_of(&r), (401, "no_admin_token".into()));
    // a password of 7 characters, a PIN that isn't 6 to 12 digits, no name
    let setup = |name: &str, password: &str, pin: &str| {
        f.admin_with(
            None,
            "POST",
            "/admin/v1/setup",
            Some(json!({ "name": name, "password": password, "pin": pin })),
        )
    };
    assert_eq!(
        code_of(&setup(ADMIN_NAME, "seven77", PIN)),
        (400, "bad_password".into())
    );
    assert_eq!(
        code_of(&setup(ADMIN_NAME, ADMIN_PASSWORD, "12345")),
        (400, "bad_pin".into())
    );
    assert_eq!(
        code_of(&setup(" ", ADMIN_PASSWORD, PIN)),
        (400, "bad_name".into())
    );
    assert_eq!(
        f.admin_with(None, "GET", "/admin/v1/status", None).status,
        409,
        "nothing was made"
    );

    // the set-up: the first administrator, the PIN, and a session
    let r = setup(ADMIN_NAME, ADMIN_PASSWORD, PIN);
    assert_eq!(r.status, 200, "{}", r.text());
    let v = r.json();
    assert_eq!(v["member"]["name"], ADMIN_NAME);
    assert_eq!(v["member"]["class"], "administrator");
    assert_eq!(v["session_minutes"], 15);
    let session = v["session"].as_str().unwrap().to_string();
    assert_eq!(session.len(), 64);
    let r = f.admin_with(
        Some(&session),
        "POST",
        "/admin/v1/members",
        Some(json!({ "name": "Sam" })),
    );
    assert_eq!(r.status, 200, "the session works: {}", r.text());
    assert_eq!(
        f.admin_with(None, "GET", "/admin/v1/pin", None).json()["set"],
        true
    );
    assert_eq!(
        f.admin_with(None, "GET", "/admin/v1/status", None).status,
        200
    );
    let list = f.admin_with(None, "GET", "/admin/v1/members", None).json();
    assert_eq!(list["members"][0]["class"], "administrator");
    assert_eq!(list["members"][0]["password_set"], true);

    // a second first set-up is refused, and changes nothing
    assert_eq!(
        code_of(&setup("Mallory", "mallory-password", "135790")),
        (409, "already_set_up".into())
    );
    assert_eq!(
        f.admin_with(None, "GET", "/admin/v1/members", None).json()["members"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        code_of(&f.sign_in("Mallory", "mallory-password")),
        (403, "wrong_password".into())
    );
    // only hashes are kept: neither the password nor the PIN is in the registry
    let registry = std::fs::read(f.dir.path().join("hub.sqlite")).unwrap();
    for secret in [ADMIN_PASSWORD, PIN] {
        assert!(!registry
            .windows(secret.len())
            .any(|w| w == secret.as_bytes()));
    }
}

#[test]
fn at27_a_set_up_hub_stays_set_up_after_a_restart() {
    let mut f = Fixture::new();
    f.restart();
    let r = f.admin_with(None, "GET", "/admin/v1/status", None);
    assert_eq!(r.status, 200);
    // sessions are the hub's memory only: signing in again works
    f.session_of(ADMIN_NAME, ADMIN_PASSWORD);
}

// ----- 28: sessions and wrong passwords ----------------------------------------------------------

/// A request marked A, with `session`: whether it was let through.
fn a_request_works(f: &Fixture, session: &str) -> bool {
    let r = f.admin_with(
        Some(session),
        "PUT",
        "/admin/v1/pin",
        Some(json!({ "pin": PIN })),
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

#[test]
fn at28_a_session_lasts_15_minutes_from_its_last_use() {
    let f = Fixture::new();
    let s = f.session_of(ADMIN_NAME, ADMIN_PASSWORD);
    assert!(a_request_works(&f, &s));
    // each use starts the minutes again
    for _ in 0..3 {
        f.advance_minutes(14);
        assert!(a_request_works(&f, &s));
    }
    // a request that needs only the token counts as a use too, when it carries the
    // session (owner decision 2026-11-19)
    f.advance_minutes(14);
    assert_eq!(
        f.admin_with(Some(&s), "GET", "/admin/v1/members", None)
            .status,
        200
    );
    f.advance_minutes(14);
    assert!(a_request_works(&f, &s));
    // one without it doesn't
    f.advance_minutes(14);
    assert_eq!(
        f.admin_with(None, "GET", "/admin/v1/members", None).status,
        200
    );
    f.advance_minutes(1);
    assert!(!a_request_works(&f, &s), "15 minutes after its last use");
    // signing out ends a session at once
    let s = f.session_of(ADMIN_NAME, ADMIN_PASSWORD);
    assert_eq!(
        f.admin_with(Some(&s), "DELETE", "/admin/v1/session", None)
            .status,
        200
    );
    assert!(!a_request_works(&f, &s));
    // a made-up session is no session
    assert!(!a_request_works(&f, &"0".repeat(64)));
}

#[test]
fn at28_the_session_length_is_the_admin_session_minutes_setting() {
    let f = Fixture::with(|cfg| cfg.admin.session_minutes = 2);
    let s = f.session_of(ADMIN_NAME, ADMIN_PASSWORD);
    assert_eq!(
        f.sign_in(ADMIN_NAME, ADMIN_PASSWORD).json()["session_minutes"],
        2
    );
    f.advance_minutes(1);
    assert!(a_request_works(&f, &s));
    f.advance_minutes(2);
    assert!(!a_request_works(&f, &s));
    // in hub.json, as `admin.session_minutes`
    let cfg: Value =
        serde_json::from_slice(&std::fs::read(f.dir.path().join("hub.json")).unwrap()).unwrap();
    assert_eq!(cfg["admin"]["session_minutes"], 2);
}

#[test]
fn at28_five_wrong_passwords_pause_that_administrator_for_10_minutes_only() {
    let f = Fixture::new();
    f.add_administrator("Blake", BLAKE_PASSWORD);
    for i in 1..5 {
        let r = f.sign_in(ADMIN_NAME, "not-the-password");
        assert_eq!(code_of(&r), (403, "wrong_password".into()), "try {i}");
    }
    let r = f.sign_in(ADMIN_NAME, "not-the-password");
    assert_eq!(code_of(&r), (429, "sign_in_paused".into()), "the fifth");
    // paused: even the right password
    let r = f.sign_in(ADMIN_NAME, ADMIN_PASSWORD);
    assert_eq!(code_of(&r), (429, "sign_in_paused".into()));
    // another administrator can still sign in, and a session from before still works
    f.session_of("Blake", BLAKE_PASSWORD);
    // (names are matched without case or spaces around them)
    f.session_of("  blake ", BLAKE_PASSWORD);
    f.advance_minutes(9);
    assert_eq!(f.sign_in(ADMIN_NAME, ADMIN_PASSWORD).status, 429);
    f.advance_minutes(1);
    f.session_of(ADMIN_NAME, ADMIN_PASSWORD);
    // wrong passwords spread over more than 10 minutes don't pause
    for _ in 0..4 {
        assert_eq!(f.sign_in(ADMIN_NAME, "nope-nope-nope").status, 403);
    }
    f.advance_minutes(11);
    assert_eq!(f.sign_in(ADMIN_NAME, "nope-nope-nope").status, 403);
    f.session_of(ADMIN_NAME, ADMIN_PASSWORD);
    // a name that is nobody's: the same refusal as a wrong password
    assert_eq!(
        code_of(&f.sign_in("Nobody", ADMIN_PASSWORD)),
        (403, "wrong_password".into())
    );
    // the log names members by number only, and never a password or a session
    let log = f.log_lines().join("\n");
    assert!(log.contains("sign-in paused"));
    for secret in [ADMIN_PASSWORD, BLAKE_PASSWORD, "not-the-password"] {
        assert!(!log.contains(secret));
    }
}

// ----- 29: standard members and requests marked A -------------------------------------------------

#[test]
fn at29_a_standard_member_cant_sign_in_and_a_needs_a_session() {
    let f = Fixture::new();
    let app = TestApp::start("alpha");
    f.register(&app, false, true);
    let sam = f.add_member("Sam");
    let r = f.sign_in("Sam", "any-password-at-all");
    assert_eq!(code_of(&r), (403, "not_an_administrator".into()));
    // a standard member has no password to set
    let r = f.admin(
        "PUT",
        &format!("/admin/v1/members/{sam}/password"),
        Some(json!({ "password": "sams-password" })),
    );
    assert_eq!(code_of(&r), (409, "not_an_administrator".into()));
    let token = f.pair(sam, "alpha", "Sam's phone");
    let device = f.admin_ok("GET", "/admin/v1/devices", None)["devices"][0]["id"].clone();
    let invite = f.admin_ok(
        "POST",
        "/admin/v1/invites",
        Some(json!({ "app": "alpha", "scope": "trip-1" })),
    )["id"]
        .clone();

    // every request marked A, with the admin token alone
    let beta = TestApp::start("beta");
    let marked_a: Vec<(&str, String, Option<Value>)> = vec![
        (
            "POST",
            "/admin/v1/apps".into(),
            Some(Fixture::registration(
                &beta,
                support::free_port(),
                false,
                false,
            )),
        ),
        ("DELETE", "/admin/v1/apps/alpha".into(), None),
        (
            "POST",
            "/admin/v1/members".into(),
            Some(json!({ "name": "Kim" })),
        ),
        (
            "PUT",
            format!("/admin/v1/members/{sam}"),
            Some(json!({ "name": "Samuel" })),
        ),
        (
            "PUT",
            format!("/admin/v1/members/{sam}/class"),
            Some(json!({ "class": "administrator" })),
        ),
        (
            "PUT",
            format!("/admin/v1/members/{}/password", avery(&f)),
            Some(json!({ "password": "taken-over-now" })),
        ),
        ("DELETE", format!("/admin/v1/members/{sam}"), None),
        (
            "POST",
            "/admin/v1/grants".into(),
            Some(json!({ "member": avery(&f), "app": "alpha" })),
        ),
        ("DELETE", format!("/admin/v1/grants/{sam}/alpha"), None),
        (
            "POST",
            "/admin/v1/pairing-codes".into(),
            Some(json!({ "member": sam, "app": "alpha" })),
        ),
        ("DELETE", "/admin/v1/pairing-codes/ABCD-EFGH".into(), None),
        (
            "POST",
            "/admin/v1/invites".into(),
            Some(json!({ "app": "alpha", "scope": "trip-2" })),
        ),
        ("DELETE", format!("/admin/v1/invites/{invite}"), None),
        ("DELETE", format!("/admin/v1/devices/{device}"), None),
        (
            "PUT",
            "/admin/v1/pin".into(),
            Some(json!({ "pin": "135790" })),
        ),
        ("POST", "/admin/v1/names/on".into(), Some(json!({}))),
        ("POST", "/admin/v1/names/off".into(), None),
        ("POST", "/admin/v1/names/renew".into(), None),
        (
            "PUT",
            "/admin/v1/address".into(),
            Some(json!({ "adapter": "automatic" })),
        ),
    ];
    for (method, path, body) in &marked_a {
        let r = f.admin_with(None, method, path, body.clone());
        assert_eq!(
            code_of(&r),
            (401, "administrator_needed".into()),
            "{method} {path}"
        );
    }
    // nothing changed
    assert_eq!(members(&f).len(), 2);
    assert_eq!(member_named(&f, "Sam")["class"], "standard");
    assert_eq!(f.api("alpha", &token, "GET", "/api/x").status, 200);
    assert_eq!(
        f.admin_ok("GET", "/admin/v1/invites", None)["invites"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    f.session_of(ADMIN_NAME, ADMIN_PASSWORD);

    // the lists, the status and Find the problem answer without a session
    for (method, path) in [
        ("GET", "/admin/v1/status"),
        ("GET", "/admin/v1/apps"),
        ("GET", "/admin/v1/members"),
        ("GET", "/admin/v1/grants"),
        ("GET", "/admin/v1/devices"),
        ("GET", "/admin/v1/invites"),
        ("GET", "/admin/v1/pin"),
        ("GET", "/admin/v1/names"),
        ("GET", "/admin/v1/addresses"),
        ("POST", "/admin/v1/problems"),
        ("GET", "/admin/v1/problems"),
        ("POST", "/admin/v1/names/address"),
    ] {
        let r = f.admin_with(None, method, path, None);
        assert_eq!(r.status, 200, "{method} {path}: {}", r.text());
    }
}

#[test]
fn at29_a_session_ends_when_its_administrator_is_made_standard_or_removed() {
    let f = Fixture::new();
    let blake = f.add_administrator("Blake", BLAKE_PASSWORD);
    let s = f.session_of("Blake", BLAKE_PASSWORD);
    assert!(a_request_works(&f, &s));
    f.admin_ok(
        "PUT",
        &format!("/admin/v1/members/{blake}/class"),
        Some(json!({ "class": "standard" })),
    );
    assert!(!a_request_works(&f, &s));
    // made standard, the password is gone: made administrator again, they need a new one
    assert_eq!(member_named(&f, "Blake")["password_set"], false);
    f.admin_ok(
        "PUT",
        &format!("/admin/v1/members/{blake}/class"),
        Some(json!({ "class": "administrator" })),
    );
    assert_eq!(
        code_of(&f.sign_in("Blake", BLAKE_PASSWORD)),
        (403, "no_password".into())
    );
    f.admin_ok(
        "PUT",
        &format!("/admin/v1/members/{blake}/password"),
        Some(json!({ "password": BLAKE_PASSWORD })),
    );
    let s = f.session_of("Blake", BLAKE_PASSWORD);
    f.admin_ok("DELETE", &format!("/admin/v1/members/{blake}"), None);
    assert!(!a_request_works(&f, &s));
}

#[test]
fn at29_another_administrator_sets_a_forgotten_password() {
    let f = Fixture::new();
    let blake = f.add_administrator("Blake", BLAKE_PASSWORD);
    let blakes = f.session_of("Blake", BLAKE_PASSWORD);
    // too short
    let r = f.admin(
        "PUT",
        &format!("/admin/v1/members/{blake}/password"),
        Some(json!({ "password": "short" })),
    );
    assert_eq!(code_of(&r), (400, "bad_password".into()));
    f.admin_ok(
        "PUT",
        &format!("/admin/v1/members/{blake}/password"),
        Some(json!({ "password": "a-brand-new-one" })),
    );
    assert_eq!(f.sign_in("Blake", BLAKE_PASSWORD).status, 403);
    f.session_of("Blake", "a-brand-new-one");
    // Blake's earlier session ended with the old password; Avery's own goes on
    assert!(!a_request_works(&f, &blakes));
    assert_eq!(f.admin("GET", "/admin/v1/members", None).status, 200);
}

#[test]
fn at29_administrators_have_names_of_their_own() {
    let f = Fixture::new();
    let r = f.admin(
        "POST",
        "/admin/v1/members",
        Some(json!({ "name": " avery ", "class": "administrator" })),
    );
    assert_eq!(code_of(&r), (409, "name_taken".into()));
    // a standard member may share a name; made an administrator, they may not
    let other = f.admin_ok(
        "POST",
        "/admin/v1/members",
        Some(json!({ "name": "Avery" })),
    )["id"]
        .as_u64()
        .unwrap();
    let r = f.admin(
        "PUT",
        &format!("/admin/v1/members/{other}/class"),
        Some(json!({ "class": "administrator" })),
    );
    assert_eq!(code_of(&r), (409, "name_taken".into()));
    let r = f.admin(
        "POST",
        "/admin/v1/members",
        Some(json!({ "name": "Kim", "class": "owner" })),
    );
    assert_eq!(code_of(&r), (400, "bad_class".into()));
}

// ----- 30: the last administrator ----------------------------------------------------------------

#[test]
fn at30_the_last_administrator_stays_one() {
    let f = Fixture::new();
    let me = avery(&f);
    let r = f.admin("DELETE", &format!("/admin/v1/members/{me}"), None);
    assert_eq!(code_of(&r), (409, "last_administrator".into()));
    let r = f.admin(
        "PUT",
        &format!("/admin/v1/members/{me}/class"),
        Some(json!({ "class": "standard" })),
    );
    assert_eq!(code_of(&r), (409, "last_administrator".into()));
    assert_eq!(member_named(&f, ADMIN_NAME)["class"], "administrator");

    // with two, one can be made standard, and then the other is the last
    let blake = f.add_administrator("Blake", BLAKE_PASSWORD);
    f.admin_ok(
        "PUT",
        &format!("/admin/v1/members/{me}/class"),
        Some(json!({ "class": "standard" })),
    );
    let blakes = f.session_of("Blake", BLAKE_PASSWORD);
    let r = f.admin_with(
        Some(&blakes),
        "DELETE",
        &format!("/admin/v1/members/{blake}"),
        None,
    );
    assert_eq!(code_of(&r), (409, "last_administrator".into()));
    // with two again, one can be removed
    let r = f.admin_with(
        Some(&blakes),
        "PUT",
        &format!("/admin/v1/members/{me}/class"),
        Some(json!({ "class": "administrator" })),
    );
    assert_eq!(r.status, 200);
    let r = f.admin_with(
        Some(&blakes),
        "DELETE",
        &format!("/admin/v1/members/{me}"),
        None,
    );
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(members(&f).len(), 1);
}

// ----- 31: removing a member ----------------------------------------------------------------------

#[test]
fn at31_removing_a_member_revokes_their_devices_and_removes_their_grants() {
    let f = Fixture::new();
    let alpha = TestApp::start("alpha");
    let beta = TestApp::start("beta");
    f.register(&alpha, false, false);
    f.register(&beta, false, false);
    let sam = f.add_member("Sam");
    let kim = f.add_member("Kim");
    let sams = [
        f.pair(sam, "alpha", "Sam's phone"),
        f.pair(sam, "beta", "Sam's phone"),
    ];
    let kims = f.pair(kim, "alpha", "Kim's phone");
    let waiting = f.code(sam, "alpha");

    let r = f.admin("DELETE", &format!("/admin/v1/members/{sam}"), None);
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(
        f.admin("DELETE", &format!("/admin/v1/members/{sam}"), None)
            .status,
        404
    );
    for (app, token) in [("alpha", &sams[0]), ("beta", &sams[1])] {
        let r = f.api(app, token, "GET", "/api/x");
        assert_eq!(code_of(&r), (401, "not_paired".into()), "{app}");
    }
    // their rows stay in the list, revoked; their grants are gone
    let devices = f.admin_ok("GET", "/admin/v1/devices", None)["devices"].clone();
    let theirs: Vec<&Value> = devices
        .as_array()
        .unwrap()
        .iter()
        .filter(|d| d["member"] == sam)
        .collect();
    assert_eq!(theirs.len(), 2);
    assert!(theirs.iter().all(|d| !d["revoked"].is_null()));
    let grants = f.admin_ok("GET", "/admin/v1/grants", None)["grants"].clone();
    assert!(grants
        .as_array()
        .unwrap()
        .iter()
        .all(|g| g["member"] != sam));
    // a code made for them before no longer pairs
    let r = f.phone_json(
        "alpha",
        "POST",
        "/hub/pair",
        &[],
        &json!({ "code": waiting, "pin": PIN, "device": "x" }),
    );
    assert_eq!(code_of(&r), (403, "wrong_code".into()));
    // the rest of the household is untouched
    assert_eq!(f.api("alpha", &kims, "GET", "/api/x").status, 200);
}

#[test]
fn at31_a_guest_is_removed_as_a_member_too() {
    // (owner decision 2026-11-19)
    let f = Fixture::new();
    let trips = TestApp::start("trips");
    f.register(&trips, false, true);
    let invite = f.admin_ok(
        "POST",
        "/admin/v1/invites",
        Some(json!({ "app": "trips", "scope": "trip-7" })),
    )["code"]
        .as_str()
        .unwrap()
        .to_string();
    let r = f.phone_json(
        "trips",
        "POST",
        "/hub/pair",
        &[],
        &json!({ "invite": invite, "name": "Kim" }),
    );
    assert_eq!(r.status, 200);
    let token = r.json()["token"].as_str().unwrap().to_string();
    let kim = r.json()["member"]["id"].as_u64().unwrap();
    // a guest's name and class don't change
    let r = f.admin(
        "PUT",
        &format!("/admin/v1/members/{kim}"),
        Some(json!({ "name": "Kimberly" })),
    );
    assert_eq!(code_of(&r), (409, "guest_member".into()));
    let r = f.admin(
        "PUT",
        &format!("/admin/v1/members/{kim}/class"),
        Some(json!({ "class": "standard" })),
    );
    assert_eq!(code_of(&r), (409, "guest_member".into()));
    // removing needs an administrator, and takes the guest and their phone
    let r = f.admin_with(None, "DELETE", &format!("/admin/v1/members/{kim}"), None);
    assert_eq!(code_of(&r), (401, "administrator_needed".into()));
    f.admin_ok("DELETE", &format!("/admin/v1/members/{kim}"), None);
    assert_eq!(
        code_of(&f.api("trips", &token, "GET", "/api/trip")),
        (401, "not_paired".into())
    );
    assert!(members(&f).iter().all(|m| m["name"] != "Kim"));
    let devices = f.admin_ok("GET", "/admin/v1/devices", None)["devices"].clone();
    assert!(!devices[0]["revoked"].is_null(), "the row stays, revoked");
}

// ----- 32: keep-hub reset-administrator ------------------------------------------------------------

fn reset(f: &Fixture, name: &str, password: &str) -> (bool, String) {
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
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), said)
}

#[test]
fn at32_reset_administrator_sets_a_new_password_and_changes_nothing_else() {
    let f = Fixture::new();
    let alpha = TestApp::start("alpha");
    f.register(&alpha, false, false);
    let sam = f.add_member("Sam");
    let token = f.pair(sam, "alpha", "Sam's phone");
    let before: Vec<Value> = ["members", "grants", "devices", "apps"]
        .iter()
        .map(|l| f.admin_ok("GET", &format!("/admin/v1/{l}"), None))
        .collect();

    // while the hub runs
    let (ok, said) = reset(&f, ADMIN_NAME, "reset-by-the-computer");
    assert!(ok, "{said}");
    assert!(!said.contains("reset-by-the-computer"));
    assert_eq!(f.sign_in(ADMIN_NAME, ADMIN_PASSWORD).status, 403);
    f.session_of(ADMIN_NAME, "reset-by-the-computer");
    let after: Vec<Value> = ["members", "grants", "devices", "apps"]
        .iter()
        .map(|l| {
            f.admin_with(None, "GET", &format!("/admin/v1/{l}"), None)
                .json()
        })
        .collect();
    assert_eq!(before, after);
    assert_eq!(f.api("alpha", &token, "GET", "/api/x").status, 200);

    // a standard member's name, a name nobody has, a short password: refused
    let (ok, said) = reset(&f, "Sam", "sams-new-password");
    assert!(!ok);
    assert!(said.contains("standard member"), "{said}");
    let (ok, said) = reset(&f, "Nobody", "whatever-password");
    assert!(!ok);
    assert!(said.contains("no administrator named"), "{said}");
    let (ok, said) = reset(&f, ADMIN_NAME, "short");
    assert!(!ok);
    assert!(said.contains("8"), "{said}");
    f.session_of(ADMIN_NAME, "reset-by-the-computer");
}

// ----- 33: Keep-Member-Class -----------------------------------------------------------------------

#[test]
fn at33_a_forwarded_request_carries_the_members_class_and_never_the_phones() {
    let f = Fixture::new();
    let trips = TestApp::start("trips");
    f.register(&trips, false, true);
    let sam = f.add_member("Sam");
    let me = avery(&f);
    let invite = f.admin_ok(
        "POST",
        "/admin/v1/invites",
        Some(json!({ "app": "trips", "scope": "trip-7" })),
    )["code"]
        .as_str()
        .unwrap()
        .to_string();
    let r = f.phone_json(
        "trips",
        "POST",
        "/hub/pair",
        &[],
        &json!({ "invite": invite, "name": "Kim" }),
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["member"]["class"], "guest");
    let guest = r.json()["token"].as_str().unwrap().to_string();
    for (who, token, class) in [
        (me, f.pair(me, "trips", "Avery's phone"), "administrator"),
        (sam, f.pair(sam, "trips", "Sam's phone"), "standard"),
        (0, guest, "guest"),
    ] {
        let auth = format!("Bearer {token}");
        // a phone that claims to be an administrator is not believed
        let r = f.phone(
            "trips",
            "GET",
            "/api/who",
            &[
                ("Authorization", &auth),
                ("Keep-Member-Class", "administrator"),
                ("keep-member-class", "administrator"),
            ],
            None,
        );
        assert_eq!(r.status, 200, "{}", r.text());
        let seen = trips.seen();
        let last = seen.last().unwrap();
        let classes: Vec<&str> = last
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("keep-member-class"))
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(classes, [class], "member {who}");
        // the phone learns its own class
        let whoami = f.api("trips", &token, "GET", "/hub/whoami").json();
        assert_eq!(whoami["member"]["class"], class);
        assert_eq!(whoami["hub"]["protocols"], json!([1]));
    }
}

// ----- 34: registering a new app, and the same app again ----------------------------------------------

#[test]
fn at34_a_new_app_needs_a_session_and_the_same_app_again_does_not() {
    let f = Fixture::new();
    let alpha = TestApp::start("alpha");
    let port = support::free_port();
    let reg = Fixture::registration(&alpha, port, false, false);
    let r = f.admin_with(None, "POST", "/admin/v1/apps", Some(reg.clone()));
    assert_eq!(code_of(&r), (401, "administrator_needed".into()));
    assert!(f.hub().app_port("alpha").is_none(), "no port opened");
    assert!(f.admin_ok("GET", "/admin/v1/apps", None)["apps"]
        .as_array()
        .unwrap()
        .is_empty());

    let first = f.admin_ok("POST", "/admin/v1/apps", Some(reg.clone()));
    alpha.set_secret(first["secret"].as_str().unwrap());
    let sam = f.add_member("Sam");
    let token = f.pair(sam, "alpha", "Sam's phone");

    // an update: the admin token alone
    let mut update = reg.clone();
    update["version"] = json!("0.2.0");
    let r = f.admin_with(None, "POST", "/admin/v1/apps", Some(update));
    assert_eq!(r.status, 200, "{}", r.text());
    let second = r.json();
    assert_ne!(first["secret"], second["secret"]);
    alpha.set_secret(second["secret"].as_str().unwrap());
    // its phones and grants kept
    assert_eq!(f.api("alpha", &token, "GET", "/api/x").status, 200);
    assert!(alpha.seen().last().unwrap().trusted);
    assert_eq!(
        f.admin_ok("GET", "/admin/v1/grants", None)["grants"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // unregistering is an administrator's act
    let r = f.admin_with(None, "DELETE", "/admin/v1/apps/alpha", None);
    assert_eq!(code_of(&r), (401, "administrator_needed".into()));
    f.admin_ok("DELETE", "/admin/v1/apps/alpha", None);
}

// ----- 35: /hub/unpair -------------------------------------------------------------------------------

#[test]
fn at35_unpair_revokes_the_calling_device_only() {
    let f = Fixture::new();
    let alpha = TestApp::start("alpha");
    let beta = TestApp::start("beta");
    f.register(&alpha, false, false);
    f.register(&beta, false, false);
    let sam = f.add_member("Sam");
    let one = f.pair(sam, "alpha", "Sam's phone");
    let two = f.pair(sam, "alpha", "Sam's tablet");
    let other_app = f.pair(sam, "beta", "Sam's phone");

    // another app's token on this port: not this app's device, nothing revoked
    let auth = format!("Bearer {other_app}");
    let r = f.phone(
        "alpha",
        "POST",
        "/hub/unpair",
        &[("Authorization", &auth)],
        None,
    );
    assert_eq!(code_of(&r), (401, "not_paired".into()));
    // no token
    let r = f.phone("alpha", "POST", "/hub/unpair", &[], None);
    assert_eq!(code_of(&r), (401, "not_paired".into()));

    let auth = format!("Bearer {one}");
    let r = f.phone(
        "alpha",
        "POST",
        "/hub/unpair",
        &[("Authorization", &auth)],
        None,
    );
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(
        code_of(&f.api("alpha", &one, "GET", "/api/x")),
        (401, "not_paired".into())
    );
    assert_eq!(f.api("alpha", &two, "GET", "/api/x").status, 200);
    assert_eq!(f.api("beta", &other_app, "GET", "/api/x").status, 200);
    // it works without a grant too: the person removes the app from a phone that lost it
    f.admin_ok("DELETE", &format!("/admin/v1/grants/{sam}/alpha"), None);
    let auth = format!("Bearer {two}");
    let r = f.phone(
        "alpha",
        "POST",
        "/hub/unpair",
        &[("Authorization", &auth)],
        None,
    );
    assert_eq!(r.status, 200);
    let devices = f.admin_ok("GET", "/admin/v1/devices", None)["devices"].clone();
    let revoked: Vec<bool> = devices
        .as_array()
        .unwrap()
        .iter()
        .map(|d| !d["revoked"].is_null())
        .collect();
    assert_eq!(revoked, [true, true, false]);
    // a GET is not an unpair
    let r = f.api("beta", &other_app, "GET", "/hub/unpair");
    assert_eq!(r.status, 404);
}

// ----- 38: one phone per code, and nothing from a phone ---------------------------------------------

#[test]
fn at38_a_code_pairs_one_phone_and_no_phone_makes_codes_grants_or_invites() {
    let f = Fixture::new();
    let trips = TestApp::start("trips");
    f.register(&trips, false, true);
    let sam = f.add_member("Sam");
    let code = f.code(sam, "trips");
    let pair = |code: &str, device: &str| {
        f.phone_json(
            "trips",
            "POST",
            "/hub/pair",
            &[],
            &json!({ "code": code, "pin": PIN, "device": device }),
        )
    };
    assert_eq!(pair(&code, "Sam's phone").status, 200);
    assert_eq!(
        code_of(&pair(&code, "Sam's tablet")),
        (403, "wrong_code".into())
    );
    let again = f.code(sam, "trips");
    assert_eq!(pair(&again, "Sam's tablet").status, 200);

    // an administrator's own phone can't make a code, a grant or an invite on an app's port
    let me = avery(&f);
    let token = f.pair(me, "trips", "Avery's phone");
    let auth = format!("Bearer {token}");
    let grants = f.admin_ok("GET", "/admin/v1/grants", None);
    let before = trips.seen().len();
    for path in [
        "/hub/pairing-codes",
        "/hub/grants",
        "/hub/invites",
        "/hub/pin",
        "/hub/members",
        "/admin/v1/pairing-codes",
        "/admin/v1/grants",
        "/admin/v1/invites",
    ] {
        let body = json!({ "member": sam, "app": "trips", "scope": "x" });
        let r = f.phone_json("trips", "POST", path, &[("Authorization", &auth)], &body);
        assert!(
            r.status == 404 || r.status == 405,
            "{path}: {} {}",
            r.status,
            r.text()
        );
    }
    assert_eq!(trips.seen().len(), before, "nothing reached the backend");
    assert_eq!(f.admin_ok("GET", "/admin/v1/grants", None), grants);
    assert!(f.admin_ok("GET", "/admin/v1/invites", None)["invites"]
        .as_array()
        .unwrap()
        .is_empty());
}
