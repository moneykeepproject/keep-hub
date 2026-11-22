//! Stage 9: Revisions 2 and 3 of `docs/specs/keep-hub.md` — an app that pairs by code alone,
//! a household where the computer's sign-in is enough, and where a household gets its
//! registration code. The test names give the acceptance test they cover (45 to 55).
//!
//! Everything runs on 127.0.0.1 with keys in memory. Passwords, PINs and codes here are
//! test values, not secrets.

mod support;

use serde_json::{json, Value};
use support::{Fixture, TestApp, ADMIN_NAME, ADMIN_PASSWORD, PIN};

fn code_of(r: &support::Reply) -> (u16, String) {
    (r.status, r.error())
}

/// A registration with `pairing` (left out when `None`).
fn registration(app: &TestApp, port: u16, pairing: Option<&str>) -> Value {
    let mut v = Fixture::registration(app, port, false, false);
    if let Some(p) = pairing {
        v["pairing"] = json!(p);
    }
    v
}

/// Register `app` with `pairing` on a free port, as `f.admin` does (with the fixture's
/// session, which an open household doesn't have); give the app its secret. The answer.
fn register(f: &Fixture, app: &TestApp, pairing: Option<&str>) -> Value {
    let port = support::free_port();
    let v = f.admin_ok(
        "POST",
        "/admin/v1/apps",
        Some(registration(app, port, pairing)),
    );
    app.set_secret(v["secret"].as_str().unwrap());
    v
}

/// A hub set up as an open household: an administrator named [`ADMIN_NAME`] with no
/// password, and no household PIN.
fn open_household() -> Fixture {
    let f = Fixture::not_set_up();
    let r = f.admin_with(
        None,
        "POST",
        "/admin/v1/setup",
        Some(json!({ "name": ADMIN_NAME, "sign_in_is_enough": true })),
    );
    assert_eq!(r.status, 200, "{}", r.text());
    f
}

fn first_member(f: &Fixture) -> u32 {
    f.admin_ok("GET", "/admin/v1/members", None)["members"][0]["id"]
        .as_u64()
        .unwrap() as u32
}

/// Pair by code alone: `{"code", "device"}`, no PIN.
fn pair_by_code(f: &Fixture, app: &str, code: &str) -> support::Reply {
    f.phone_json(
        app,
        "POST",
        "/hub/pair",
        &[],
        &json!({ "code": code, "device": "Sam's phone" }),
    )
}

fn token_of(r: &support::Reply) -> String {
    assert_eq!(r.status, 200, "{}", r.text());
    r.json()["token"].as_str().unwrap().to_string()
}

fn status(f: &Fixture) -> Value {
    f.admin_ok("GET", "/admin/v1/status", None)
}

/// A request marked A with the admin token alone.
fn token_alone_adds_a_member(f: &Fixture) -> support::Reply {
    f.admin_with(
        None,
        "POST",
        "/admin/v1/members",
        Some(json!({ "name": "Someone" })),
    )
}

// ----- 45 to 48: an app chooses how its phones pair (Revision 2 A) --------------------------------

#[test]
fn at45_a_code_app_pairs_without_a_pin_and_its_token_works_for_it_only() {
    // in a household with no PIN set
    let f = open_household();
    assert_eq!(f.admin_ok("GET", "/admin/v1/pin", None)["set"], false);
    let ez = TestApp::start("ez");
    let other = TestApp::start("other");
    register(&f, &ez, Some("code"));
    register(&f, &other, Some("code"));
    let sam = f.add_member("Sam");
    f.admin_ok(
        "POST",
        "/admin/v1/grants",
        Some(json!({ "member": sam, "app": "other" })),
    );
    let code = f.code(sam, "ez");
    let r = pair_by_code(&f, "ez", &code);
    let token = token_of(&r);
    assert_eq!(r.json()["app"], "ez");
    assert_eq!(f.api("ez", &token, "GET", "/api/items").status, 200);
    assert_eq!(ez.seen().len(), 1);
    // for that app only, though Sam may use the other one too
    assert_eq!(
        code_of(&f.api("other", &token, "GET", "/api/items")),
        (403, "no_access".into())
    );
    assert!(other.seen().is_empty());
    // pin_not_set is never answered on its port, whatever else is wrong
    let r = pair_by_code(&f, "ez", "ZZZZ-ZZZZ");
    assert_eq!(code_of(&r), (403, "wrong_code".into()));
}

#[test]
fn at45_the_same_body_on_a_code_and_pin_apps_port_is_refused() {
    let f = Fixture::new();
    let ez = TestApp::start("ez");
    let trips = TestApp::start("trips");
    register(&f, &ez, Some("code"));
    register(&f, &trips, None);
    let sam = f.add_member("Sam");
    let code = f.code(sam, "trips");
    assert_eq!(
        code_of(&pair_by_code(&f, "trips", &code)),
        (403, "wrong_code".into())
    );
    // the code is still there (one wrong PIN of five) and pairs with the PIN
    let r = f.phone_json(
        "trips",
        "POST",
        "/hub/pair",
        &[],
        &json!({ "code": code, "pin": PIN, "device": "phone" }),
    );
    token_of(&r);
    // a secured household: the code app still pairs by code alone, and a PIN sent to its
    // port is ignored, right or wrong
    let code = f.code(sam, "ez");
    let r = f.phone_json(
        "ez",
        "POST",
        "/hub/pair",
        &[],
        &json!({ "code": code, "pin": "000000", "device": "phone" }),
    );
    token_of(&r);
}

#[test]
fn at46_a_wrong_code_on_a_code_apps_port_is_a_wrong_try() {
    let f = open_household();
    let ez = TestApp::start("ez");
    register(&f, &ez, Some("code"));
    let sam = f.add_member("Sam");
    // a code older than 10 minutes is refused
    let old = f.code(sam, "ez");
    f.advance_minutes(10);
    f.clock.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        code_of(&pair_by_code(&f, "ez", &old)),
        (403, "wrong_code".into())
    );
    // a used code is refused
    let code = f.code(sam, "ez");
    token_of(&pair_by_code(&f, "ez", &code));
    assert_eq!(
        code_of(&pair_by_code(&f, "ez", &code)),
        (403, "wrong_code".into())
    );
    // (two wrong tries so far) eight more make ten
    for _ in 0..8 {
        assert_eq!(
            code_of(&pair_by_code(&f, "ez", "ABCD-EFGH")),
            (403, "wrong_code".into())
        );
    }
    // ten from this address pause it, a good code too
    let good = f.code(sam, "ez");
    assert_eq!(
        code_of(&pair_by_code(&f, "ez", &good)),
        (429, "pairing_paused".into())
    );
    // the pause ends when the ten minutes have passed
    f.advance_minutes(11);
    let good = f.code(sam, "ez");
    token_of(&pair_by_code(&f, "ez", &good));
}

#[test]
fn at47_pairing_is_code_and_pin_unless_said_and_shown_everywhere() {
    let f = Fixture::new();
    let trips = TestApp::start("trips");
    let ez = TestApp::start("ez");
    assert_eq!(register(&f, &trips, None)["pairing"], "code_and_pin");
    assert_eq!(register(&f, &ez, Some("code"))["pairing"], "code");
    let st = status(&f);
    let pairing_in = |apps: &Value, id: &str, key: Option<&str>| {
        apps.as_array()
            .unwrap()
            .iter()
            .map(|a| key.map_or(a, |k| &a[k]))
            .find(|a| a["id"] == id)
            .map(|a| a["pairing"].clone())
            .unwrap()
    };
    assert_eq!(
        pairing_in(&st["apps"], "trips", Some("app")),
        "code_and_pin"
    );
    assert_eq!(pairing_in(&st["apps"], "ez", Some("app")), "code");
    let apps = f.admin_ok("GET", "/admin/v1/apps", None)["apps"].clone();
    assert_eq!(pairing_in(&apps, "trips", None), "code_and_pin");
    assert_eq!(pairing_in(&apps, "ez", None), "code");
    // a way the hub doesn't know is refused
    let other = TestApp::start("other");
    let r = f.admin(
        "POST",
        "/admin/v1/apps",
        Some(registration(&other, support::free_port(), Some("pin"))),
    );
    assert_eq!(code_of(&r), (400, "bad_registration".into()));
}

#[test]
fn at48_changing_pairing_needs_an_administrator_keeping_it_doesnt() {
    let f = Fixture::new();
    let ez = TestApp::start("ez");
    let port = support::free_port();
    f.admin_ok(
        "POST",
        "/admin/v1/apps",
        Some(registration(&ez, port, Some("code"))),
    );
    let token_alone = |pairing: Option<&str>| {
        f.admin_with(
            None,
            "POST",
            "/admin/v1/apps",
            Some(registration(&ez, port, pairing)),
        )
    };
    // the same value: the admin token is enough
    let r = token_alone(Some("code"));
    assert_eq!(r.status, 200, "{}", r.text());
    // a different one (left out is code_and_pin) needs an administrator
    assert_eq!(
        code_of(&token_alone(None)),
        (401, "administrator_needed".into())
    );
    assert_eq!(
        code_of(&token_alone(Some("code_and_pin"))),
        (401, "administrator_needed".into())
    );
    assert_eq!(
        f.admin_ok("GET", "/admin/v1/apps", None)["apps"][0]["pairing"],
        "code"
    );
    let v = f.admin_ok(
        "POST",
        "/admin/v1/apps",
        Some(registration(&ez, port, Some("code_and_pin"))),
    );
    assert_eq!(v["pairing"], "code_and_pin");
    // in an open household the token is an administrator, but an app can't move to the
    // PIN there: the household has none
    let f = open_household();
    let ez = TestApp::start("ez");
    let port = support::free_port();
    f.admin_ok(
        "POST",
        "/admin/v1/apps",
        Some(registration(&ez, port, Some("code"))),
    );
    let r = f.admin_with(
        None,
        "POST",
        "/admin/v1/apps",
        Some(registration(&ez, port, None)),
    );
    assert_eq!(code_of(&r), (409, "household_not_secured".into()));
    assert_eq!(
        f.admin_ok("GET", "/admin/v1/apps", None)["apps"][0]["pairing"],
        "code"
    );
}

// ----- 49 to 53: a household where the computer's sign-in is enough (Revision 2 B) ----------------

#[test]
fn at49_an_open_household_takes_the_admin_token_as_an_administrator() {
    let f = Fixture::not_set_up();
    // the second form takes no password and no PIN
    for body in [
        json!({ "name": ADMIN_NAME, "sign_in_is_enough": true, "password": ADMIN_PASSWORD }),
        json!({ "name": ADMIN_NAME, "sign_in_is_enough": true, "pin": PIN }),
        json!({ "name": ADMIN_NAME }),
    ] {
        let r = f.admin_with(None, "POST", "/admin/v1/setup", Some(body.clone()));
        assert_eq!(code_of(&r), (400, "bad_setup".into()), "{body}");
    }
    let r = f.admin_with(
        None,
        "POST",
        "/admin/v1/setup",
        Some(json!({ "name": ADMIN_NAME, "sign_in_is_enough": true })),
    );
    assert_eq!(r.status, 200, "{}", r.text());
    let v = r.json();
    assert_eq!(v["household"], "open");
    assert_eq!(v["member"]["class"], "administrator");
    assert!(v.get("session").is_none(), "no session is used");
    let st = status(&f);
    assert_eq!(st["household"], "open");
    // a member, a grant and a pairing code, each with the admin token alone
    let ez = TestApp::start("ez");
    register(&f, &ez, Some("code"));
    let r = token_alone_adds_a_member(&f);
    assert_eq!(r.status, 200, "{}", r.text());
    let sam = r.json()["id"].as_u64().unwrap();
    let r = f.admin_with(
        None,
        "POST",
        "/admin/v1/grants",
        Some(json!({ "member": sam, "app": "ez" })),
    );
    assert_eq!(r.status, 200, "{}", r.text());
    let r = f.admin_with(
        None,
        "POST",
        "/admin/v1/pairing-codes",
        Some(json!({ "member": sam, "app": "ez" })),
    );
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json()["code"].as_str().unwrap().len(), 9);
    // signing in is not used
    assert_eq!(
        code_of(&f.sign_in(ADMIN_NAME, ADMIN_PASSWORD)),
        (409, "sign_in_not_used".into())
    );
    // nor are passwords or a PIN on their own: `secure` gives both
    let me = first_member(&f);
    let r = f.admin_with(
        None,
        "PUT",
        &format!("/admin/v1/members/{me}/password"),
        Some(json!({ "password": ADMIN_PASSWORD })),
    );
    assert_eq!(code_of(&r), (409, "household_not_secured".into()));
    let r = f.admin_with(None, "PUT", "/admin/v1/pin", Some(json!({ "pin": PIN })));
    assert_eq!(code_of(&r), (409, "household_not_secured".into()));
    // members added are administrators or standard members as chosen, none with a password
    let r = f.admin_with(
        None,
        "POST",
        "/admin/v1/members",
        Some(json!({ "name": "Blake", "class": "administrator" })),
    );
    assert_eq!(r.json()["class"], "administrator");
    let members = f.admin_ok("GET", "/admin/v1/members", None)["members"].clone();
    assert!(members
        .as_array()
        .unwrap()
        .iter()
        .all(|m| m["password_set"] == false));
    // the class still travels to the app
    let code = f.code(sam as u32, "ez");
    let token = token_of(&pair_by_code(&f, "ez", &code));
    f.api("ez", &token, "GET", "/api/me");
    let seen = ez.seen();
    assert_eq!(seen[0].header("Keep-Member-Class"), Some("standard"));
    // a second first set-up, in either form, is refused
    for body in [
        json!({ "name": "Other", "sign_in_is_enough": true }),
        json!({ "name": "Other", "password": ADMIN_PASSWORD, "pin": PIN }),
    ] {
        let r = f.admin_with(None, "POST", "/admin/v1/setup", Some(body));
        assert_eq!(code_of(&r), (409, "already_set_up".into()));
    }
    // the open household is kept in hub.sqlite: a restart doesn't change it
    let mut f = f;
    f.restart();
    assert_eq!(status(&f)["household"], "open");
    assert_eq!(token_alone_adds_a_member(&f).status, 200);
}

#[test]
fn at49_reset_administrator_in_an_open_household_has_nothing_to_reset() {
    let f = open_household();
    let e = keep_hub::reset_administrator(f.dir.path(), ADMIN_NAME, "a-new-password").unwrap_err();
    assert!(e.contains("nothing to reset"), "{e}");
}

/// Where `pin_not_set` is met again: an open household that still has an app that pairs
/// with the PIN, as a hub upgraded from stage 7 may (its apps were registered before any
/// administrator, so they keep `code_and_pin`).
#[test]
fn pin_not_set_is_answered_for_a_pin_app_in_an_open_household() {
    let f = Fixture::not_set_up();
    let trips = TestApp::start("trips");
    {
        let r = keep_hub::registry::Registry::open(f.dir.path()).unwrap();
        r.put_app(&keep_hub::registry::App {
            id: "trips".into(),
            title: "Trips".into(),
            version: "1.0".into(),
            protocol: 1,
            public_port: support::free_port(),
            loopback_port: trips.port,
            money: false,
            guests: false,
            registered: 1,
            pairing: "code_and_pin".into(),
        })
        .unwrap();
    }
    let f = {
        let r = f.admin_with(
            None,
            "POST",
            "/admin/v1/setup",
            Some(json!({ "name": ADMIN_NAME, "sign_in_is_enough": true })),
        );
        assert_eq!(r.status, 200, "{}", r.text());
        f
    };
    let sam = f.add_member("Sam");
    let r = f.admin(
        "POST",
        "/admin/v1/pairing-codes",
        Some(json!({ "member": sam, "app": "trips" })),
    );
    assert_eq!(code_of(&r), (409, "pin_not_set".into()));
    // an update keeps its pairing with the token alone, and doesn't need a secured household
    let mut f = f;
    f.restart();
    let port = f.admin_ok("GET", "/admin/v1/apps", None)["apps"][0]["public_port"]
        .as_u64()
        .unwrap() as u16;
    let v = f.admin_ok(
        "POST",
        "/admin/v1/apps",
        Some(registration(&trips, port, None)),
    );
    trips.set_secret(v["secret"].as_str().unwrap());
    let r = f.phone_json(
        "trips",
        "POST",
        "/hub/pair",
        &[],
        &json!({ "code": "ABCD-EFGH", "pin": PIN, "device": "phone" }),
    );
    assert_eq!(code_of(&r), (409, "pin_not_set".into()));
}

#[test]
fn at50_a_code_and_pin_app_needs_a_secured_household() {
    let f = open_household();
    let trips = TestApp::start("trips");
    let port = support::free_port();
    let r = f.admin_with(
        None,
        "POST",
        "/admin/v1/apps",
        Some(registration(&trips, port, None)),
    );
    assert_eq!(code_of(&r), (409, "household_not_secured".into()));
    assert!(r.json()["message"].as_str().unwrap().contains("password"));
    assert_eq!(f.admin_ok("GET", "/admin/v1/apps", None)["apps"], json!([]));
    // secure: a password for the administrator and the household PIN
    let r = f.admin_with(
        None,
        "POST",
        "/admin/v1/secure",
        Some(json!({ "name": ADMIN_NAME, "password": ADMIN_PASSWORD, "pin": PIN })),
    );
    assert_eq!(r.status, 200, "{}", r.text());
    let v = r.json();
    assert_eq!(v["household"], "secured");
    let session = v["session"].as_str().unwrap().to_string();
    assert_eq!(status(&f)["household"], "secured");
    // now it registers with a session...
    let r = f.admin_with(
        Some(&session),
        "POST",
        "/admin/v1/apps",
        Some(registration(&trips, port, None)),
    );
    assert_eq!(r.status, 200, "{}", r.text());
    // ...and a request marked A with the admin token alone answers administrator_needed
    assert_eq!(
        code_of(&token_alone_adds_a_member(&f)),
        (401, "administrator_needed".into())
    );
    // signing in works from now on
    f.session_of(ADMIN_NAME, ADMIN_PASSWORD);
    assert_eq!(f.admin_ok("GET", "/admin/v1/pin", None)["set"], true);
}

#[test]
fn at50_secure_names_an_administrator_and_checks_the_password_and_pin() {
    let f = open_household();
    f.add_member("Sam");
    let secure = |name: &str, password: &str, pin: &str| {
        f.admin_with(
            None,
            "POST",
            "/admin/v1/secure",
            Some(json!({ "name": name, "password": password, "pin": pin })),
        )
    };
    assert_eq!(
        code_of(&secure("Sam", ADMIN_PASSWORD, PIN)),
        (409, "not_an_administrator".into())
    );
    assert_eq!(
        code_of(&secure("Nobody", ADMIN_PASSWORD, PIN)),
        (404, "no_such_member".into())
    );
    assert_eq!(
        code_of(&secure(ADMIN_NAME, "short", PIN)),
        (400, "bad_password".into())
    );
    assert_eq!(
        code_of(&secure(ADMIN_NAME, ADMIN_PASSWORD, "12")),
        (400, "bad_pin".into())
    );
    assert_eq!(status(&f)["household"], "open", "nothing changed");
}

#[test]
fn at51_a_secured_household_stays_secured() {
    // secured by its first set-up
    let f = Fixture::new();
    let secure = |f: &Fixture| {
        f.admin_with(
            None,
            "POST",
            "/admin/v1/secure",
            Some(json!({ "name": ADMIN_NAME, "password": ADMIN_PASSWORD, "pin": PIN })),
        )
    };
    assert_eq!(code_of(&secure(&f)), (409, "already_secured".into()));
    // and secured by `secure`: a second one is refused, and nothing makes it open again
    let f = open_household();
    assert_eq!(secure(&f).status, 200);
    assert_eq!(code_of(&secure(&f)), (409, "already_secured".into()));
    let r = f.admin_with(
        None,
        "POST",
        "/admin/v1/setup",
        Some(json!({ "name": "Other", "sign_in_is_enough": true })),
    );
    assert_eq!(code_of(&r), (409, "already_set_up".into()));
    assert_eq!(status(&f)["household"], "secured");
}

#[test]
fn at52_phones_paired_before_secure_work_after_it() {
    let f = open_household();
    let ez = TestApp::start("ez");
    register(&f, &ez, Some("code"));
    let sam = f.add_member("Sam");
    let code = f.code(sam, "ez");
    let before = token_of(&pair_by_code(&f, "ez", &code));
    let r = f.admin_with(
        None,
        "POST",
        "/admin/v1/secure",
        Some(json!({ "name": ADMIN_NAME, "password": ADMIN_PASSWORD, "pin": PIN })),
    );
    let session = r.json()["session"].as_str().unwrap().to_string();
    assert_eq!(f.api("ez", &before, "GET", "/api/items").status, 200);
    // making its code now needs a session
    let make = |s: Option<&str>| {
        f.admin_with(
            s,
            "POST",
            "/admin/v1/pairing-codes",
            Some(json!({ "member": sam, "app": "ez" })),
        )
    };
    assert_eq!(code_of(&make(None)), (401, "administrator_needed".into()));
    let r = make(Some(&session));
    assert_eq!(r.status, 200, "{}", r.text());
    // and it still pairs without a PIN
    let code = r.json()["code"].as_str().unwrap().to_string();
    let after = token_of(&pair_by_code(&f, "ez", &code));
    assert_eq!(f.api("ez", &after, "GET", "/api/items").status, 200);
}

#[test]
fn at53_todays_first_set_up_makes_a_secured_household() {
    // Tests 27 to 32 are unchanged (administrators.rs); the set-up's answer and the status
    // now also say which kind of household it is.
    let f = Fixture::not_set_up();
    let r = f.admin_with(
        None,
        "POST",
        "/admin/v1/setup",
        Some(json!({ "name": ADMIN_NAME, "password": ADMIN_PASSWORD, "pin": PIN })),
    );
    assert_eq!(r.json()["household"], "secured");
    assert_eq!(status(&f)["household"], "secured");
    assert_eq!(
        code_of(&token_alone_adds_a_member(&f)),
        (401, "administrator_needed".into())
    );
}

// ----- 54 and 55: where a household gets its registration code (Revision 3) ----------------------

#[test]
fn at54_the_status_shows_the_code_page_and_whether_a_code_is_needed() {
    let (f, world) = Fixture::with_world(|cfg| {
        cfg.names.service = support::world::SERVICE.into();
        cfg.names.acme = support::world::ACME_DIR.into();
        cfg.names.staging = true;
    });
    world
        .allow_loopback
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let st = status(&f);
    assert_eq!(st["code_page"], "https://getmoneykeep.org/phone-access/");
    assert_eq!(st["code_needed"], true);
    let names = f.admin_ok("GET", "/admin/v1/names", None);
    assert_eq!(names["code_page"], st["code_page"]);
    assert_eq!(names["code_needed"], true);
    // turned on: registered, so no code is needed
    f.admin_ok(
        "POST",
        "/admin/v1/names/on",
        Some(json!({ "registration_code": support::world::CODE })),
    );
    let wait_registered = || {
        for _ in 0..200 {
            if status(&f)["code_needed"] == false {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        false
    };
    assert!(wait_registered(), "{}", status(&f));
    // and it stays no after turning names off and on
    f.admin_ok("POST", "/admin/v1/names/off", None);
    assert_eq!(status(&f)["code_needed"], false);
    f.admin_ok("POST", "/admin/v1/names/on", Some(json!({})));
    assert_eq!(status(&f)["code_needed"], false);
}

#[test]
fn at55_a_code_page_that_isnt_https_or_is_too_long_is_refused() {
    let f = Fixture::new();
    let set = |s: Option<&str>, page: &str| {
        f.admin_with(
            s,
            "PUT",
            "/admin/v1/names/code-page",
            Some(json!({ "code_page": page })),
        )
    };
    let session = f.session_of(ADMIN_NAME, ADMIN_PASSWORD);
    let s = Some(session.as_str());
    let long = format!("https://example.org/{}", "a".repeat(181));
    assert_eq!(long.len(), 201);
    for bad in ["http://example.org/codes", long.as_str()] {
        assert_eq!(
            code_of(&set(s, bad)),
            (400, "bad_code_page".into()),
            "{bad}"
        );
        assert_eq!(
            status(&f)["code_page"],
            "https://getmoneykeep.org/phone-access/",
            "the old value stays"
        );
    }
    // changing it is an administrator's act
    assert_eq!(
        code_of(&set(None, "https://example.org/codes")),
        (401, "administrator_needed".into())
    );
    let r = set(s, "https://example.org/codes");
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json()["code_page"], "https://example.org/codes");
    // kept in hub.json, through a restart
    let mut f = f;
    f.restart();
    assert_eq!(status(&f)["code_page"], "https://example.org/codes");
    let cfg = keep_hub::HubConfig::load(f.dir.path()).unwrap();
    assert_eq!(cfg.names.code_page, "https://example.org/codes");
}
