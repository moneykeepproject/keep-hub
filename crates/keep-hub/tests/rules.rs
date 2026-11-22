//! Stage 8: the newer rules of `docs/specs/keep-hub.md` that earlier stages built and the
//! spec now names as acceptance tests 36, 37 and 39 to 44. Some parts are also shown by
//! earlier tests (named in each test here); these tests put each rule in one place.
//!
//! Everything runs on 127.0.0.1 with keys in memory; the name and certificates come from
//! the fake world in `support::world`.

mod support;

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use serde_json::json;
use support::{named_hub, Fixture, TestApp};

// ----- 36: what passes without a token --------------------------------------------------------------

#[test]
fn at36_without_a_token_only_plain_gets_pass() {
    // (also in hub.rs, only_what_the_hub_checked_reaches_a_backend)
    let f = Fixture::new();
    let alpha = TestApp::start("alpha");
    f.register(&alpha, false, false);
    let sam = f.add_member("Sam");
    let token = f.pair(sam, "alpha", "Sam's phone");

    let r = f.phone("alpha", "GET", "/app.js", &[], None);
    assert_eq!(
        (r.status, r.text()),
        (200, "alpha file /app.js".to_string())
    );
    let passed = alpha.seen().len();

    let r = f.phone("alpha", "POST", "/app.js", &[], Some(b"x"));
    assert_eq!((r.status, r.error().as_str()), (405, "method_not_allowed"));
    let r = f.phone("alpha", "GET", "/app.js", &[], Some(b"x"));
    assert_eq!((r.status, r.error().as_str()), (405, "method_not_allowed"));
    for path in [
        "/a/../app.js",
        "/a//app.js",
        "//app.js",
        "/a\\app.js",
        "/a%5capp.js",
        "/%2Fapi/items",
        "/%2fapi/items",
        "/%61pi/items",
        "/x/%2e%2e/api/items",
    ] {
        let r = f.phone("alpha", "GET", path, &[], None);
        assert_eq!((r.status, r.error().as_str()), (400, "bad_path"), "{path}");
    }
    assert_eq!(
        alpha.seen().len(),
        passed,
        "none of them reached the backend"
    );

    // a body with Transfer-Encoding: 411, with a token too
    let auth = format!("Bearer {token}");
    let r = f.phone(
        "alpha",
        "POST",
        "/api/items",
        &[("Authorization", &auth), ("Transfer-Encoding", "chunked")],
        None,
    );
    assert_eq!((r.status, r.error().as_str()), (411, "length_needed"));
}

// ----- 37: an app's port -------------------------------------------------------------------------------

#[test]
fn at37_any_port_but_a_held_one_the_hubs_own_or_one_below_1024() {
    let f = Fixture::new();
    let alpha = TestApp::start("alpha");
    let beta = TestApp::start("beta");
    // a port not in the table
    let not_in_table = support::free_port();
    let v = f.admin_ok(
        "POST",
        "/admin/v1/apps",
        Some(Fixture::registration(&alpha, not_in_table, false, false)),
    );
    alpha.set_secret(v["secret"].as_str().unwrap());
    assert_eq!(f.port("alpha").port(), not_in_table);
    assert_eq!(f.phone("alpha", "GET", "/x", &[], None).status, 200);

    let admin_port = f.hub().admin.port();
    let page_port = f.hub().helper().unwrap().port();
    for (port, code) in [
        (not_in_table, "port_taken"),
        (admin_port, "bad_registration"),
        (page_port, "bad_registration"),
        (1023, "bad_registration"),
        (80, "bad_registration"),
    ] {
        let r = f.admin(
            "POST",
            "/admin/v1/apps",
            Some(Fixture::registration(&beta, port, false, false)),
        );
        assert_eq!(r.error(), code, "port {port}: {}", r.text());
        assert!(r.status == 400 || r.status == 409);
    }
    // the refusal names the app that holds the port
    let r = f.admin(
        "POST",
        "/admin/v1/apps",
        Some(Fixture::registration(&beta, not_in_table, false, false)),
    );
    assert!(r.text().contains("Test alpha"), "{}", r.text());
    assert!(f.hub().app_port("beta").is_none());
}

// ----- 39: HSTS ------------------------------------------------------------------------------------------

#[test]
fn at39_hsts_for_a_day_by_name_with_a_real_certificate_only() {
    // (also in fallback.rs, at18_... and a_staging_certificate_is_served_by_name_...)
    let (f, world, _app, name) = named_hub(false);
    let roots = [world.acme_ca()];
    // the hub's own answer, one passed on, and one whose backend sent its own HSTS
    for path in ["/hub/check", "/index.html", "/slow?ms=0"] {
        let (r, _) = f.phone_by_name("vacapick", &roots, &name, path).unwrap();
        assert_eq!(r.status, 200, "{path}");
        let all: Vec<&str> = r
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("strict-transport-security"))
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(all, ["max-age=86400"], "{path}");
    }
    // by address: none, not even the backend's own
    for path in ["/hub/check", "/index.html", "/slow?ms=0"] {
        let r = f.phone("vacapick", "GET", path, &[], None);
        assert_eq!(r.header("strict-transport-security"), None, "{path}");
    }
}

#[test]
fn at39_no_hsts_with_a_staging_certificate() {
    let (f, world, _app, name) = named_hub(true);
    let roots = [world.acme_ca()];
    for path in ["/hub/check", "/slow?ms=0"] {
        let (r, _) = f.phone_by_name("vacapick", &roots, &name, path).unwrap();
        assert_eq!(r.header("strict-transport-security"), None, "{path}");
    }
}

// ----- 40: the addresses with a pairing code ---------------------------------------------------------

#[test]
fn at40_a_code_gives_four_addresses_and_url_is_by_name_only_with_a_real_certificate() {
    // (also in fallback.rs: at18_a_phone_paired_by_name_..., a_staging_certificate_...,
    // without_a_name_a_pairing_code_...)
    for (staging, by_name) in [(false, true), (true, false)] {
        let (f, _world, _app, name) = named_hub(staging);
        let sam = f.add_member("Sam");
        let v = f.admin_ok(
            "POST",
            "/admin/v1/pairing-codes",
            Some(json!({ "member": sam, "app": "vacapick" })),
        );
        let code = v["code"].as_str().unwrap();
        let port = f.port("vacapick").port();
        for key in ["url", "url_by_address", "certificate_page"] {
            assert!(v[key].is_string(), "{key}: {v}");
        }
        assert!(v.get("url_by_name").is_some(), "{v}");
        assert_eq!(
            v["url_by_address"],
            format!("https://127.0.0.1:{port}/#pair={code}")
        );
        if by_name {
            let named = format!("https://{name}:{port}/#pair={code}");
            assert_eq!(
                (&v["url"], &v["url_by_name"]),
                (&json!(named), &json!(named))
            );
        } else {
            assert_eq!(v["url"], v["url_by_address"], "staging: by address");
        }
    }
    // with no name at all: by address
    let f = Fixture::new();
    let app = TestApp::start("vacapick");
    f.register(&app, false, false);
    let sam = f.add_member("Sam");
    let v = f.admin_ok(
        "POST",
        "/admin/v1/pairing-codes",
        Some(json!({ "member": sam, "app": "vacapick" })),
    );
    assert_eq!(v["url"], v["url_by_address"]);
    assert!(v["certificate_page"]
        .as_str()
        .unwrap()
        .starts_with("http://"));
}

// ----- 41: the certificate page opened from a code ----------------------------------------------------

fn page(f: &Fixture, method: &str, path: &str) -> support::Reply {
    support::http(
        f.hub().helper().unwrap(),
        method,
        path,
        &[("User-Agent", "Mozilla/5.0 (Linux; Android 14)")],
        None,
    )
}

#[test]
fn at41_the_certificate_page_from_a_code_ends_with_the_pairing_link() {
    // (also in fallback.rs: the_page_opened_from_a_pairing_code_..., other_addresses_on_...)
    let f = Fixture::new();
    let app = TestApp::start("vacapick");
    f.register(&app, false, false);
    let port = f.port("vacapick").port();
    let r = page(&f, "GET", "/?app=vacapick&pair=abcd-efgh");
    assert_eq!(r.status, 200);
    let text = r.text();
    let link = format!("https://127.0.0.1:{port}/#pair=ABCD-EFGH");
    let at = text.find(&link).expect("the pairing link");
    // the steps end with it: the downloads (step 1), then step 2 with the pairing link
    // (stage 6's reading: an "Already installed?" list of plain links may follow)
    let step2 = text.find("Step 2").unwrap();
    assert!(text.find("Download certificate").unwrap() < step2 && step2 < at);
    assert_eq!(text.matches("#pair=").count(), 1);
    // a parameter that isn't 8 letters and digits is not shown back
    for bad in ["abc", "abcd-efgh-i", "<script>x", "abcd%20efg"] {
        let r = page(&f, "GET", &format!("/?app=vacapick&pair={bad}"));
        assert_eq!(r.status, 200);
        let t = r.text();
        assert!(!t.contains("#pair="), "{bad}");
        assert!(!t.contains("<script>x"), "{bad}");
    }
    let r = page(&f, "GET", "/?app=<i%20id=probe>&pair=abcd-efgh");
    assert!(
        !r.text().contains("probe"),
        "an unknown app is not shown back"
    );
    // a POST gets no page; another path is sent to the start
    let r = page(&f, "POST", "/");
    assert_ne!(r.status, 200);
    assert!(!r.text().contains("certificate"));
    let r = page(&f, "GET", "/somewhere/else");
    assert!(
        r.status == 301 || r.status == 302 || r.status == 303 || r.status == 307 || r.status == 308
    );
    assert_eq!(r.header("location"), Some("/"));
}

// ----- 42: names off and on again ----------------------------------------------------------------------

#[test]
fn at42_names_off_keeps_the_registration_and_certificate_and_on_again_needs_no_code() {
    // (also in fallback.rs turning_names_off_..., names.rs the_registration_code_is_needed_...)
    let (f, world, _app, name) = named_hub(false);
    let roots = [world.acme_ca()];
    let before = f.admin_ok("GET", "/admin/v1/names", None);
    f.admin_ok("POST", "/admin/v1/names/off", None);
    let off = f.admin_ok("GET", "/admin/v1/names", None);
    assert_eq!(off["state"], "off");
    assert_eq!(off["name"], before["name"], "the registration is kept");
    assert_eq!(
        off["certificate"], before["certificate"],
        "and the certificate"
    );
    let until = Instant::now() + Duration::from_secs(5);
    while f
        .phone_by_name("vacapick", &roots, &name, "/hub/check")
        .is_ok()
    {
        assert!(Instant::now() < until, "still answering by name");
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(
        f.phone("vacapick", "GET", "/hub/check", &[], None).status,
        200
    );

    // on again with no registration code
    f.admin_ok("POST", "/admin/v1/names/on", Some(json!({})));
    let until = Instant::now() + Duration::from_secs(5);
    while f
        .phone_by_name("vacapick", &roots, &name, "/hub/check")
        .is_err()
    {
        assert!(Instant::now() < until, "not answering by name again");
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(world.ns.lock().unwrap().registrations, 1);
    assert_eq!(world.acme.lock().unwrap().new_orders, 1);
}

// ----- 43: staging with the real name service ------------------------------------------------------------

#[test]
fn at43_staging_with_the_real_name_service_is_refused_and_nothing_is_sent() {
    // (also in names.rs staging_uses_lets_encrypts_staging_service_...)
    let (f, world) = Fixture::with_world(|cfg| {
        cfg.names.service = keep_hub::nameservice::NAME_SERVICE.into();
        cfg.names.acme = support::world::ACME_DIR.into();
        cfg.names.staging = true;
    });
    world.allow_loopback.store(true, Ordering::SeqCst);
    let r = f.admin(
        "POST",
        "/admin/v1/names/on",
        Some(json!({ "registration_code": support::world::CODE })),
    );
    assert_eq!((r.status, r.error().as_str()), (409, "names_refused"));
    assert!(r.text().contains("staging"), "{}", r.text());
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(f.admin_ok("GET", "/admin/v1/names", None)["state"], "off");
    assert!(world.ns.lock().unwrap().calls.is_empty());
    assert_eq!(world.acme.lock().unwrap().new_orders, 0);
    assert!(world.acme.lock().unwrap().directories.is_empty());
}

// ----- 44: a slow backend, and the hub's own headers -------------------------------------------------------

#[test]
fn at44_a_backend_that_starts_its_answer_inside_the_limit_is_passed_on() {
    // the real limit is 120 seconds ("119 seconds and then answers"); here 2 seconds stand
    // for it, as the idle limit is shortened in web.rs
    assert_eq!(keep_hub::relay::FIRST_BYTE, Duration::from_secs(120));
    let f = Fixture::with_first_byte(Duration::from_secs(2));
    let app = TestApp::start("alpha");
    f.register(&app, false, false);
    let r = f.phone("alpha", "GET", "/slow?ms=1800", &[], None);
    assert_eq!((r.status, r.text()), (200, "worked it out".to_string()));
    // the hub's nosniff and no-referrer replace the backend's own
    let one = |name: &str| -> Vec<String> {
        r.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
            .collect()
    };
    assert_eq!(one("x-content-type-options"), ["nosniff"]);
    assert_eq!(one("referrer-policy"), ["no-referrer"]);
    // past the limit: the hub gives up and says so
    let r = f.phone("alpha", "GET", "/slow?ms=3000", &[], None);
    assert_eq!((r.status, r.error().as_str()), (502, "app_failed"));
}
