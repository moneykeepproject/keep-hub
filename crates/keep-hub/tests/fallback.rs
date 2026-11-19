//! Stage 4: the hub's own certificate authority as the fallback, the certificate page, and
//! both certificates on one port. The test names give the acceptance test of
//! `docs/specs/keep-hub.md` they cover.
//!
//! Everything runs on 127.0.0.1 against the fake world of `support/world.rs`.

mod support;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use keep_hub::der;
use serde_json::{json, Value};
use support::world::{World, ACME_DIR, CODE, SERVICE};
use support::{Fixture, TestApp, PIN};

/// A hub whose name is ready, with one app; the name.
fn named_hub(staging: bool) -> (Fixture, Arc<World>, TestApp, String) {
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

fn names_of(cert: &[u8]) -> Vec<String> {
    der::cert_info(cert).unwrap().dns_names
}

#[test]
fn at18_one_port_answers_with_the_name_certificate_by_name_and_the_hubs_own_by_address() {
    let (f, world, _app, name) = named_hub(false);
    let roots = [world.acme_ca()];
    // by name: Let's Encrypt's certificate (here the fake's), with HSTS for a day
    let (r, cert) = f
        .phone_by_name("vacapick", &roots, &name, "/hub/check")
        .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(names_of(&cert), std::slice::from_ref(&name));
    assert_eq!(r.header("strict-transport-security"), Some("max-age=86400"));
    // HSTS on passed-through answers too
    let (r, _) = f
        .phone_by_name("vacapick", &roots, &name, "/index.html")
        .unwrap();
    assert_eq!(r.text(), "vacapick file /index.html");
    assert_eq!(r.header("strict-transport-security"), Some("max-age=86400"));

    // by address, on the same port: the hub's own certificate, no HSTS
    let by_address = support::cert_by_address(f.port("vacapick"), &f.hub().ca_der);
    assert!(
        names_of(&by_address).is_empty(),
        "the hub's own is for the address"
    );
    assert_ne!(by_address, cert);
    let r = f.phone("vacapick", "GET", "/hub/check", &[], None);
    assert_eq!(r.status, 200);
    assert_eq!(r.header("strict-transport-security"), None);
    // a phone that trusts only the name's authority can't be fooled by address
    assert!(support::https_raw(
        f.port("vacapick"),
        &world.acme_ca(),
        b"GET / HTTP/1.1\r\n\r\n"
    )
    .is_err());
}

#[test]
fn at18_a_phone_paired_by_name_and_one_paired_by_address_work_side_by_side() {
    let (f, world, app, name) = named_hub(false);
    f.set_pin();
    let sam = f.add_member("Sam");
    let roots = [world.acme_ca()];

    // a pairing code now gives the address by name, by address and the certificate page
    let code = f.admin_ok(
        "POST",
        "/admin/v1/pairing-codes",
        Some(json!({ "member": sam, "app": "vacapick" })),
    );
    let port = f.port("vacapick").port();
    let c = code["code"].as_str().unwrap();
    assert_eq!(code["url"], format!("https://{name}:{port}/#pair={c}"));
    assert_eq!(code["url_by_name"], code["url"]);
    assert_eq!(
        code["url_by_address"],
        format!("https://127.0.0.1:{port}/#pair={c}")
    );
    assert_eq!(
        code["certificate_page"],
        format!("http://{}/?app=vacapick&pair={c}", f.hub().helper)
    );

    // paired by name
    let body = json!({ "code": c, "pin": PIN, "device": "phone by name" }).to_string();
    let req = format!(
        "POST /hub/pair HTTP/1.1\r\nHost: {name}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let (r, _) = support::https_named(f.port("vacapick"), &roots, &name, req.as_bytes()).unwrap();
    assert_eq!(r.status, 200, "{}", r.text());
    let by_name = r.json()["token"].as_str().unwrap().to_string();
    // paired by address
    let by_address = f.pair(sam, "vacapick", "phone by address");

    let req = format!(
        "GET /api/trips HTTP/1.1\r\nHost: {name}\r\nAuthorization: Bearer {by_name}\r\n\r\n"
    );
    let (r, _) = support::https_named(f.port("vacapick"), &roots, &name, req.as_bytes()).unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(
        f.api("vacapick", &by_address, "GET", "/api/trips").status,
        200
    );
    let devices: Vec<String> = app
        .seen()
        .iter()
        .filter_map(|s| s.header("keep-device-name").map(str::to_string))
        .collect();
    assert_eq!(devices, ["phone%20by%20name", "phone%20by%20address"]);
}

#[test]
fn a_staging_certificate_is_served_by_name_but_never_as_trusted() {
    let (f, world, _app, name) = named_hub(true);
    let roots = [world.acme_ca()];
    let (r, cert) = f
        .phone_by_name("vacapick", &roots, &name, "/hub/check")
        .unwrap();
    assert_eq!(names_of(&cert), std::slice::from_ref(&name));
    assert_eq!(
        r.header("strict-transport-security"),
        None,
        "no HSTS for staging"
    );
    assert_eq!(
        f.admin_ok("GET", "/admin/v1/names", None)["certificate"]["staging"],
        true
    );
    // pairing codes keep to the address
    f.set_pin();
    let sam = f.add_member("Sam");
    let code = f.admin_ok(
        "POST",
        "/admin/v1/pairing-codes",
        Some(json!({ "member": sam, "app": "vacapick" })),
    );
    assert!(code["url_by_name"].is_null());
    assert_eq!(code["url"], code["url_by_address"]);
}

#[test]
fn turning_names_off_leaves_the_ports_answering_by_address_only() {
    let (f, world, _app, name) = named_hub(false);
    let roots = [world.acme_ca()];
    f.admin_ok("POST", "/admin/v1/names/off", None);
    let mut refused = false;
    for _ in 0..200 {
        if f.phone_by_name("vacapick", &roots, &name, "/hub/check")
            .is_err()
        {
            refused = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(refused, "the name's certificate is no longer offered");
    assert_eq!(
        f.phone("vacapick", "GET", "/hub/check", &[], None).status,
        200
    );
    // and on again: offered again, no new certificate
    f.admin_ok("POST", "/admin/v1/names/on", None);
    let mut back = false;
    for _ in 0..200 {
        if f.phone_by_name("vacapick", &roots, &name, "/hub/check")
            .is_ok()
        {
            back = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(back);
    assert_eq!(world.acme.lock().unwrap().new_orders, 1);
}

#[test]
fn a_new_name_certificate_replaces_the_old_without_dropping_a_phone() {
    let (f, world, _app, name) = named_hub(false);
    let roots = [world.acme_ca()];
    let (_, before) = f
        .phone_by_name("vacapick", &roots, &name, "/hub/check")
        .unwrap();
    // a phone downloading slowly by name (two seconds) while the certificate is renewed
    let (port, n) = (f.port("vacapick"), name.clone());
    let roots2 = roots.clone();
    let slow = std::thread::spawn(move || {
        let req = format!("GET /trickle?n=20&ms=100 HTTP/1.1\r\nHost: {n}\r\n\r\n");
        support::https_named(port, &roots2, &n, req.as_bytes())
    });
    std::thread::sleep(Duration::from_millis(300));
    f.admin_ok("POST", "/admin/v1/names/renew", None);
    let mut after = before.clone();
    for _ in 0..200 {
        after = f
            .phone_by_name("vacapick", &roots, &name, "/hub/check")
            .unwrap()
            .1;
        if after != before {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_ne!(after, before, "new connections get the new certificate");
    assert_eq!(names_of(&after), [name]);
    let (r, cert) = slow.join().unwrap().unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.body.len(), 20, "the slow download finished");
    assert_eq!(cert, before, "on the certificate it started with");
    assert_eq!(world.acme.lock().unwrap().new_orders, 2);
}

// ----- the certificate page ---------------------------------------------------------------------

fn page(f: &Fixture, path: &str, ua: &str) -> support::Reply {
    support::http(f.hub().helper, "GET", path, &[("User-Agent", ua)], None)
}

#[test]
fn the_certificate_page_gives_the_fingerprint_both_downloads_and_the_steps() {
    let f = Fixture::new();
    let app = TestApp::start("vacapick");
    f.register(&app, false, false);
    let port = f.port("vacapick").port();
    let r = page(
        &f,
        "/",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)",
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("text/html; charset=utf-8"));
    assert!(r
        .header("content-security-policy")
        .unwrap()
        .starts_with("default-src 'none'"));
    let html = r.text();
    assert!(html.contains(&f.hub().info.fingerprint));
    assert!(html.contains("Download certificate (Android)"));
    assert!(html.contains("Download certificate (iPhone or iPad)"));
    for section in [
        "iPhone or iPad</h2>",
        "Android phone or tablet</h2>",
        "Windows computer</h2>",
        "Mac</h2>",
    ] {
        assert!(html.contains(section), "{section}");
    }
    assert!(html.find("iPhone or iPad</h2>") < html.find("Android phone or tablet</h2>"));
    assert!(html.contains(&format!(
        r#"href="https://127.0.0.1:{port}/">Open Test vacapick</a>"#
    )));
    assert!(!html.contains("Step 2"));
    assert!(!html.contains("<script"));
}

#[test]
fn the_page_opened_from_a_pairing_code_ends_with_the_link_that_pairs() {
    let f = Fixture::new();
    let app = TestApp::start("vacapick");
    f.register(&app, false, false);
    let port = f.port("vacapick").port();
    let r = page(&f, "/?app=vacapick&pair=abcd-efgh", "Android");
    assert!(r.text().contains(&format!(
        r#"href="https://127.0.0.1:{port}/#pair=ABCD-EFGH">Open Test vacapick</a>"#
    )));
    let r = page(&f, "/?app=vacapick&invite=WXYZ2345", "Android");
    assert!(r
        .text()
        .contains(&format!("https://127.0.0.1:{port}/#invite=WXYZ-2345")));
    // anything that isn't a code, or an app that isn't there, is ignored and not echoed
    for q in [
        "/?app=vacapick&pair=%3Cscript%3E",
        "/?app=vacapick&pair=<b>x</b>",
        "/?app=other&pair=ABCD-EFGH",
    ] {
        let t = page(&f, q, "Android").text();
        assert!(!t.contains("Step 2"), "{q}");
        assert!(!t.contains("<b>x</b>") && !t.contains("%3Cscript"), "{q}");
    }
}

#[test]
fn both_downloads_carry_the_hubs_authority_and_a_phone_that_installs_it_can_connect() {
    let f = Fixture::new();
    let app = TestApp::start("vacapick");
    f.register(&app, false, false);
    let r = page(&f, "/keep-hub-ca.crt", "Android");
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("application/x-x509-ca-cert"));
    assert_eq!(
        r.header("content-disposition"),
        Some("attachment; filename=\"keep-hub-ca.crt\"")
    );
    let downloaded = der::pem_certificates(&r.text());
    assert_eq!(downloaded, [f.hub().ca_der.clone()]);
    // the downloaded authority is enough to reach the app port by address
    let cert = support::cert_by_address(f.port("vacapick"), &downloaded[0]);
    assert!(!cert.is_empty());

    let r = page(&f, "/keep-hub-ca.mobileconfig", "iPhone");
    assert_eq!(
        r.header("content-type"),
        Some("application/x-apple-aspen-config")
    );
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&f.hub().ca_der);
    assert!(r.text().contains(&b64));
    assert!(r.text().contains("com.apple.security.root"));
}

#[test]
fn other_addresses_on_the_page_go_to_its_start_and_only_get_is_answered() {
    let f = Fixture::new();
    let r = page(&f, "/elsewhere", "Android");
    assert_eq!(r.status, 302);
    assert_eq!(r.header("location"), Some("/"));
    let r = support::http(f.hub().helper, "POST", "/", &[], Some(b"x"));
    assert_eq!(r.status, 405);
    assert!(f.log_lines().contains(&"GET /elsewhere 302".to_string()));
}

/// Acceptance test 24, the part stage 4 adds: with no app registered the hub still answers
/// on the certificate page (and the admin address, stage 1).
#[test]
fn at24_a_hub_with_no_app_registered_answers_on_the_certificate_page() {
    let f = Fixture::new();
    let r = page(&f, "/", "Android");
    assert_eq!(r.status, 200);
    assert!(r
        .text()
        .contains("No app on the hub computer has turned on phones yet."));
}

#[test]
fn without_a_name_a_pairing_code_gives_the_address_and_the_certificate_page() {
    let f = Fixture::new();
    let app = TestApp::start("vacapick");
    f.register(&app, false, false);
    f.set_pin();
    let sam = f.add_member("Sam");
    let code = f.admin_ok(
        "POST",
        "/admin/v1/pairing-codes",
        Some(json!({ "member": sam, "app": "vacapick" })),
    );
    assert!(code["url_by_name"].is_null());
    assert_eq!(code["url"], code["url_by_address"]);
    let page_url = code["certificate_page"].as_str().unwrap();
    let path = page_url.split_once(&f.hub().helper.to_string()).unwrap().1;
    let html = page(&f, path, "Android").text();
    assert!(html.contains("Step 2"), "{path}");
    assert!(html.contains(code["url_by_address"].as_str().unwrap()));
}
