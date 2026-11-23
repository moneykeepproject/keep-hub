//! Stage 10, parts A to C: what the hub gives ServicesKeep (Revision 4 of
//! `docs/specs/keep-hub.md`): the probe, the tunnel hostname, and Fix as an admin request.
//! The test names give the acceptance test they cover (56 to 61), and the owner's decisions
//! of 2026-11-22 on them.
//!
//! Every request in these tests comes from 127.0.0.1. A "home" source (a private address
//! on the Wi-Fi) can't be sent from a test, so that part of tests 56 and 58 is the unit test
//! `probe::tests::the_source_is_home_tunnel_or_this_computer`. The tests' hubs have
//! 127.0.0.1 as their home address, which is also where a tunnel's connector reaches the
//! hub, so their app ports are the loopback listener (Cloudflare's header counts there).

mod support;

use std::sync::atomic::Ordering;

use serde_json::{json, Value};
use support::{Fixture, TestApp};

fn code_of(r: &support::Reply) -> (u16, String) {
    (r.status, r.error())
}

/// Move the hub's clock on by `ms` (the probe allows one request a second from an address,
/// and every request here comes from 127.0.0.1).
fn later(f: &Fixture, ms: i64) {
    f.clock.fetch_add(ms, Ordering::SeqCst);
}

fn issue(f: &Fixture) -> Value {
    f.admin_ok("POST", "/admin/v1/probe", None)
}

fn nonce(f: &Fixture) -> String {
    issue(f)["nonce"].as_str().unwrap().to_string()
}

fn seen(f: &Fixture, nonce: &str) -> support::Reply {
    f.admin_with(None, "GET", &format!("/admin/v1/probe/{nonce}"), None)
}

fn probe(f: &Fixture, app: &str, nonce: &str, headers: &[(&str, &str)]) -> support::Reply {
    f.phone(app, "GET", &format!("/_probe/{nonce}"), headers, None)
}

// ----- 56 to 58: the probe (Revision 4 A) ---------------------------------------------------------

#[test]
fn at56_a_probe_answers_204_records_its_source_and_reaches_no_backend() {
    let f = Fixture::new();
    let app = TestApp::start("vacapick");
    let port = f.register(&app, false, false);
    // the nonce, the address to open (names are off: the certificate page's port, by
    // address) and its life
    let v = issue(&f);
    let n = v["nonce"].as_str().unwrap().to_string();
    assert!(keep_hub::probe::well_formed(&n));
    assert_eq!(v["minutes"], 10);
    let helper = f.hub().helper().unwrap();
    assert_eq!(
        v["url"],
        format!("http://127.0.0.1:{}/_probe/{n}", helper.port())
    );
    assert_eq!(seen(&f, &n).json(), json!({ "seen": false }));

    // loopback without Cloudflare's header: this computer
    let r = probe(&f, "vacapick", &n, &[]);
    assert_eq!(r.status, 204);
    assert!(r.body.is_empty());
    assert_eq!(r.header("Content-Length"), None, "a 204 has none");
    assert!(app.seen().is_empty(), "no backend receives anything");
    let s = seen(&f, &n).json();
    assert_eq!(
        (s["seen"].clone(), s["source"].clone()),
        (json!(true), json!("this_computer"))
    );
    assert!(s["when"].as_i64().is_some());

    // loopback with it: the tunnel
    later(&f, 1000);
    let n2 = nonce(&f);
    let r = probe(&f, "vacapick", &n2, &[("CF-Connecting-IP", "198.51.100.7")]);
    assert_eq!(r.status, 204);
    assert_eq!(seen(&f, &n2).json()["source"], "tunnel");

    // on the certificate page's port (plain HTTP), answered by its front
    later(&f, 1000);
    let n3 = nonce(&f);
    let r = support::http(helper, "GET", &format!("/_probe/{n3}"), &[], None);
    assert_eq!(r.status, 204);
    assert_eq!(seen(&f, &n3).json()["source"], "this_computer");

    // a nonce with a space, shorter than 16 or longer than 64: 404, nothing recorded
    for bad in ["abcdefgh%20abcdefgh", "abc", &"a".repeat(65)] {
        later(&f, 1000);
        assert_eq!(probe(&f, "vacapick", bad, &[]).status, 404, "{bad}");
        assert_eq!(seen(&f, bad).status, 404);
    }
    let r = support::http(helper, "GET", "/_probe/short", &[], None);
    assert_eq!(r.status, 404);
    // an unknown nonce of the right shape: 204, and nothing kept
    later(&f, 1000);
    let unknown = "0123456789abcdef0123456789abcdef";
    assert_eq!(probe(&f, "vacapick", unknown, &[]).status, 204);
    assert_eq!(code_of(&seen(&f, unknown)), (404, "no_such_probe".into()));
    // the probe needs no token and asks for nothing else: any other method is 404
    later(&f, 1000);
    let r = f.phone("vacapick", "POST", &format!("/_probe/{n}"), &[], Some(b"x"));
    assert_eq!(r.status, 404);
    assert!(app.seen().is_empty());
    // the log names no nonce
    let lines = f.log_lines();
    assert!(lines.iter().any(|l| l.starts_with("GET /_probe/- 204")));
    for n in [&n, &n2, &n3] {
        assert!(lines.iter().all(|l| !l.contains(n.as_str())), "{n}");
    }
    let _ = port;
}

#[test]
fn at56_issuing_a_probe_needs_an_administrator_and_asking_after_it_doesnt() {
    let f = Fixture::new();
    let r = f.admin_with(None, "POST", "/admin/v1/probe", None);
    assert_eq!(code_of(&r), (401, "administrator_needed".into()));
    let n = nonce(&f);
    assert_eq!(seen(&f, &n).status, 200, "the admin token alone");
}

#[test]
fn at56_with_names_on_the_probe_address_is_by_name_on_the_first_app_port() {
    let (f, _world, _app, name) = support::named_hub(false);
    let first = f.port("vacapick").port();
    let other = TestApp::start("trips");
    f.register(&other, false, false);
    let v = issue(&f);
    let n = v["nonce"].as_str().unwrap();
    assert_eq!(v["url"], format!("https://{name}:{first}/_probe/{n}"));
}

#[test]
fn at57_one_probe_a_second_from_an_address_and_a_nonce_lives_probe_minutes() {
    let f = Fixture::with(|cfg| cfg.probe.minutes = 3);
    let app = TestApp::start("vacapick");
    f.register(&app, false, false);
    let v = issue(&f);
    assert_eq!(v["minutes"], 3);
    let n = v["nonce"].as_str().unwrap().to_string();
    let other = nonce(&f);
    assert_eq!(probe(&f, "vacapick", &n, &[]).status, 204);
    // a second within the second: 429, nothing kept
    later(&f, 999);
    assert_eq!(probe(&f, "vacapick", &other, &[]).status, 429);
    assert_eq!(seen(&f, &other).json(), json!({ "seen": false }));
    later(&f, 1);
    assert_eq!(probe(&f, "vacapick", &other, &[]).status, 204);
    // still there within its life, gone after it
    f.advance_minutes(2);
    assert_eq!(seen(&f, &n).status, 200);
    f.advance_minutes(1);
    assert_eq!(code_of(&seen(&f, &n)), (404, "no_such_probe".into()));
    // and the default life is 10 minutes
    let f = Fixture::new();
    let n = nonce(&f);
    f.advance_minutes(9);
    assert_eq!(seen(&f, &n).status, 200);
    f.advance_minutes(1);
    assert_eq!(seen(&f, &n).status, 404);
}

/// Cloudflare's header on a request that came to the home address is ignored. (127.0.0.2
/// stands for the tunnel's loopback address here, so 127.0.0.1 can be the home address; a
/// Mac has no 127.0.0.2 unless it is added, so this runs on Windows and Linux.)
#[cfg(not(target_os = "macos"))]
#[test]
fn at58_cloudflares_header_on_the_home_address_is_ignored() {
    let mut f = Fixture::new();
    f.tunnel_listen = std::net::Ipv4Addr::new(127, 0, 0, 2);
    f.restart();
    let app = TestApp::start("vacapick");
    let port = f.register(&app, false, false);
    let n = nonce(&f);
    let r = probe(&f, "vacapick", &n, &[("CF-Connecting-IP", "198.51.100.7")]);
    assert_eq!(r.status, 204);
    // not the tunnel: the request came from 127.0.0.1, this computer
    assert_eq!(seen(&f, &n).json()["source"], "this_computer");
    // on the loopback listener the same header is believed
    later(&f, 1000);
    let n2 = nonce(&f);
    let twin = std::net::SocketAddr::from(([127, 0, 0, 2], port));
    let bytes = format!(
        "GET /_probe/{n2} HTTP/1.1\r\nHost: x\r\nCF-Connecting-IP: 198.51.100.7\r\nConnection: close\r\n\r\n"
    );
    // (the hub's own certificate is for its home address, 127.0.0.1)
    let (r, _) =
        support::https_named(twin, &[f.hub().ca_der()], "127.0.0.1", bytes.as_bytes()).unwrap();
    assert_eq!(r.status, 204);
    assert_eq!(seen(&f, &n2).json()["source"], "tunnel");
}

// ----- 59 and 60: the tunnel hostname (Revision 4 B) -----------------------------------------------

fn status(f: &Fixture) -> Value {
    f.admin_ok("GET", "/admin/v1/status", None)
}

fn check(f: &Fixture, app: &str) -> Value {
    f.phone(app, "GET", "/hub/check", &[], None).json()
}

#[test]
fn at59_the_tunnel_hostname_is_checked_shown_and_removed() {
    let mut f = Fixture::new();
    let app = TestApp::start("vacapick");
    f.register(&app, false, false);
    assert_eq!(status(&f)["tunnel"]["hostname"], Value::Null);
    assert_eq!(check(&f, "vacapick")["tunnel_hostname"], Value::Null);
    let put = |f: &Fixture, s: Option<&str>, name: &str| {
        f.admin_with(
            s,
            "PUT",
            "/admin/v1/tunnel",
            Some(json!({ "hostname": name })),
        )
    };
    let session = f.session_of(support::ADMIN_NAME, support::ADMIN_PASSWORD);
    let s = Some(session.as_str());
    let long = format!("{}.example.org", "a".repeat(288));
    assert_eq!(long.len(), 300);
    for bad in [long.as_str(), "hub one.example.org"] {
        assert_eq!(
            code_of(&put(&f, s, bad)),
            (400, "bad_hostname".into()),
            "{bad}"
        );
        assert_eq!(
            status(&f)["tunnel"]["hostname"],
            Value::Null,
            "the setting stays"
        );
    }
    // both need an administrator
    assert_eq!(
        code_of(&put(&f, None, "hub.example.org")),
        (401, "administrator_needed".into())
    );
    assert_eq!(
        code_of(&f.admin_with(None, "DELETE", "/admin/v1/tunnel", None)),
        (401, "administrator_needed".into())
    );
    // a good name: in the status and in /hub/check, and kept in hub.json
    let r = put(&f, s, "Hub.Example.org");
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json()["hostname"], "hub.example.org");
    assert_eq!(status(&f)["tunnel"]["hostname"], "hub.example.org");
    assert_eq!(check(&f, "vacapick")["tunnel_hostname"], "hub.example.org");
    assert_eq!(check(&f, "vacapick")["probe"], "/_probe/<nonce>");
    f.restart();
    assert_eq!(status(&f)["tunnel"]["hostname"], "hub.example.org");
    // DELETE removes it
    f.admin_ok("DELETE", "/admin/v1/tunnel", None);
    assert_eq!(status(&f)["tunnel"]["hostname"], Value::Null);
    assert_eq!(check(&f, "vacapick")["tunnel_hostname"], Value::Null);
    let cfg = keep_hub::HubConfig::load(f.dir.path()).unwrap();
    assert_eq!(cfg.tunnel.hostname, "");
}

/// Every file under `dir`, as bytes.
fn every_file(dir: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                todo.push(p);
            } else {
                out.push((p.clone(), std::fs::read(&p).unwrap_or_default()));
            }
        }
    }
    out
}

#[test]
fn at60_a_tunnel_from_the_name_service_passes_its_token_once_and_keeps_none() {
    let (f, world, _app, _name) = support::named_hub(false);
    let first = f.port("vacapick").port();
    let other = TestApp::start("trips");
    f.register(&other, false, false);
    let r = f.admin_with(None, "PUT", "/admin/v1/tunnel/moneykeep-name", None);
    assert_eq!(code_of(&r), (401, "administrator_needed".into()));

    let v = f.admin_ok("PUT", "/admin/v1/tunnel/moneykeep-name", None);
    let id = world.ns.lock().unwrap().hubs.keys().next().unwrap().clone();
    let (port, token) = world.ns.lock().unwrap().tunnels[&id].clone();
    // the first registered app's port was sent, and the fake's token answered
    assert_eq!(port, first);
    assert_eq!(
        world.ns.lock().unwrap().tunnel_requests[0],
        json!({ "port": first })
    );
    assert_eq!(v["token"], token.as_str());
    assert_eq!(v["port"], first);
    let away = format!("{id}.away.getmoneykeep.org");
    assert_eq!(v["hostname"], away.as_str());
    assert_eq!(status(&f)["tunnel"]["hostname"], away.as_str());
    assert_eq!(check(&f, "vacapick")["tunnel_hostname"], away.as_str());
    // a repeat answers the token again (how ServicesKeep repairs)
    let again = f.admin_ok("PUT", "/admin/v1/tunnel/moneykeep-name", None);
    assert_eq!(again["token"], token.as_str());
    // no part of the token in the data folder or the log
    let part = &token[token.len() - 16..];
    for (path, bytes) in every_file(f.dir.path()) {
        assert!(
            !bytes.windows(part.len()).any(|w| w == part.as_bytes()),
            "{} holds the tunnel token",
            path.display()
        );
    }
    assert!(f.log_lines().iter().all(|l| !l.contains(part)));
    // a refusal is the name service's own words
    world.ns.lock().unwrap().refuse_tunnel = Some("tunnel_failed".into());
    let r = f.admin("PUT", "/admin/v1/tunnel/moneykeep-name", None);
    assert_eq!(code_of(&r), (502, "name_service_refused".into()));
    assert!(r.json()["message"]
        .as_str()
        .unwrap()
        .contains("tunnel_failed"));
    assert_eq!(status(&f)["tunnel"]["hostname"], away.as_str(), "unchanged");
    world.ns.lock().unwrap().refuse_tunnel = None;
    // DELETE: the name service deletes it, and the hostname is cleared
    f.admin_ok("DELETE", "/admin/v1/tunnel/moneykeep-name", None);
    assert!(world.ns.lock().unwrap().tunnels.is_empty());
    assert_eq!(status(&f)["tunnel"]["hostname"], Value::Null);
    // with names off, the routes aren't there
    f.admin_ok("POST", "/admin/v1/names/off", None);
    let r = f.admin("PUT", "/admin/v1/tunnel/moneykeep-name", None);
    assert_eq!(code_of(&r), (404, "not_found".into()));
    let r = f.admin("DELETE", "/admin/v1/tunnel/moneykeep-name", None);
    assert_eq!(code_of(&r), (404, "not_found".into()));
}

#[test]
fn at60_with_names_never_turned_on_the_moneykeep_name_routes_are_404() {
    let f = Fixture::new();
    let app = TestApp::start("vacapick");
    f.register(&app, false, false);
    let r = f.admin("PUT", "/admin/v1/tunnel/moneykeep-name", None);
    assert_eq!(code_of(&r), (404, "not_found".into()));
}

// ----- 61: Fix as an admin request (Revision 4 C) -----------------------------------------------

/// Owner decision 2026-11-22: on Windows the firewall needs an administrator's permission,
/// which the service can't ask for, so Fix stays the app's `keep-hub fix-firewall` with
/// Windows' prompt. The request says so and changes nothing.
#[test]
fn at61_on_windows_fix_needs_windows_permission_prompt() {
    let f = Fixture::new();
    let a = TestApp::start("vacapick");
    f.register(&a, false, false);
    // a Windows firewall without the hub's rule
    *f.machine.firewall.lock().unwrap() = Some(keep_hub::machine::FirewallScan::default());
    let body = json!({ "check": 4 });
    let r = f.admin_with(None, "POST", "/admin/v1/problems/fix", Some(body.clone()));
    assert_eq!(code_of(&r), (401, "administrator_needed".into()));
    let r = f.admin("POST", "/admin/v1/problems/fix", Some(body));
    assert_eq!(code_of(&r), (409, "permission_needed".into()));
    assert!(r.json()["message"]
        .as_str()
        .unwrap()
        .contains("fix-firewall"));
    assert!(
        f.machine.fixes.lock().unwrap().is_empty(),
        "the service changed nothing"
    );
    // check 4 offers the command, with Windows' prompt
    let run = f.admin_ok("POST", "/admin/v1/problems", None);
    let action = run["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["number"] == 4)
        .unwrap()["action"]
        .clone();
    assert_eq!(action["command"][1], "fix-firewall");
    assert!(action.get("path").is_none(), "not the admin request");
}

/// Where the hub manages no firewall (a Mac), Fix has nothing to do and answers check 4.
#[test]
fn at61_with_no_firewall_to_manage_fix_answers_check_4() {
    let f = Fixture::new();
    *f.machine.os.lock().unwrap() = keep_hub::machine::Os::Mac;
    let v = f.admin_ok(
        "POST",
        "/admin/v1/problems/fix",
        Some(json!({ "check": 4 })),
    );
    assert_eq!(v["check"]["number"], 4);
    assert_eq!(v["check"]["status"], "ok");
    assert!(f.machine.fixes.lock().unwrap().is_empty());
}

#[test]
fn at61_any_other_check_has_no_fix() {
    let f = Fixture::new();
    let r = f.admin(
        "POST",
        "/admin/v1/problems/fix",
        Some(json!({ "check": 7 })),
    );
    assert_eq!(code_of(&r), (400, "no_fix".into()));
    assert!(r.json()["message"]
        .as_str()
        .unwrap()
        .contains("Use the other way to connect"));
    let r = f.admin(
        "POST",
        "/admin/v1/problems/fix",
        Some(json!({ "check": 11 })),
    );
    assert_eq!(code_of(&r), (400, "bad_request".into()));
    assert!(f.machine.fixes.lock().unwrap().is_empty());
}

/// Owner decision 2026-11-22: on Linux the service can't change ufw or firewalld, so the
/// package opens the ports at install and ServicesKeep does Fix.
#[test]
fn at61_on_linux_fix_is_for_serviceskeep() {
    let f = Fixture::new();
    *f.machine.os.lock().unwrap() = keep_hub::machine::Os::Linux;
    let r = f.admin(
        "POST",
        "/admin/v1/problems/fix",
        Some(json!({ "check": 4 })),
    );
    assert_eq!(code_of(&r), (409, "fix_in_serviceskeep".into()));
    assert!(r.json()["message"]
        .as_str()
        .unwrap()
        .contains("ServicesKeep"));
    assert!(f.machine.fixes.lock().unwrap().is_empty());
}

// ----- owner decision 2026-11-22: tunnel phones are counted by their own address --------------

/// Acceptance test 64 (Revision 4, amended). Through the tunnel every request comes from the
/// connector on 127.0.0.1. Pairing's wrong
/// tries are counted by the visitor's address that Cloudflare sends, so one visitor's wrong
/// codes don't pause pairing for every phone away from home.
#[test]
fn at64_through_the_tunnel_wrong_pairing_tries_are_counted_per_visitor() {
    let f = Fixture::new();
    let app = TestApp::start("vacapick");
    f.register(&app, false, false);
    let sam = f.add_member("Sam");
    let try_from = |visitor: &str, code: &str| {
        f.phone_json(
            "vacapick",
            "POST",
            "/hub/pair",
            &[("CF-Connecting-IP", visitor)],
            &json!({ "code": code, "pin": support::PIN, "device": "phone" }),
        )
    };
    for _ in 0..keep_hub::hub::MAX_FAILURES {
        assert_eq!(try_from("198.51.100.7", "ZZZZ-ZZZZ").status, 403);
    }
    assert_eq!(
        code_of(&try_from("198.51.100.7", "ZZZZ-ZZZZ")),
        (429, "pairing_paused".into())
    );
    // another visitor through the same tunnel still pairs
    let code = f.code(sam, "vacapick");
    let r = try_from("203.0.113.20", &code);
    assert_eq!(r.status, 200, "{}", r.text());
    // and so does a phone at home (on this listener with no header: this computer's own)
    let code = f.code(sam, "vacapick");
    let r = f.phone_json(
        "vacapick",
        "POST",
        "/hub/pair",
        &[],
        &json!({ "code": code, "pin": support::PIN, "device": "phone" }),
    );
    assert_eq!(r.status, 200, "{}", r.text());
}

/// The header counts only on the tunnel's loopback listener: on the home address a phone
/// can't choose the address its wrong tries are counted by. (127.0.0.2 stands for the
/// tunnel's address, so this runs on Windows and Linux.)
#[cfg(not(target_os = "macos"))]
#[test]
fn at64_on_the_home_address_the_header_doesnt_move_the_count() {
    let mut f = Fixture::new();
    f.tunnel_listen = std::net::Ipv4Addr::new(127, 0, 0, 2);
    f.restart();
    let app = TestApp::start("vacapick");
    f.register(&app, false, false);
    let sam = f.add_member("Sam");
    for i in 0..keep_hub::hub::MAX_FAILURES {
        let visitor = format!("198.51.100.{i}");
        let r = f.phone_json(
            "vacapick",
            "POST",
            "/hub/pair",
            &[("CF-Connecting-IP", visitor.as_str())],
            &json!({ "code": "ZZZZ-ZZZZ", "pin": support::PIN, "device": "phone" }),
        );
        assert_eq!(r.status, 403);
    }
    let code = f.code(sam, "vacapick");
    let r = f.phone_json(
        "vacapick",
        "POST",
        "/hub/pair",
        &[("CF-Connecting-IP", "203.0.113.20")],
        &json!({ "code": code, "pin": support::PIN, "device": "phone" }),
    );
    assert_eq!(code_of(&r), (429, "pairing_paused".into()));
}
