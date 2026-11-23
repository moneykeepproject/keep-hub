//! Stage 5: the home address follows the computer, and Find the problem.
//!
//! The fixture's computer is a fake (`support::machine`): the test moves its address,
//! sets the network's profile and plays Windows' firewall. Addresses 127.0.0.x stand in
//! for home addresses (every one of them reaches this computer).

mod support;

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::Duration;

use keep_hub::machine::{self, FirewallScan};
use serde_json::{json, Value};
use support::machine::rule;
use support::world::Home;
use support::{named_hub, Fixture, TestApp};

const MOVED: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

/// Wait (up to 5 s) until `done` is true.
fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    for _ in 0..200 {
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("never happened: {what}");
}

// ----- the address --------------------------------------------------------------------------------

#[test]
fn at15_a_new_address_reaches_the_name_service_keeps_the_name_certificate_and_makes_a_new_authority(
) {
    let (f, world, app, name) = named_hub(false);
    f.set_pin();
    let member = f.add_member("Ann");
    let token = f.pair(member, "vacapick", "Ann's phone");
    let old_ca = f.hub().ca_der();
    let old_fingerprint = f.hub().info().fingerprint;
    let orders = world.acme.lock().unwrap().new_orders;
    assert_eq!(
        world.ns.lock().unwrap().a.get(&name).map(String::as_str),
        Some("127.0.0.1")
    );

    f.machine.move_to(Some(MOVED));
    wait_for("the ports on the new address", || {
        f.hub()
            .app_port("vacapick")
            .is_some_and(|a| a.ip() == MOVED)
    });
    // the name service has the new address
    wait_for("the name service told", || {
        world.ns.lock().unwrap().a.get(&name).map(String::as_str) == Some("127.0.0.2")
    });
    // hub.json too
    let cfg = keep_hub::HubConfig::load(f.dir.path()).unwrap();
    assert_eq!(cfg.address.current, Some(MOVED));
    assert_eq!(
        f.admin_ok("GET", "/admin/v1/addresses", None)["current"],
        "127.0.0.2"
    );

    // a new authority for phones that connect by address
    assert_ne!(f.hub().ca_der(), old_ca);
    assert_ne!(f.hub().info().fingerprint, old_fingerprint);
    assert_eq!(f.hub().info().address, MOVED.to_string());
    // the name's certificate is the same one, served on the new address
    assert_eq!(
        world.acme.lock().unwrap().new_orders,
        orders,
        "no new certificate"
    );
    let (r, cert) = f
        .phone_by_name("vacapick", &[world.acme_ca()], &name, "/hub/check")
        .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(
        keep_hub::der::cert_info(&cert).unwrap().dns_names,
        std::slice::from_ref(&name)
    );
    // the phone paired before keeps its pairing (it installs the new authority by address)
    let r = f.api("vacapick", &token, "GET", "/api/hello");
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(app.seen().iter().any(|s| s.target == "/api/hello"));
    // the certificate page is on the new address and shows the new fingerprint
    assert_eq!(f.hub().helper().unwrap().ip(), MOVED);
    // 127.0.0.1 was the home address here, and is also where a tunnel's connector reaches
    // the hub (Revision 4 A): the port there is now that listener alone, and the home port
    // is on the new address only
    assert!(std::net::TcpStream::connect(("127.0.0.1", f.port("vacapick").port())).is_ok());
    assert_eq!(f.port("vacapick").ip(), MOVED);
    assert!(f.log_lines().iter().any(|l| l.contains("address changed")));
}

#[test]
fn with_no_home_address_the_ports_close_and_names_wait_until_one_comes_back() {
    let (f, _world, _app, name) = named_hub(false);
    let port = f.port("vacapick").port();
    f.machine.move_to(None);
    wait_for("the ports closed", || {
        f.hub().app_port("vacapick").is_none()
    });
    assert!(f.hub().helper().is_none(), "no certificate page either");
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
    wait_for("names waiting", || {
        f.admin_ok("GET", "/admin/v1/names", None)["state"] == "waiting"
    });
    let st = f.admin_ok("GET", "/admin/v1/names", None);
    assert!(
        st["message"].as_str().unwrap().contains("home network"),
        "{st}"
    );
    assert_eq!(st["name"], name.as_str(), "the name is kept");
    assert_eq!(
        f.admin_ok("GET", "/admin/v1/addresses", None)["current"],
        Value::Null
    );
    // the admin address keeps working (this computer only)
    assert_eq!(
        f.admin_ok("GET", "/admin/v1/status", None)["names"],
        "waiting"
    );

    // back home on the same address: the same authority, ready again
    let ca = f.hub().ca_der();
    f.machine.move_to(Some(Ipv4Addr::LOCALHOST));
    wait_for("the ports again", || f.hub().app_port("vacapick").is_some());
    assert_eq!(f.hub().ca_der(), ca, "same address, same authority");
    wait_for("names ready", || {
        f.admin_ok("GET", "/admin/v1/names", None)["state"] == "ready"
    });
}

#[test]
fn a_hub_started_away_from_home_opens_its_ports_when_an_address_comes() {
    let mut f = Fixture::new();
    let app = TestApp::start("vacapick");
    f.register(&app, false, false);
    f.machine.move_to(None);
    f.restart();
    assert!(f.hub().app_port("vacapick").is_none());
    assert_eq!(
        keep_hub::HubConfig::load(f.dir.path())
            .unwrap()
            .address
            .current,
        None
    );
    // registering works without an address; the port opens when one comes
    let other = TestApp::start("carpick");
    f.register(&other, false, false);
    f.machine.move_to(Some(MOVED));
    wait_for("both ports", || {
        f.hub().app_port("vacapick").is_some() && f.hub().app_port("carpick").is_some()
    });
    assert_eq!(
        f.phone("carpick", "GET", "/hub/check", &[], None).status,
        200
    );
}

#[test]
fn a_chosen_adapter_is_used_instead_of_the_default_route() {
    let f = Fixture::new();
    let app = TestApp::start("vacapick");
    f.register(&app, false, false);
    f.machine
        .addresses
        .lock()
        .unwrap()
        .push(machine::LocalAddress {
            address: MOVED.to_string(),
            adapter: "Ethernet".into(),
            profile: "Private".into(),
            ..Default::default()
        });
    let list = f.admin_ok("GET", "/admin/v1/addresses", None);
    assert_eq!(list["adapter"], "automatic");
    assert_eq!(list["addresses"].as_array().unwrap().len(), 2);

    f.admin_ok(
        "PUT",
        "/admin/v1/address",
        Some(json!({ "adapter": "Ethernet" })),
    );
    assert_eq!(f.hub().app_port("vacapick").unwrap().ip(), MOVED);
    // the default route moving doesn't move it
    f.machine.move_to(Some(Ipv4Addr::new(127, 0, 0, 3)));
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(f.hub().app_port("vacapick").unwrap().ip(), MOVED);
    // an adapter that isn't there: no address, until automatic again
    f.admin_ok(
        "PUT",
        "/admin/v1/address",
        Some(json!({ "adapter": "Nope" })),
    );
    assert!(f.hub().app_port("vacapick").is_none());
    f.admin_ok(
        "PUT",
        "/admin/v1/address",
        Some(json!({ "adapter": "automatic" })),
    );
    assert_eq!(
        f.hub().app_port("vacapick").unwrap().ip(),
        Ipv4Addr::new(127, 0, 0, 3)
    );
    let r = f.admin("PUT", "/admin/v1/address", Some(json!({ "adapter": "" })));
    assert_eq!((r.status, r.error().as_str()), (400, "bad_adapter"));
}

// ----- Find the problem ---------------------------------------------------------------------------

fn run(f: &Fixture) -> Value {
    f.admin_ok("POST", "/admin/v1/problems", None)
}

/// `(number, code, status)` of each result.
fn summary(r: &Value) -> Vec<(u64, String, String)> {
    r["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["number"].as_u64().unwrap(),
                c["code"].as_str().unwrap().to_string(),
                c["status"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

fn last(r: &Value) -> &Value {
    r["checks"].as_array().unwrap().last().unwrap()
}

#[test]
fn at20_the_checks_run_in_order_and_stop_at_the_first_failure() {
    let f = Fixture::new();
    let mut app = TestApp::start("vacapick");
    f.register(&app, false, false);
    assert_eq!(
        f.admin_ok("GET", "/admin/v1/problems", None)["checks"],
        json!([])
    );

    // all well (names off: 5 to 8 skipped)
    let r = run(&f);
    let numbers: Vec<u64> = summary(&r).iter().map(|c| c.0).collect();
    assert_eq!(numbers, (1..=10).collect::<Vec<u64>>(), "{r}");
    for (n, code, status) in summary(&r) {
        let want = if (5..=8).contains(&n) {
            "skipped"
        } else {
            "ok"
        };
        assert_eq!(status, want, "{n} {code}");
    }
    assert_eq!(r["stopped_at"], Value::Null);
    assert_eq!(
        f.admin_ok("GET", "/admin/v1/problems", None),
        r,
        "kept for the next app"
    );

    // 3: a public network
    f.machine.set_profile("Public");
    let r = run(&f);
    assert_eq!(r["stopped_at"], 3);
    assert_eq!(summary(&r).len(), 3, "nothing after the failure");
    assert_eq!(last(&r)["code"], "network_public");
    assert_eq!(last(&r)["action"]["target"], "ms-settings:network-status");
    f.machine.set_profile("Private");

    // 4: Windows' firewall with the rule missing; Fix puts it back
    *f.machine.firewall.lock().unwrap() = Some(FirewallScan::default());
    let r = run(&f);
    assert_eq!(
        (r["stopped_at"].as_u64(), last(&r)["code"].as_str()),
        (Some(4), Some("firewall_rule_missing"))
    );
    let command = last(&r)["action"]["command"].as_array().unwrap().clone();
    assert_eq!(command.last().unwrap(), "fix-firewall");
    let exe = Path::new(r"C:\Program Files\Keep Hub\keep-hub.exe");
    machine::fix_firewall(&*f.machine, exe).unwrap();
    let fixes = f.machine.fixes.lock().unwrap().clone();
    assert_eq!(fixes.len(), 1);
    assert_eq!(fixes[0].0.name, machine::FIREWALL_RULE);
    assert_eq!(fixes[0].0.program, exe.display().to_string());
    assert!(!fixes[0].0.profiles.iter().any(|p| p == "Public"));
    assert_eq!(run(&f)["stopped_at"], Value::Null);

    // 4: a rule Windows made that blocks the hub; Fix removes it
    f.machine
        .firewall
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .program_rules = vec![rule(
        "keep-hub.exe",
        "Block",
        r"C:\Program Files\Keep Hub\keep-hub.exe",
    )];
    let r = run(&f);
    assert_eq!(last(&r)["code"], "firewall_blocked");
    machine::fix_firewall(&*f.machine, exe).unwrap();
    let removed = f.machine.fixes.lock().unwrap()[1].1.clone();
    assert_eq!(removed, ["{keep-hub.exe-Block}"]);
    assert_eq!(run(&f)["stopped_at"], Value::Null);
    // a fixed firewall needs no Fix
    machine::fix_firewall(&*f.machine, exe).unwrap();
    assert_eq!(f.machine.fixes.lock().unwrap().len(), 2);

    // a firewall that can't be read says so and doesn't stop the run
    *f.machine.firewall_error.lock().unwrap() = Some("PowerShell is blocked".into());
    let r = run(&f);
    assert_eq!(r["stopped_at"], Value::Null);
    assert_eq!(
        summary(&r)[3],
        (4, "firewall_unknown".into(), "unknown".into())
    );
    *f.machine.firewall_error.lock().unwrap() = None;

    // 9: an app that isn't running
    app.stop();
    let r = run(&f);
    assert_eq!(r["stopped_at"], 9);
    assert_eq!(last(&r)["code"], "app_stopped");
    assert_eq!(last(&r)["action"]["app"], "vacapick");

    // 2: no home address
    f.machine.move_to(None);
    wait_for("the ports closed", || {
        f.hub().app_port("vacapick").is_none()
    });
    let r = run(&f);
    assert_eq!(r["stopped_at"], 2);
    assert_eq!(summary(&r).len(), 2);
    assert_eq!(last(&r)["code"], "no_home_address");
}

#[test]
fn at20_with_names_on_checks_5_to_8_and_10_by_name() {
    let (f, world, _app, name) = named_hub(false);
    let r = run(&f);
    assert_eq!(r["stopped_at"], Value::Null, "{r}");
    assert!(summary(&r).iter().all(|c| c.2 == "ok"), "{r}");
    assert!(last(&r)["words"]
        .as_str()
        .unwrap()
        .contains("phone questions"));

    // 5: the name service can't be reached
    world.service_down.store(true, Ordering::SeqCst);
    let r = run(&f);
    assert_eq!(
        (r["stopped_at"].as_u64(), last(&r)["code"].as_str()),
        (Some(5), Some("name_service_unreachable"))
    );
    assert_eq!(last(&r)["action"]["kind"], "retry");
    world.service_down.store(false, Ordering::SeqCst);

    // 6: public DNS has another address; Update the name sends it again
    world
        .ns
        .lock()
        .unwrap()
        .a
        .insert(name.clone(), "127.0.0.9".into());
    let r = run(&f);
    assert_eq!(last(&r)["code"], "public_dns_wrong");
    assert_eq!(last(&r)["action"]["path"], "/admin/v1/names/address");
    f.admin_ok("POST", "/admin/v1/names/address", None);
    wait_for("the address sent again", || {
        world.ns.lock().unwrap().a.get(&name).map(String::as_str) == Some("127.0.0.1")
    });
    assert_eq!(run(&f)["stopped_at"], Value::Null);

    // 7: the router refuses the name: the other way to connect
    *world.home.lock().unwrap() = Home::Refuses;
    let r = run(&f);
    assert_eq!(last(&r)["code"], "home_dns_blocked");
    let target = last(&r)["action"]["target"].as_str().unwrap().to_string();
    assert_eq!(target, format!("http://{}/", f.hub().helper().unwrap()));
    *world.home.lock().unwrap() = Home::SameAsPublic;

    // 8: the certificate within 14 days of its end
    f.advance_minutes(77 * 24 * 60);
    let r = run(&f);
    assert_eq!(last(&r)["code"], "certificate_ending", "{r}");
    assert_eq!(last(&r)["action"]["path"], "/admin/v1/names/renew");
}

#[test]
fn the_results_hold_no_secrets() {
    let (f, _world, _app, _name) = named_hub(false);
    let r = run(&f).to_string();
    for secret in [f.admin_token.as_str(), support::world::CODE] {
        assert!(!r.contains(secret));
    }
    assert!(!r.contains("PRIVATE KEY"));
}
