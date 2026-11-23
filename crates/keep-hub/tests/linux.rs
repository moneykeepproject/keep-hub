//! Stage 10, part D: the Linux service (Revision 4 D of `docs/specs/keep-hub.md`). The test
//! names give the acceptance test they cover (62 and 63).
//!
//! Test 63 runs everywhere, with a fake machine that plays Linux. Test 62 installs the real
//! `.deb` on a Linux computer with systemd and a home network, as root: it is end to end and
//! ignored by default.

mod support;

use keep_hub::linuxfw::{Active, LinuxFirewall};
use keep_hub::machine::{FirewallScan, Os};
use serde_json::{json, Value};
use support::{Fixture, TestApp};

fn check(f: &Fixture, number: u64) -> Value {
    let run = f.admin_ok("POST", "/admin/v1/problems", None);
    run["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["number"] == number)
        .unwrap_or_else(|| panic!("no check {number}: {run}"))
        .clone()
}

fn linux_firewall(f: &Fixture, active: Option<Active>, open: &[u16]) {
    *f.machine.firewall.lock().unwrap() = Some(FirewallScan {
        linux: Some(LinuxFirewall {
            active,
            open: open.iter().map(|p| (*p, *p)).collect(),
        }),
        ..FirewallScan::default()
    });
}

#[test]
fn at63_on_linux_check_3_isnt_needed_and_check_4_reads_the_firewall_that_is_on() {
    let f = Fixture::new();
    *f.machine.os.lock().unwrap() = Os::Linux;
    // a profile Windows would call Public means nothing here
    f.machine.set_profile("Public");
    let c = check(&f, 3);
    assert_eq!(
        (c["status"].clone(), c["words"].clone()),
        (json!("ok"), json!("Not needed on this system."))
    );

    // no firewall on: check 4 passes
    let app = TestApp::start("vacapick");
    let port = f.register(&app, false, false);
    linux_firewall(&f, None, &[]);
    let c = check(&f, 4);
    assert_eq!(
        (c["status"].clone(), c["words"].clone()),
        (json!("ok"), json!("No firewall is on."))
    );

    // ufw on, with the certificate page's port and not the app's: fails, naming that port
    let helper = f.hub().helper().unwrap().port();
    linux_firewall(&f, Some(Active::Ufw), &[helper]);
    let run = f.admin_ok("POST", "/admin/v1/problems", None);
    assert_eq!(run["stopped_at"], 4);
    let c = check(&f, 4);
    assert_eq!(c["status"], "failed");
    assert_eq!(c["code"], "firewall_ports_closed");
    let words = c["words"].as_str().unwrap();
    assert!(
        words.contains("ufw") && words.contains(&port.to_string()),
        "{words}"
    );
    assert!(!words.contains(&helper.to_string()), "{words}");
    // the action is ServicesKeep's Fix, with exactly that port (owner decision 2026-11-22)
    assert_eq!(c["action"]["kind"], "serviceskeep");
    assert_eq!(c["action"]["ports"], json!([port]));
    assert_eq!(c["action"]["firewall"], "ufw");
    let r = f.admin(
        "POST",
        "/admin/v1/problems/fix",
        Some(json!({ "check": 4 })),
    );
    assert_eq!(r.error(), "fix_in_serviceskeep");
    assert!(
        f.machine.fixes.lock().unwrap().is_empty(),
        "the hub changes nothing"
    );

    // with every port open: passes, naming the firewall
    linux_firewall(&f, Some(Active::Firewalld), &[helper, port]);
    let c = check(&f, 4);
    assert_eq!(c["status"], "ok");
    assert!(c["words"].as_str().unwrap().contains("firewalld"));

    // nft couldn't be asked: the check can't be made, and the run goes on
    *f.machine.firewall_error.lock().unwrap() = Some("nft couldn't read the rules".into());
    assert_eq!(check(&f, 4)["status"], "unknown");
}

/// The status says how keys are kept (owner decision 2026-11-22: the words when keys are
/// protected by file permissions only).
#[test]
fn the_status_says_how_keys_are_kept() {
    let f = Fixture::new();
    let keys = f.admin_ok("GET", "/admin/v1/status", None)["keys"].clone();
    if cfg!(windows) {
        assert_eq!(keys["sealed"], true);
    } else {
        // (the tests' hubs never get systemd's credential)
        assert_eq!(
            keys,
            json!({ "sealed": false, "words": "Keys are protected by file permissions only." })
        );
    }
}

/// Acceptance test 62, end to end: run as root on a Linux computer with systemd and a home
/// network, after `cargo xtask deb`:
///
/// ```text
/// sudo cargo test -p keep-hub --test linux at62 -- --ignored
/// ```
///
/// It installs `dist/keep-hub_<version>_<arch>.deb`, checks the service runs as `keep-hub`
/// with `/var/lib/keep-hub`, that 16080 listens on the home address and the admin address on
/// 127.0.0.1 only, then `dpkg -r` and checks the folder is still there. Reaching the ports
/// from another computer is checked by hand (or by the runner's second machine).
#[test]
#[ignore = "end to end: needs root, systemd, a home network and the built .deb"]
fn at62_the_deb_installs_a_service_as_keep_hub_and_dpkg_r_keeps_the_data() {
    use std::process::Command;
    let run = |prog: &str, args: &[&str]| {
        let o = Command::new(prog).args(args).output().unwrap();
        assert!(
            o.status.success(),
            "{prog} {args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8_lossy(&o.stdout).into_owned()
    };
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let deb = std::fs::read_dir(root.join("dist"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "deb"))
        .expect("run cargo xtask deb first");
    run("dpkg", &["-i", deb.to_str().unwrap()]);
    let show = |p: &str| {
        run(
            "systemctl",
            &["show", "-p", p, "--value", "keep-hub.service"],
        )
    };
    for _ in 0..50 {
        if show("ActiveState").trim() == "active" {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    assert_eq!(show("ActiveState").trim(), "active");
    assert_eq!(show("User").trim(), "keep-hub");
    assert!(std::path::Path::new("/var/lib/keep-hub/hub.json").is_file());
    let listening = run("ss", &["-Htlnp"]);
    let lines: Vec<&str> = listening
        .lines()
        .filter(|l| l.contains("keep-hub"))
        .collect();
    assert!(lines.iter().any(|l| l.contains(":16080")), "{listening}");
    let admin: Vec<&&str> = lines.iter().filter(|l| l.contains(":16081")).collect();
    assert!(!admin.is_empty() && admin.iter().all(|l| l.contains("127.0.0.1:16081")));
    // the admin token is the group's, and the keys are sealed when systemd-creds is there
    let mode = run("stat", &["-c", "%a %G", "/var/lib/keep-hub/admin.token"]);
    assert_eq!(mode.trim(), "640 keep-hub");
    run("dpkg", &["-r", "keep-hub"]);
    assert_ne!(show("ActiveState").trim(), "active");
    assert!(std::path::Path::new("/var/lib/keep-hub/hub.json").is_file());
}

/// Owner decision 2026-11-22: on Linux the hub can't open an app's port, so registering
/// says when the firewall doesn't let it in yet, for the app to show.
#[test]
fn on_linux_registering_says_when_the_firewall_keeps_the_port_closed() {
    let f = Fixture::new();
    *f.machine.os.lock().unwrap() = Os::Linux;
    let helper = f.hub().helper().unwrap().port();
    linux_firewall(&f, Some(Active::Ufw), &[helper]);
    let app = TestApp::start("vacapick");
    let port = support::free_port();
    let v = f.admin_ok(
        "POST",
        "/admin/v1/apps",
        Some(Fixture::registration(&app, port, false, false)),
    );
    assert_eq!(v["firewall"]["open"], false);
    let words = v["firewall"]["words"].as_str().unwrap();
    assert!(
        words.contains(&port.to_string()) && words.contains("ServicesKeep"),
        "{words}"
    );
    // with the port open, or no firewall on, nothing is said
    linux_firewall(&f, Some(Active::Ufw), &[helper, port]);
    let v = f.admin_ok(
        "POST",
        "/admin/v1/apps",
        Some(Fixture::registration(&app, port, false, false)),
    );
    assert!(v.get("firewall").is_none());
    linux_firewall(&f, None, &[]);
    let other = TestApp::start("trips");
    let v = f.admin_ok(
        "POST",
        "/admin/v1/apps",
        Some(Fixture::registration(
            &other,
            support::free_port(),
            false,
            false,
        )),
    );
    assert!(v.get("firewall").is_none());
    // and not on Windows
    *f.machine.os.lock().unwrap() = Os::Windows;
    let v = f.admin_ok(
        "POST",
        "/admin/v1/apps",
        Some(Fixture::registration(&app, port, false, false)),
    );
    assert!(v.get("firewall").is_none());
}
