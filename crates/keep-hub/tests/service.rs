//! Stage 7: the `keep-hub` program's commands for the setup and the uninstaller. The service
//! itself, the folder's permissions, the firewall rule and the setup run for real on Windows
//! (`scripts/ci/windows-install.ps1`, run by `.github/workflows/windows.yml`).

mod support;

use std::process::Command;

use support::{Fixture, TestApp};

fn hub() -> Command {
    Command::new(env!("CARGO_BIN_EXE_keep-hub"))
}

#[test]
fn the_uninstaller_learns_which_apps_still_use_the_hub_while_it_runs() {
    let f = Fixture::new();
    let data = f.dir.path().to_str().unwrap().to_string();
    let out = hub()
        .args(["registered-apps", "--data", &data])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), "", "no apps: nothing");

    let a = TestApp::start("vacapick");
    let b = TestApp::start("carpick");
    f.register(&a, false, false);
    f.register(&b, false, false);
    let out = hub()
        .args(["registered-apps", "--data", &data])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let line = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let mut names: Vec<&str> = line.split(", ").collect();
    names.sort_unstable();
    // (support::Fixture::registration names a test app "Test <id>")
    let want = vec!["Test carpick", "Test vacapick"];
    assert_eq!(names, want, "{line}");
    // read only: the hub keeps working
    assert_eq!(
        f.phone("vacapick", "GET", "/hub/check", &[], None).status,
        200
    );

    // a folder with no hub in it
    let empty = tempfile::tempdir().unwrap();
    let out = hub()
        .args(["registered-apps", "--data", empty.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
}

#[test]
fn install_service_never_takes_a_folder_and_runs_only_where_it_installs_a_service() {
    let out = hub()
        .args(["install-service", "--data", "/tmp/elsewhere"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(15), "--data is refused");
    let out = hub().arg("install-service").output().unwrap();
    if cfg!(windows) {
        // the test program isn't in Program Files
        assert_eq!(out.status.code(), Some(10));
    } else if cfg!(target_os = "linux") {
        // (Revision 4 D) as root from the .deb only: a test is either not root, or root
        // without the package's unit, and never installs anything
        assert_ne!(out.status.code(), Some(0));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("root") || err.contains(".deb"), "{err}");
    } else {
        assert_eq!(out.status.code(), Some(15), "not on a Mac");
        assert!(String::from_utf8_lossy(&out.stderr).contains("setup"));
    }
}

#[test]
fn service_run_is_for_the_service_manager_and_run_is_for_everything_else() {
    if cfg!(windows) {
        return; // started outside the service manager it says so: windows-install.ps1
    }
    // on Linux only systemd runs it (Revision 4 D); on a Mac never
    let dir = tempfile::tempdir().unwrap();
    let out = hub()
        .args(["service-run", "--data", dir.path().to_str().unwrap()])
        .env_remove("INVOCATION_ID")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("use `run`"));
    assert!(
        std::fs::read_dir(dir.path()).unwrap().next().is_none(),
        "nothing set up"
    );
}

/// Acceptance test 79, end to end on Windows (ignored by default; the Windows setup
/// workflow runs it as an administrator, right after the setup installed the hub): with
/// port 16081 held by another program the service fails to start, and it starts by itself
/// within a minute of the port being freed. The keys the first start wrote are in a folder
/// locked to SYSTEM, the administrators and the service. (That the folder is locked before
/// the first file is written is the order of `keep-hub install-service`'s steps:
/// `service::windows_lock` runs before setup; its unit test checks the steps.)
#[cfg(windows)]
#[test]
#[ignore = "end to end: an installed Keep Hub service, run as an administrator"]
fn at79_a_failed_start_is_started_again_once_the_port_is_free() {
    use std::time::{Duration, Instant};
    let sc = |args: &[&str]| {
        let o = Command::new("sc.exe").args(args).output().unwrap();
        String::from_utf8_lossy(&o.stdout).to_string()
    };
    let state = || sc(&["query", "KeepHub"]);
    let wait_for = |what: &str, secs: u64| {
        let until = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < until {
            if state().contains(what) {
                return true;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        false
    };
    sc(&["stop", "KeepHub"]);
    assert!(wait_for("STOPPED", 30), "{}", state());
    let held = std::net::TcpListener::bind("127.0.0.1:16081").expect("the admin port");
    sc(&["start", "KeepHub"]);
    std::thread::sleep(Duration::from_secs(10));
    assert!(
        !state().contains("RUNNING"),
        "it can't start while the port is held"
    );
    drop(held);
    assert!(
        wait_for("RUNNING", 70),
        "started again by itself: {}",
        state()
    );

    let data = std::path::PathBuf::from(std::env::var_os("ProgramData").unwrap()).join("Keep Hub");
    let acl = |p: &std::path::Path| {
        let o = Command::new("icacls.exe").arg(p).output().unwrap();
        String::from_utf8_lossy(&o.stdout).to_string()
    };
    let keys = acl(&data.join("keys"));
    assert!(
        !keys.contains("S-1-5-32-545") && !keys.contains("Users"),
        "{keys}"
    );
    assert!(keys.contains("KeepHub"), "{keys}");
}
