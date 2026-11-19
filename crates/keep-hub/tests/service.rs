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
fn install_service_never_takes_a_folder_and_runs_only_from_program_files_on_windows() {
    let out = hub()
        .args(["install-service", "--data", "/tmp/elsewhere"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(15), "--data is refused");
    if !cfg!(windows) {
        let out = hub().arg("install-service").output().unwrap();
        assert_eq!(out.status.code(), Some(15), "Windows only");
        assert!(String::from_utf8_lossy(&out.stderr).contains("setup"));
    } else {
        // the test program isn't in Program Files
        let out = hub().arg("install-service").output().unwrap();
        assert_eq!(out.status.code(), Some(10));
    }
}

#[test]
fn service_run_is_for_windows_and_run_is_for_everything_else() {
    if cfg!(windows) {
        return; // started outside the service manager it says so: windows-install.ps1
    }
    let out = hub()
        .args(["service-run", "--data", "/tmp/x"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("use `run`"));
}
