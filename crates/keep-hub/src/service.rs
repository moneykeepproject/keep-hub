//! Running the hub in the background: a Windows service, or a macOS launchd daemon (the spec,
//! "Installing and running": as today's hub). Copied from ShareKeep's hub (`service.rs`) and
//! changed for Keep Hub:
//!
//! - The Windows service runs as its own virtual account (`NT SERVICE\KeepHub`), never
//!   LocalSystem, restarting on failure, on a data folder in `%ProgramData%` that only it,
//!   SYSTEM and administrators can change.
//! - The computer's users may list that folder and read `admin.token` (owner decision
//!   2026-11-18: an app's desktop program, running as the person signed in, uses the admin
//!   address with it). Nothing else in the folder is theirs to read: not `keys/`, not
//!   `hub.sqlite`. `hub.json` is readable too until the hub first rewrites it (a rewrite makes a
//!   new file, which takes only the folder's own permissions); the apps don't need it.
//! - The firewall rule is the one stage 5 checks: "Keep Hub", for the hub program, any port,
//!   Private and Domain networks only (owner decision 2026-11-18).
//! - No PowerShell: `sc.exe`, `icacls.exe` and `netsh.exe` only (MoneyKeep's `PSModulePath`
//!   lesson, as ShareKeep).
//! - On the Mac, the daemon runs as the installing user, not root, with the data folder in
//!   that user's Library (owner-only), as ShareKeep's.
//!
//! The steps are plain data ([`windows_install`], [`macos_plist`]) so they are tested on any
//! system; [`run_steps`] runs them.

use std::path::{Path, PathBuf};

use crate::machine::FIREWALL_RULE;

/// The Windows service's name (also its virtual account: `NT SERVICE\KeepHub`).
pub const SERVICE_NAME: &str = "KeepHub";
pub const DISPLAY_NAME: &str = "Keep Hub";
pub const DESCRIPTION: &str =
    "Lets the household's phones reach the Keep and Pick apps on this computer over the home network.";
/// The data folder's name, in `%ProgramData%` on Windows and the user's Application Support
/// on a Mac.
pub const DATA_DIR: &str = "Keep Hub";
/// The macOS launchd label.
pub const LAUNCHD_LABEL: &str = "org.moneykeep.keep-hub";
/// The log file in the data folder (the service has no console).
pub const LOG_FILE: &str = "hub.log";

/// Well-known accounts, by SID (the same on every Windows language).
const SYSTEM: &str = "*S-1-5-18";
const ADMINISTRATORS: &str = "*S-1-5-32-544";
const USERS: &str = "*S-1-5-32-545";

/// One program run: the program and its arguments.
pub type Step = Vec<String>;

fn step(parts: &[&str]) -> Step {
    parts.iter().map(|s| s.to_string()).collect()
}

/// The service's account.
pub fn account() -> String {
    format!("NT SERVICE\\{SERVICE_NAME}")
}

/// Windows: what `keep-hub install-service` runs (elevated) after `setup`, in order.
pub fn windows_install(exe: &Path, data: &Path) -> Vec<Step> {
    let exe = exe.display().to_string();
    let data_s = data.display().to_string();
    let account = account();
    // sc.exe takes `binPath= <value>` as two arguments; the value quotes paths with spaces
    let bin = format!("\"{exe}\" service-run --data \"{data_s}\"");
    vec![
        step(&["sc.exe", "stop", SERVICE_NAME]),
        step(&["sc.exe", "delete", SERVICE_NAME]),
        vec![
            "sc.exe".into(),
            "create".into(),
            SERVICE_NAME.into(),
            "binPath=".into(),
            bin,
            "start=".into(),
            "auto".into(),
            "obj=".into(),
            account.clone(),
            "DisplayName=".into(),
            DISPLAY_NAME.into(),
        ],
        step(&["sc.exe", "description", SERVICE_NAME, DESCRIPTION]),
        step(&[
            "sc.exe",
            "failure",
            SERVICE_NAME,
            "reset=",
            "86400",
            "actions=",
            "restart/5000/restart/5000/restart/60000",
        ]),
        // the folder: owned by Administrators; every permission anyone put on anything in it
        // removed (`/reset`: only what the folder passes down remains), then the folder itself
        // passes down only SYSTEM and administrators full, the service modify. `/L` works on
        // a link itself, never on what it points to (`prepare` refuses links anyway).
        vec![
            "icacls.exe".into(),
            data_s.clone(),
            "/setowner".into(),
            ADMINISTRATORS.into(),
            "/T".into(),
            "/C".into(),
            "/L".into(),
        ],
        vec![
            "icacls.exe".into(),
            data_s.clone(),
            "/reset".into(),
            "/T".into(),
            "/C".into(),
            "/L".into(),
        ],
        vec![
            "icacls.exe".into(),
            data_s.clone(),
            "/inheritance:r".into(),
            "/grant:r".into(),
            format!("{SYSTEM}:(OI)(CI)F"),
            "/grant:r".into(),
            format!("{ADMINISTRATORS}:(OI)(CI)F"),
            "/grant:r".into(),
            format!("{account}:(OI)(CI)M"),
            "/C".into(),
            "/L".into(),
        ],
        // the computer's users: list this folder (not what's in its subfolders), read the
        // admin token and the public facts
        vec![
            "icacls.exe".into(),
            data_s.clone(),
            "/grant".into(),
            format!("{USERS}:(RX)"),
            "/L".into(),
        ],
        vec![
            "icacls.exe".into(),
            data.join(crate::hub::ADMIN_TOKEN_FILE)
                .display()
                .to_string(),
            "/grant".into(),
            format!("{USERS}:(R)"),
            "/L".into(),
        ],
        vec![
            "icacls.exe".into(),
            data.join(crate::config::CONFIG_FILE).display().to_string(),
            "/grant".into(),
            format!("{USERS}:(R)"),
            "/L".into(),
        ],
        step(&[
            "netsh.exe",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={FIREWALL_RULE}"),
        ]),
        vec![
            "netsh.exe".into(),
            "advfirewall".into(),
            "firewall".into(),
            "add".into(),
            "rule".into(),
            format!("name={FIREWALL_RULE}"),
            "dir=in".into(),
            "action=allow".into(),
            "protocol=TCP".into(),
            "profile=private,domain".into(),
            format!("program={exe}"),
            "enable=yes".into(),
        ],
        step(&["sc.exe", "start", SERVICE_NAME]),
    ]
}

/// Windows: removing the service and the firewall rule (the data folder stays).
pub fn windows_uninstall() -> Vec<Step> {
    vec![
        step(&["sc.exe", "stop", SERVICE_NAME]),
        step(&["sc.exe", "delete", SERVICE_NAME]),
        step(&[
            "netsh.exe",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={FIREWALL_RULE}"),
        ]),
    ]
}

/// Steps that may fail without stopping the install (removing what isn't there).
pub fn may_fail(s: &Step) -> bool {
    let a: Vec<&str> = s.iter().map(String::as_str).collect();
    matches!(
        a.as_slice(),
        ["sc.exe", "stop", ..] | ["sc.exe", "delete", ..] | ["netsh.exe", _, _, "delete", ..]
    )
}

/// Before the elevated setup trusts a data folder that is already there: everything in it must
/// belong to the administrators, SYSTEM or a service, and nothing in it may be a link (any
/// user can create a folder in `%ProgramData%` before Keep Hub is installed). A folder that
/// fails is renamed aside, never used or deleted, and the hub starts fresh. Answers what was
/// done, for the setup's log.
pub fn prepare_data(data: &Path, stamp: &str) -> Result<String, String> {
    if std::fs::symlink_metadata(data).is_err() {
        return Ok(format!("{} is new.", data.display()));
    }
    match crate::owner::protected_tree(data) {
        Ok(()) => Ok(format!("{} is the hub's own.", data.display())),
        Err(why) => {
            let mut name = data.as_os_str().to_owned();
            name.push(format!(" (set aside {stamp})"));
            let aside = PathBuf::from(name);
            std::fs::rename(data, &aside).map_err(|e| {
                format!(
                    "{} was not made by Keep Hub's setup ({why}) and can't be moved aside ({e}). Move or delete it, then run the setup again.",
                    data.display()
                )
            })?;
            Ok(format!(
                "{} was not made by Keep Hub's setup ({why}): it was moved to {} and is not used.",
                data.display(),
                aside.display()
            ))
        }
    }
}

/// The hub's data folder on Windows: `%ProgramData%\Keep Hub`, never given by the caller of
/// the elevated commands.
pub fn windows_data() -> Option<PathBuf> {
    std::env::var_os("ProgramData").map(|p| PathBuf::from(p).join(DATA_DIR))
}

/// Program Files on this computer (the 64-bit folder first).
pub fn program_files() -> Vec<PathBuf> {
    ["ProgramW6432", "ProgramFiles"]
        .iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .collect()
}

/// Whether `exe` is inside one of `roots` (Windows paths compare without regard to case).
/// The service runs the hub program from where it is installed: only Program Files is locked
/// against ordinary programs.
pub fn under(exe: &Path, roots: &[PathBuf]) -> bool {
    let lower = |p: &Path| -> Vec<String> {
        p.components()
            .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
            .collect()
    };
    let e = lower(exe);
    roots.iter().any(|r| {
        let r = lower(r);
        !r.is_empty() && e.len() > r.len() && e.get(..r.len()) == Some(&r[..])
    })
}

/// `keep-hub install-service`'s exit codes (the setup reads them; its own words say what
/// happened).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Done,
    /// The hub program isn't under Program Files (an ordinary program could have replaced it).
    NotInProgramFiles,
    /// A hub folder Keep Hub's setup didn't make is there and can't be moved aside.
    FolderInTheWay,
    /// The first setup found no home network.
    NoHomeNetwork,
    /// The hub couldn't be set up for another reason.
    SetupFailed,
    /// The service couldn't be registered or started.
    ServiceDidntStart,
    /// Called wrongly (`--data` given, or not Windows).
    BadArguments,
}

impl Exit {
    pub const ALL: [Exit; 7] = [
        Exit::Done,
        Exit::NotInProgramFiles,
        Exit::FolderInTheWay,
        Exit::NoHomeNetwork,
        Exit::SetupFailed,
        Exit::ServiceDidntStart,
        Exit::BadArguments,
    ];

    pub fn code(self) -> u8 {
        match self {
            Exit::Done => 0,
            Exit::NotInProgramFiles => 10,
            Exit::FolderInTheWay => 11,
            Exit::NoHomeNetwork => 12,
            Exit::SetupFailed => 13,
            Exit::ServiceDidntStart => 14,
            Exit::BadArguments => 15,
        }
    }

    pub fn from_code(code: i64) -> Option<Exit> {
        Exit::ALL.into_iter().find(|e| i64::from(e.code()) == code)
    }

    /// What the setup says.
    pub fn message(self, data: &Path) -> String {
        match self {
            Exit::Done => "Keep Hub is running on this computer.".into(),
            Exit::NotInProgramFiles => "Keep Hub has to be installed in Program Files (the service runs it from there, where ordinary programs can't change it). Install it with its setup.".into(),
            Exit::FolderInTheWay => format!("A folder named {} is there that Keep Hub's setup didn't make, and it can't be moved aside. Move or delete it, then run the setup again.", data.display()),
            Exit::NoHomeNetwork => "Keep Hub couldn't be set up: this computer isn't on a home network. Connect it to the home Wi-Fi or network, then run the setup again.".into(),
            Exit::SetupFailed => format!("Keep Hub couldn't be set up. {} may say more.", data.join(LOG_FILE).display()),
            Exit::ServiceDidntStart => format!("The Keep Hub service couldn't be started. {} may say more.", data.join(LOG_FILE).display()),
            Exit::BadArguments => "keep-hub install-service was called wrongly. Run Keep Hub's setup.".into(),
        }
    }
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// macOS: the launchd daemon's property list. It runs as `user` and restarts if it stops.
pub fn macos_plist(exe: &Path, data: &Path, user: &str) -> String {
    // a Mac path whatever system writes it (the tests also run on Windows)
    let log = format!(
        "{}/{LOG_FILE}",
        data.display().to_string().trim_end_matches('/')
    );
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string>
    <string>run</string>
    <string>--data</string>
    <string>{data}</string>
    <string>--log</string>
    <string>{log}</string>
  </array>
  <key>UserName</key><string>{user}</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
"#,
        label = LAUNCHD_LABEL,
        exe = xml(&exe.display().to_string()),
        data = xml(&data.display().to_string()),
        log = xml(&log),
        user = xml(user),
    )
}

/// Where the macOS daemon's property list goes.
pub fn macos_plist_path() -> String {
    format!("/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist")
}

/// Run the steps in order; a step that may fail is reported but doesn't stop the rest.
pub fn run_steps(steps: &[Step], echo: &dyn Fn(&str)) -> Result<(), String> {
    for s in steps {
        let Some((prog, args)) = s.split_first() else {
            continue;
        };
        echo(&format!("> {}", s.join(" ")));
        let out = std::process::Command::new(prog)
            .args(args)
            .output()
            .map_err(|e| format!("{prog} couldn't start: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !text.is_empty() {
            echo(&text);
        }
        if !out.status.success() && !may_fail(s) {
            return Err(format!(
                "{} failed: {}{}",
                s.join(" "),
                text,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
    }
    Ok(())
}

/// A log that appends to `path`, starting over at 1 MB (the old one is kept as `.1`).
pub fn file_log(path: PathBuf) -> crate::hub::Log {
    let lock = std::sync::Mutex::new(());
    std::sync::Arc::new(move |line: &str| {
        use std::io::Write;
        let _g = lock.lock();
        if std::fs::metadata(&path).is_ok_and(|m| m.len() > 1_000_000) {
            let mut old = path.as_os_str().to_owned();
            old.push(".1");
            let _ = std::fs::rename(&path, old);
        }
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let now = time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default();
            let _ = writeln!(f, "{now} {line}");
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_windows_install_uses_a_virtual_account_a_locked_folder_and_no_powershell() {
        let exe = PathBuf::from(r"C:\Program Files\Keep Hub\keep-hub.exe");
        let data = PathBuf::from(r"C:\ProgramData\Keep Hub");
        let steps = windows_install(&exe, &data);
        let flat: Vec<String> = steps.iter().map(|s| s.join(" ")).collect();
        assert!(steps
            .iter()
            .all(|s| !s[0].to_lowercase().contains("powershell")));
        let create = steps.iter().find(|s| s[1] == "create").unwrap();
        assert_eq!(create[3], "binPath=");
        // (the path is joined with "/" off Windows; the quoting is what matters)
        assert!(create[4]
            .starts_with(r#""C:\Program Files\Keep Hub\keep-hub.exe" service-run --data ""#));
        assert!(create.contains(&r"NT SERVICE\KeepHub".to_string()));
        assert!(!flat.iter().any(|s| s.contains("LocalSystem")));
        // owner first, then the permissions, then the users' two files, then start
        let pos = |needle: &str| flat.iter().position(|s| s.contains(needle)).unwrap();
        assert!(pos("/setowner") < pos("/reset"));
        assert!(pos("/reset") < pos("/inheritance:r"));
        assert!(pos("/inheritance:r") < pos("*S-1-5-32-545:(RX)"));
        // every permission step works on links themselves, never their targets
        assert!(steps
            .iter()
            .filter(|s| s[0] == "icacls.exe")
            .all(|s| s.contains(&"/L".to_string())));
        // the users read the admin token, and never anything passed down to keys/ or the
        // registry
        assert!(flat
            .iter()
            .any(|s| s.contains("admin.token") && s.contains("*S-1-5-32-545:(R)")));
        assert!(!flat
            .iter()
            .any(|s| s.contains("*S-1-5-32-545") && (s.contains("(OI)") || s.contains("(CI)"))));
        assert!(!flat
            .iter()
            .any(|s| (s.contains("keys") || s.contains("hub.sqlite")) && s.contains("545")));
        // the stage 5 rule: the hub program, any port, never Public
        let rule = &flat[pos("action=allow")];
        assert!(rule.contains("name=Keep Hub"), "{rule}");
        assert!(rule.contains("program=C:\\Program Files\\Keep Hub\\keep-hub.exe"));
        assert!(rule.contains("profile=private,domain"));
        assert!(!rule.contains("localport"));
        assert_eq!(flat.last().unwrap(), "sc.exe start KeepHub");
        assert!(may_fail(&steps[0]) && may_fail(&steps[1]));
        assert!(!may_fail(create));
        // removing: the service and the rule; the data stays
        let gone: Vec<String> = windows_uninstall().iter().map(|s| s.join(" ")).collect();
        assert!(gone.iter().any(|s| s == "sc.exe delete KeepHub"));
        assert!(gone.iter().any(|s| s.contains("delete rule name=Keep Hub")));
        assert!(!gone
            .iter()
            .any(|s| s.contains("ProgramData") || s.contains("rmdir")));
        assert!(windows_uninstall().iter().all(may_fail));
    }

    #[cfg(unix)]
    #[test]
    fn a_data_folder_with_a_link_in_it_is_set_aside() {
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("Keep Hub");
        assert!(prepare_data(&data, "x").unwrap().contains("is new"));
        std::fs::create_dir(&data).unwrap();
        std::fs::write(data.join("hub.json"), "{}").unwrap();
        assert!(prepare_data(&data, "x").unwrap().contains("own"));
        std::os::unix::fs::symlink("/etc", data.join("keys")).unwrap();
        let said = prepare_data(&data, "20261118").unwrap();
        assert!(said.contains("moved to"), "{said}");
        assert!(!data.exists());
        assert!(d
            .path()
            .join("Keep Hub (set aside 20261118)")
            .join("hub.json")
            .exists());
    }

    #[test]
    fn only_programs_inside_program_files_count() {
        let roots = [PathBuf::from("/Program Files")];
        assert!(under(
            Path::new("/program files/Keep Hub/keep-hub.exe"),
            &roots
        ));
        assert!(!under(Path::new("/Program Files"), &roots));
        assert!(!under(Path::new("/Program Files Evil/x.exe"), &roots));
        assert!(!under(Path::new("/Users/jerry/keep-hub.exe"), &roots));
        assert!(!under(Path::new("/x.exe"), &[]));
    }

    #[test]
    fn exit_codes_round_trip_and_say_something() {
        for e in Exit::ALL {
            assert_eq!(Exit::from_code(i64::from(e.code())), Some(e));
            assert!(!e.message(Path::new("C:/ProgramData/Keep Hub")).is_empty());
        }
        assert_eq!(Exit::from_code(1), None);
        assert_eq!(Exit::Done.code(), 0);
    }

    /// The Mac's install script writes launchd's file itself (so nothing of Keep Hub's runs as
    /// root): it must be the same file as [`macos_plist`].
    #[test]
    fn the_mac_install_script_writes_the_same_daemon_file() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../installer/macos");
        let script = std::fs::read_to_string(root.join("install-hub.command"))
            .unwrap()
            .replace("\r\n", "\n");
        let body = script
            .split_once("<<PLIST\n")
            .unwrap()
            .1
            .split_once("\nPLIST\n")
            .unwrap()
            .0;
        let exe = "/Applications/Keep Hub.app/Contents/MacOS/keep-hub";
        let data = "/Users/jerry/Library/Application Support/Keep Hub";
        let from_script = format!("{body}\n")
            .replace("$LABEL", LAUNCHD_LABEL)
            .replace("$HUB_X", exe)
            .replace("$DATA_X", data)
            .replace("$LOG_X", &format!("{data}/{LOG_FILE}"))
            .replace("$USER_X", "jerry");
        assert_eq!(
            from_script,
            macos_plist(Path::new(exe), Path::new(data), "jerry")
        );
        assert!(script.contains(&format!("LABEL=\"{LAUNCHD_LABEL}\"")));
        assert!(script.contains(&format!("Application Support/{DATA_DIR}\"")));
        // root only places the file and starts launchd: never Keep Hub's own program
        for line in script
            .lines()
            .filter(|l| l.trim_start().starts_with("sudo "))
        {
            assert!(!line.contains("$HUB"), "{line}");
        }
        let remove = std::fs::read_to_string(root.join("remove-hub.command")).unwrap();
        assert!(remove.contains(&format!("LABEL=\"{LAUNCHD_LABEL}\"")));
        for line in remove
            .lines()
            .filter(|l| l.trim_start().starts_with("sudo "))
        {
            assert!(!line.contains("$HUB"), "{line}");
        }
    }

    #[test]
    fn the_mac_daemon_runs_as_the_user_and_quotes_paths() {
        let p = macos_plist(
            Path::new("/Applications/Keep Hub.app/Contents/MacOS/keep-hub"),
            Path::new("/Users/jerry/Library/Application Support/Keep Hub"),
            "jerry",
        );
        assert!(p.contains("<key>UserName</key><string>jerry</string>"));
        assert!(p.contains("<string>/Users/jerry/Library/Application Support/Keep Hub</string>"));
        assert!(p.contains("Keep Hub/hub.log</string>"));
        assert!(!macos_plist(Path::new("/a&b"), Path::new("/d"), "u<").contains("a&b"));
        assert_eq!(
            macos_plist_path(),
            "/Library/LaunchDaemons/org.moneykeep.keep-hub.plist"
        );
    }

    #[test]
    fn the_log_starts_over_when_it_grows() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join(LOG_FILE);
        let log = file_log(path.clone());
        log("first");
        assert!(std::fs::read_to_string(&path).unwrap().contains("first"));
        std::fs::write(&path, vec![b'x'; 1_000_001]).unwrap();
        log("second");
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .ends_with("second\n"));
        assert!(d.path().join("hub.log.1").exists());
    }
}
