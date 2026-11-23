//! `keep-hub`: the shared hub.
//!
//! ```text
//! keep-hub setup            --data <folder> [--address <home IPv4> | --address auto]
//! keep-hub run              --data <folder> [--log <file>]
//! keep-hub status           --data <folder>
//! keep-hub registered-apps  --data <folder>     the apps that use the hub, for removing it
//! keep-hub addresses                            this computer's home addresses and adapters
//! keep-hub fix-firewall                         put the firewall rule back (administrator)
//! keep-hub install-service                      Windows, elevated: the setup's one step
//!                                               (the folder is always %ProgramData%\Keep Hub;
//!                                               exit codes in keep_hub::service::Exit).
//!                                               Linux, as root (the .deb's postinst): the
//!                                               user, the sealing key, the service
//! keep-hub remove-service                       Windows, elevated: the service and the
//!                                               firewall rule go; the data folder stays.
//!                                               Linux, as root: the service is disabled
//! keep-hub service-run      --data <folder>     the Windows service itself; on Linux what
//!                                               keep-hub.service runs (setup the first time)
//! keep-hub reset-administrator --name <name> [--data <folder>]
//!                                               a new password for a named administrator,
//!                                               read from the standard input (one line);
//!                                               needs the computer's administrator rights,
//!                                               as the data folder does (on Windows the
//!                                               folder is %ProgramData%\Keep Hub by default)
//! ```
//!
//! Users never run this by hand: the hub is its own release package, which keep-launcher
//! installs and runs as a service. `fix-firewall` is run by an app's desktop program, with
//! Windows' permission prompt, when Find the problem offers Fix. The commands are for the
//! setup, the apps, support and tests.

use keep_hub::registry::Registry;
use keep_hub::service::{self, Exit};
use keep_hub::{ca, machine, HubConfig, HubOptions, KeyStore};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn echo(line: &str) {
    println!("{line}");
}

/// On a Mac, Keep Hub's own program never runs as root: the disk image's two scripts place and
/// remove launchd's file themselves.
const MAC_INSTALL: &str = "On a Mac, open \"Install Keep Hub\" (or \"Remove Keep Hub\") from the Keep Hub disk image: they register the hub with launchd without running Keep Hub as root.";

/// The password on the line read from the standard input: without the line ending, and without
/// the byte-order mark Windows PowerShell puts in front of what it pipes to a program when its
/// output encoding is UTF-8 (no one types U+FEFF, and a password kept with it could never be
/// typed at sign-in).
fn typed_password(line: &str) -> &str {
    line.trim_start_matches('\u{feff}')
        .trim_end_matches(['\r', '\n'])
}

/// `reset-administrator`: when no administrator can sign in. The new password comes on the
/// standard input, so it is never in the command line (which other programs can see).
fn reset_administrator(args: &[String]) -> Result<(), String> {
    let name = arg(args, "--name").ok_or("--name <administrator> is needed")?;
    let data = match arg(args, "--data") {
        Some(d) => PathBuf::from(d),
        None if cfg!(windows) => service::windows_data().ok_or("%ProgramData% isn't set")?,
        None if cfg!(target_os = "linux") => PathBuf::from(service::LINUX_DATA),
        None => return Err("--data <folder> is needed".into()),
    };
    if !data.join(keep_hub::registry::REGISTRY_FILE).exists() {
        return Err(format!(
            "There are no hub records in {} (or this account can't read them: run this as an administrator of the computer).",
            data.display()
        ));
    }
    eprintln!("Type the new password for {name} and press Enter (at least 8 characters):");
    let mut line = zeroize::Zeroizing::new(String::new());
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("the password couldn't be read: {e}"))?;
    let id = keep_hub::reset_administrator(&data, &name, typed_password(&line))?;
    println!("Administrator {name} (member {id}) has a new password. Phones, members and grants are unchanged.");
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("");
    match cmd {
        "addresses" => {
            let list = machine::Machine::addresses(&machine::System);
            println!(
                "{}",
                serde_json::json!({
                    "default_route": machine::default_route_address(),
                    "addresses": list,
                })
            );
            return Ok(());
        }
        "fix-firewall" => {
            let exe = std::env::current_exe()
                .map_err(|e| format!("the hub program's path can't be found: {e}"))?;
            for line in machine::fix_firewall(&machine::System, &exe)? {
                println!("{line}");
            }
            return Ok(());
        }
        "install-service" if cfg!(target_os = "linux") => {
            let exit = match linux_install_service(&args) {
                Ok(()) => Exit::Done,
                Err((exit, e)) => {
                    eprintln!("{e}");
                    exit
                }
            };
            std::process::exit(i32::from(exit.code()));
        }
        "install-service" => {
            let exit = install_service(&args);
            if exit != Exit::Done {
                let data = service::windows_data().unwrap_or_default();
                eprintln!("{}", exit.message(&data));
            }
            std::process::exit(i32::from(exit.code()));
        }
        "remove-service" => return remove_service(),
        "reset-administrator" => return reset_administrator(&args),
        "setup" | "run" | "status" | "registered-apps" | "service-run" => {}
        _ => {
            return Err(
                "usage: keep-hub <setup|run|status|registered-apps|addresses|fix-firewall|install-service|remove-service|service-run|reset-administrator> [--data <folder>] [--address <home IPv4>|auto] [--name <administrator>]"
                    .into(),
            )
        }
    }
    let data = arg(&args, "--data")
        .map(PathBuf::from)
        .ok_or("--data <folder> is needed")?;
    match cmd {
        "setup" => {
            let info = setup(&data, arg(&args, "--address").as_deref()).map_err(|(_, e)| e)?;
            println!("Keep Hub is set up for {}.", info.address);
            Ok(())
        }
        "run" => {
            let mut opts = HubOptions::new(data);
            if let Some(log) = arg(&args, "--log") {
                opts.log = service::file_log(PathBuf::from(log));
            }
            let running = keep_hub::start(opts)?;
            let page = running
                .helper()
                .map(|a| format!("http://{a}"))
                .unwrap_or_else(|| "(not on a home network)".into());
            eprintln!(
                "Keep Hub running: this computer http://{}  certificate page {page}",
                running.admin
            );
            running.wait();
            Ok(())
        }
        "registered-apps" => {
            // the names only, on one line, for the uninstaller's question (it reads stdout)
            let apps = Registry::read_apps(&data)?;
            let titles: Vec<String> = apps.into_iter().map(|a| a.title).collect();
            if !titles.is_empty() {
                println!("{}", titles.join(", "));
            }
            Ok(())
        }
        "service-run" => service_run(data),
        _ => {
            let cfg = HubConfig::load(&data)?;
            let info = ca::read_info(&data).unwrap_or_default();
            println!(
                "{}",
                serde_json::json!({ "config": cfg, "certificate": info })
            );
            Ok(())
        }
    }
}

/// `setup`: the hub's certificates, settings and admin token in `data`. The error says
/// whether it was the network.
fn setup(data: &Path, address: Option<&str>) -> Result<ca::Info, (bool, String)> {
    let ip = match address {
        None | Some("auto") => machine::default_route_address().ok_or((
            true,
            "This computer isn't on a home network: it has no home or office address.".to_string(),
        ))?,
        Some(a) => {
            let ip = ca::check_address(a).map_err(|e| (false, e))?;
            if !ca::address_present(ip) {
                return Err((
                    true,
                    format!("This computer doesn't have the address {ip}."),
                ));
            }
            ip
        }
    };
    keep_hub::setup(
        data,
        &HubConfig::new(ip),
        &KeyStore::files(data.to_path_buf()),
        &ca::computer_name(),
        keep_hub::util::now_ms(),
    )
    .map_err(|e| (false, e))
}

/// `install-service`: everything the setup does on the computer, in one elevated program
/// (copied from ShareKeep's make-hub): a folder that isn't the hub's own moved aside, `setup`
/// the first time only (an existing hub keeps its name, certificate and pairings), then the
/// service, the folder's permissions and the firewall rule. The folder is never the caller's.
fn install_service(args: &[String]) -> Exit {
    if !cfg!(windows) || arg(args, "--data").is_some() {
        return Exit::BadArguments;
    }
    let Ok(exe) = std::env::current_exe() else {
        return Exit::BadArguments;
    };
    if !service::under(&exe, &service::program_files()) {
        return Exit::NotInProgramFiles;
    }
    let Some(data) = service::windows_data() else {
        return Exit::BadArguments;
    };
    let now = time::OffsetDateTime::now_utc();
    let stamp = format!("{} {}", now.date(), now.unix_timestamp());
    match service::prepare_data(&data, &stamp) {
        Ok(said) => println!("{said}"),
        Err(e) => {
            eprintln!("{e}");
            return Exit::FolderInTheWay;
        }
    }
    if !data.join(keep_hub::config::CONFIG_FILE).exists() {
        match setup(&data, None) {
            Ok(info) => println!("Keep Hub is set up for {}.", info.address),
            Err((network, e)) => {
                eprintln!("{e}");
                return if network {
                    Exit::NoHomeNetwork
                } else {
                    Exit::SetupFailed
                };
            }
        }
    }
    if let Err(e) = service::run_steps(&service::windows_install(&exe, &data), &echo) {
        eprintln!("{e}");
        return Exit::ServiceDidntStart;
    }
    Exit::Done
}

fn remove_service() -> Result<(), String> {
    if cfg!(windows) {
        service::run_steps(&service::windows_uninstall(), &echo)
    } else if cfg!(target_os = "linux") {
        service::run_steps(&service::linux_uninstall(), &echo)
    } else if cfg!(target_os = "macos") {
        Err(MAC_INSTALL.into())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
mod winsvc {
    //! The Windows service (copied from ShareKeep's hub, `main.rs`).
    use keep_hub::{service, HubOptions};
    use std::path::PathBuf;
    use std::sync::{mpsc, OnceLock};
    use std::time::Duration;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    pub static DATA: OnceLock<PathBuf> = OnceLock::new();

    define_windows_service!(ffi_service_main, service_main);

    fn status(state: ServiceState, code: u32) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::ServiceSpecific(code),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        }
    }

    fn service_main(_arguments: Vec<std::ffi::OsString>) {
        let Some(data) = DATA.get().cloned() else {
            return;
        };
        let log = service::file_log(data.join(service::LOG_FILE));
        let (tx, rx) = mpsc::channel();
        let handler = move |c: ServiceControl| match c {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let Ok(handle) = service_control_handler::register(service::SERVICE_NAME, handler) else {
            log("the service control handler couldn't be registered");
            return;
        };
        let mut opts = HubOptions::new(data);
        opts.log = log.clone();
        match keep_hub::start(opts) {
            Ok(running) => {
                log(&format!("started: this computer http://{}", running.admin));
                let _ = handle.set_service_status(status(ServiceState::Running, 0));
                let _ = rx.recv();
                running.stop();
                log("stopped");
                let _ = handle.set_service_status(status(ServiceState::Stopped, 0));
            }
            Err(e) => {
                log(&format!("couldn't start: {e}"));
                let _ = handle.set_service_status(status(ServiceState::Stopped, 1));
            }
        }
    }

    pub fn run(data: PathBuf) -> Result<(), String> {
        let _ = DATA.set(data);
        service_dispatcher::start(service::SERVICE_NAME, ffi_service_main)
            .map_err(|e| format!("not started by Windows' service manager ({e})"))
    }
}

#[cfg(windows)]
fn service_run(data: PathBuf) -> Result<(), String> {
    winsvc::run(data)
}

/// `install-service` on Linux (Revision 4 D), as root from the package's `postinst`: the
/// sealing key, the user and group, the installing person in the group, the certificate
/// page's port in the firewall, and the service enabled and started. The data folder is the
/// service's own (`StateDirectory`): the service sets itself up at its first start.
/// The exit codes are Windows' ([`Exit`]), so keep-launcher reads both alike.
#[cfg(unix)]
fn linux_install_service(args: &[String]) -> Result<(), (Exit, String)> {
    let failed = |e: String| (Exit::SetupFailed, e);
    if arg(args, "--data").is_some() {
        return Err((
            Exit::BadArguments,
            format!(
                "install-service takes no --data: the folder is always {}.",
                service::LINUX_DATA
            ),
        ));
    }
    if !service::is_root() {
        return Err((
            Exit::BadArguments,
            "install-service must run as root (the package's installer runs it).".into(),
        ));
    }
    for f in [service::LINUX_UNIT_FILE, service::LINUX_SYSUSERS_FILE] {
        if !Path::new(f).is_file() {
            return Err(failed(format!(
                "{f} is missing: install Keep Hub from its .deb package."
            )));
        }
    }
    if service::make_credential(&echo).map_err(failed)? {
        let dropin = Path::new(service::SEALING_DROPIN);
        if let Some(dir) = dropin.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| failed(format!("{} can't be made: {e}", dir.display())))?;
        }
        std::fs::write(dropin, service::sealing_dropin())
            .map_err(|e| failed(format!("{} can't be written: {e}", dropin.display())))?;
    }
    let person = service::installing_person(|k| std::env::var(k).ok());
    let helper = HubConfig::load(Path::new(service::LINUX_DATA))
        .map(|c| c.ports.helper)
        .unwrap_or(keep_hub::config::HELPER_PORT);
    service::run_steps(
        &service::linux_install(person.as_deref(), service::install_firewall(), helper),
        &echo,
    )
    .map_err(|e| (Exit::ServiceDidntStart, e))?;
    if let Some(p) = person {
        echo(&format!(
            "{p} can use Keep Hub from the apps after signing in to this computer again."
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn linux_install_service(_args: &[String]) -> Result<(), (Exit, String)> {
    Err((
        Exit::BadArguments,
        "install-service for Linux runs on Linux only.".into(),
    ))
}

/// `service-run` on Linux: what keep-hub.service runs, as the keep-hub user. The master key
/// from systemd (when it gave one) seals the keys; the first start sets the hub up; the
/// admin token is shared with the keep-hub group.
#[cfg(unix)]
fn service_run(data: PathBuf) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("service-run is for Windows and Linux; on a Mac use `run`.".into());
    }
    // (systemd gives every service an invocation id: by hand, this would set a hub up)
    if std::env::var_os("INVOCATION_ID").is_none() {
        return Err(
            "service-run is what keep-hub.service runs; to run the hub by hand, use `run`.".into(),
        );
    }
    let log = service::file_log(data.join(service::LOG_FILE));
    if let Some(key) = service::credential(std::env::var_os("CREDENTIALS_DIRECTORY")) {
        keep_hub::seal::set_master(&key)?;
    }
    let words = keep_hub::seal::protection()["words"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    log(&words);
    if !data.join(keep_hub::config::CONFIG_FILE).exists() {
        match setup(&data, None) {
            Ok(info) => log(&format!("set up for {}", info.address)),
            Err((_, e)) => {
                // (systemd starts it again in 30 seconds: a home network may come)
                log(&format!("couldn't set up: {e}"));
                return Err(e);
            }
        }
    }
    if let Err(e) = service::share_admin_token(&data) {
        log(&e);
    }
    let mut opts = HubOptions::new(data);
    opts.log = log.clone();
    let running = keep_hub::start(opts).inspect_err(|e| log(&format!("couldn't start: {e}")))?;
    log(&format!("started: this computer http://{}", running.admin));
    running.wait();
    Ok(())
}

#[cfg(not(any(windows, unix)))]
fn service_run(_data: PathBuf) -> Result<(), String> {
    Err("service-run is for Windows and Linux; elsewhere use `run`.".into())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("keep-hub: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::typed_password;

    #[test]
    fn a_piped_password_loses_its_line_ending_and_a_byte_order_mark() {
        assert_eq!(
            typed_password("ci-reset-password-2\r\n"),
            "ci-reset-password-2"
        );
        assert_eq!(
            typed_password("\u{feff}ci-reset-password-2\r\n"),
            "ci-reset-password-2"
        );
        assert_eq!(typed_password("pass word \n"), "pass word ");
    }
}
