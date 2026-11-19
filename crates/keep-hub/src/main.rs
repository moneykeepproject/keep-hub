//! `keep-hub`: the shared hub.
//!
//! ```text
//! keep-hub setup         --data <folder> [--address <home IPv4> | --address auto]
//! keep-hub run           --data <folder>
//! keep-hub status        --data <folder>
//! keep-hub addresses                         this computer's home addresses and adapters
//! keep-hub fix-firewall                      put the firewall rule back (administrator)
//! ```
//!
//! Users never run this by hand: the hub is its own release package, which keep-launcher
//! installs and runs as a service (stage 7). `fix-firewall` is run by an app's desktop
//! program, with Windows' permission prompt, when Find the problem offers Fix. The commands
//! are for the hub's setup, the apps, support and tests.

use keep_hub::{ca, machine, HubConfig, HubOptions, KeyStore};
use std::path::PathBuf;
use std::process::ExitCode;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
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
        "setup" | "run" | "status" => {}
        _ => {
            return Err(
                "usage: keep-hub <setup|run|status|addresses|fix-firewall> [--data <folder>] [--address <home IPv4>|auto]"
                    .into(),
            )
        }
    }
    let data = arg(&args, "--data")
        .map(PathBuf::from)
        .ok_or("--data <folder> is needed")?;
    match cmd {
        "setup" => {
            let ip = match arg(&args, "--address").as_deref() {
                None | Some("auto") => machine::default_route_address().ok_or(
                    "This computer isn't on a home network: it has no home or office address.",
                )?,
                Some(a) => {
                    let ip = ca::check_address(a)?;
                    if !ca::address_present(ip) {
                        return Err(format!("This computer doesn't have the address {ip}."));
                    }
                    ip
                }
            };
            let info = keep_hub::setup(
                &data,
                &HubConfig::new(ip),
                &KeyStore::files(data.clone()),
                &ca::computer_name(),
                keep_hub::util::now_ms(),
            )?;
            println!("Keep Hub is set up for {}.", info.address);
            Ok(())
        }
        "run" => {
            let running = keep_hub::start(HubOptions::new(data))?;
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

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("keep-hub: {e}");
            ExitCode::FAILURE
        }
    }
}
