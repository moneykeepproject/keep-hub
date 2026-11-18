//! `keep-hub`: the shared hub.
//!
//! ```text
//! keep-hub setup   --data <folder> --address <hub IPv4>
//! keep-hub run     --data <folder>
//! keep-hub status  --data <folder>
//! ```
//!
//! Users never run this by hand: the hub is its own release package, which keep-launcher
//! installs and runs as a service (stage 7). The commands are for the hub's setup, support
//! and tests.

use keep_hub::{ca, HubConfig, HubOptions, KeyStore};
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
    if !["setup", "run", "status"].contains(&cmd) {
        return Err(
            "usage: keep-hub <setup|run|status> --data <folder> [--address <hub IPv4>]".into(),
        );
    }
    let data = arg(&args, "--data")
        .map(PathBuf::from)
        .ok_or("--data <folder> is needed")?;
    match cmd {
        "setup" => {
            let address = arg(&args, "--address").ok_or("--address <hub IPv4> is needed")?;
            let ip = ca::check_address(&address)?;
            if !ca::address_present(ip) {
                return Err(format!("This computer doesn't have the address {ip}."));
            }
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
            eprintln!("Keep Hub running: this computer http://{}", running.admin);
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
