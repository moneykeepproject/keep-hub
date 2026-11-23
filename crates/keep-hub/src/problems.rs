//! "Find the problem": the hub runs the spec's checks in order, stopping at the first
//! failure, and gives the results to whichever app asks (the admin address). Each result
//! has a code, plain words and at most one action.
//!
//! | # | Check | Action offered |
//! |---|---|---|
//! | 1 | The hub service is running (it answers: the app asks, not the hub) | Start it |
//! | 2 | This computer has a private home address | Open network settings |
//! | 3 | The network is set to Private (Windows) | Open the Windows setting |
//! | 4 | The firewall rule exists, and no rule blocks the hub | Fix |
//! | 5 | The name service can be reached | Try again |
//! | 6 | Public DNS gives this computer's address for the name | Update the name |
//! | 7 | The home resolver gives the same answer | Use the other way to connect |
//! | 8 | The certificate has more than 14 days left | Renew now |
//! | 9 | Each app's backend answers on its loopback port | Start that app |
//! | 10 | The hub answers `/hub/check` on its own name and each app port | None: the phone questions |
//!
//! Checks 5 to 8 are skipped while names are off. A check that couldn't be made (for
//! example Windows Firewall can't be asked) says so and doesn't stop the run. Some words are from
//! MoneyKeep's Wi-Fi capture checks.
//!
//! The firewall rule (owner decision 2026-11-18) is one rule for the hub program, any port:
//! "every app port" is covered by it. The hub can't change the firewall itself (it runs
//! without administrator rights): Fix is `keep-hub fix-firewall`, which the app runs with
//! Windows' permission prompt.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::Serialize;
use serde_json::{json, Value};

use crate::dns::Kind;
use crate::hub::Hub;
use crate::machine::{self, RuleState};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Failed,
    Skipped,
    /// The check couldn't be made; the run goes on.
    Unknown,
}

/// One check's result.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Check {
    pub number: u8,
    pub code: &'static str,
    pub status: Status,
    pub words: String,
    /// What the app can offer: `{"kind", "label", ...}`.
    pub action: Option<Value>,
}

fn ok(number: u8, code: &'static str, words: impl Into<String>) -> Check {
    Check {
        number,
        code,
        status: Status::Ok,
        words: words.into(),
        action: None,
    }
}

fn failed(
    number: u8,
    code: &'static str,
    words: impl Into<String>,
    action: Option<Value>,
) -> Check {
    Check {
        number,
        code,
        status: Status::Failed,
        words: words.into(),
        action,
    }
}

fn other(number: u8, code: &'static str, status: Status, words: impl Into<String>) -> Check {
    Check {
        number,
        code,
        status,
        words: words.into(),
        action: None,
    }
}

/// The system's network settings page.
fn network_settings() -> &'static str {
    if cfg!(target_os = "macos") {
        "x-apple.systempreferences:com.apple.Network-Settings.extension"
    } else {
        "ms-settings:network-status"
    }
}

/// One check (some give no result when an earlier one already says why).
type Step = fn(&Arc<Hub>) -> Vec<Check>;

/// 1: asked by the app (it got an answer from the admin address).
fn hub_running(_: &Arc<Hub>) -> Vec<Check> {
    vec![ok(1, "hub_running", "The hub is running.")]
}

/// Run every check in order, stopping at the first failure.
pub(crate) fn run(hub: &Arc<Hub>) -> Value {
    let mut results: Vec<Check> = Vec::new();
    let checks: [Step; 10] = [
        hub_running,
        home_address,
        network_private,
        firewall,
        name_service,
        public_dns,
        home_dns,
        certificate,
        apps,
        self_check,
    ];
    let mut stopped_at = None;
    for c in checks {
        let found = c(hub);
        let stop = found
            .iter()
            .find(|r| r.status == Status::Failed)
            .map(|r| r.number);
        results.extend(found);
        if stop.is_some() {
            stopped_at = stop;
            break;
        }
    }
    json!({ "checks": results, "stopped_at": stopped_at, "at": hub.now() })
}

fn home_address(hub: &Arc<Hub>) -> Vec<Check> {
    vec![match hub.address() {
        Some(ip) => ok(2, "home_address", format!("This computer's home address is {ip}.")),
        None => failed(
            2,
            "no_home_address",
            "This computer isn't on a home network: it has no home or office address. Connect it to the home Wi-Fi or network.",
            Some(json!({ "kind": "open", "label": "Open network settings", "target": network_settings() })),
        ),
    }]
}

fn network_private(hub: &Arc<Hub>) -> Vec<Check> {
    let Some(ip) = hub.address() else {
        return Vec::new();
    };
    // (Revision 4 D: Linux has no network type to set)
    if hub.machine.os() == machine::Os::Linux {
        return vec![ok(3, "network_private", "Not needed on this system.")];
    }
    let here = hub
        .machine
        .addresses()
        .into_iter()
        .find(|a| a.address == ip.to_string());
    vec![match here {
        Some(a) if a.profile.eq_ignore_ascii_case("public") => failed(
            3,
            "network_public",
            "Windows treats this network as public, so phones can't connect over Wi-Fi. Change it in Windows' network settings: this network > Network profile type > Private network. Keep Hub doesn't change it itself.",
            Some(json!({ "kind": "open", "label": "Open the Windows setting", "target": "ms-settings:network-status" })),
        ),
        _ => ok(3, "network_private", "The network isn't set to Public."),
    }]
}

/// The ports phones need: every registered app's and the certificate page's.
pub(crate) fn needed_ports(hub: &Arc<Hub>) -> Vec<u16> {
    let mut ports: Vec<u16> = hub
        .lock()
        .registry
        .apps()
        .unwrap_or_default()
        .iter()
        .map(|a| a.public_port)
        .collect();
    ports.push(hub.helper_port());
    ports
}

/// Check 4 on Linux (Revision 4 D): an allow rule for every port in the firewall that is on.
/// The hub can't change ufw or firewalld, so the action is ServicesKeep's Fix.
fn linux_firewall(hub: &Arc<Hub>, fw: &crate::linuxfw::LinuxFirewall) -> Vec<Check> {
    let Some(active) = fw.active else {
        return vec![ok(4, "firewall", "No firewall is on.")];
    };
    let closed = fw.closed(&needed_ports(hub));
    if closed.is_empty() {
        return vec![ok(
            4,
            "firewall",
            format!(
                "The firewall ({}) lets phones reach the hub.",
                active.name()
            ),
        )];
    }
    let list: Vec<String> = closed.iter().map(u16::to_string).collect();
    vec![failed(
        4,
        "firewall_ports_closed",
        format!(
            "Phones can't reach this computer: the firewall ({}) doesn't let in port {}. Fix it in ServicesKeep.",
            active.name(),
            list.join(", ")
        ),
        Some(json!({
            "kind": "serviceskeep",
            "label": "Fix in ServicesKeep",
            "ports": closed,
            "firewall": active.name(),
        })),
    )]
}

fn firewall(hub: &Arc<Hub>) -> Vec<Check> {
    let scan = match hub.machine.firewall_scan() {
        Ok(s) => s,
        Err(e) => {
            return vec![other(
                4,
                "firewall_unknown",
                Status::Unknown,
                format!("The firewall couldn't be checked: {e}"),
            )]
        }
    };
    if let Some(fw) = scan.as_ref().and_then(|s| s.linux.as_ref()) {
        return linux_firewall(hub, fw);
    }
    let check = machine::firewall_check(scan);
    if check.ok() {
        let words = if check.managed {
            "The firewall lets phones reach the hub."
        } else {
            "This system's firewall isn't one Keep Hub manages. If it's on, allow keep-hub to accept incoming connections."
        };
        return vec![ok(4, "firewall", words)];
    }
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "keep-hub".into());
    // (Revision 4 C's admin request can't do this on Windows: the owner decided on
    // 2026-11-22 that Windows' permission prompt is needed, so the command is the Fix)
    let fix = json!({
        "kind": "fix",
        "label": "Fix",
        "command": [exe, "fix-firewall"],
        "permission": "Windows will ask for permission, because the firewall is set for all users.",
    });
    let (code, words) = if !check.block_rules.is_empty() {
        (
            "firewall_blocked",
            "Windows is blocking the hub. Windows made a rule that blocks keep-hub.exe (this happens when its \"allow access\" pop-up is closed). Fix turns that rule off.",
        )
    } else if check.rule == RuleState::Disabled {
        (
            "firewall_rule_off",
            "Phones can't reach this computer: the firewall rule is turned off.",
        )
    } else {
        (
            "firewall_rule_missing",
            "Phones can't reach this computer: the firewall rule is missing.",
        )
    };
    vec![failed(4, code, words, Some(fix))]
}

/// Each check's one action, in words (for a Fix asked of a check that has none).
fn action_words(number: u8) -> Option<&'static str> {
    Some(match number {
        1 => "Start it",
        2 => "Open network settings",
        3 => "Open the Windows setting",
        4 => "Fix",
        5 => "Try again",
        6 => "Update the name",
        7 => "Use the other way to connect",
        8 => "Renew now",
        9 => "Start that app",
        10 => "None: go to the phone questions",
        _ => return None,
    })
}

/// `POST /admin/v1/problems/fix {check}` (Revision 4 C). Only check 4 has a Fix, and the
/// service can't do it on any system the hub manages a firewall on (owner decisions
/// 2026-11-22): on Windows it needs Windows' permission prompt, which the app's
/// `keep-hub fix-firewall` shows; on Linux it is ServicesKeep's. The answer says which, in
/// words. Where the hub manages no firewall (a Mac) there is nothing to fix and it answers
/// check 4's result.
pub(crate) fn fix(hub: &Arc<Hub>, check: u8) -> Result<Value, crate::hub::Refusal> {
    use crate::hub::Refusal;
    let Some(action) = action_words(check) else {
        return Err(Refusal::new(
            400,
            "bad_request",
            "There is no check with that number: the checks are 1 to 10.",
        ));
    };
    if check != 4 {
        return Err(Refusal::new(
            400,
            "no_fix",
            format!("Only check 4 (the firewall) has a Fix. Check {check}'s action is: {action}."),
        ));
    }
    match hub.machine.os() {
        // (owner decision 2026-11-22: the service can't change the Windows firewall, which
        // asks an administrator's permission: the app runs `keep-hub fix-firewall` with
        // Windows' prompt, as check 4's action says)
        machine::Os::Windows => Err(Refusal::new(
            409,
            "permission_needed",
            "Changing the Windows firewall needs an administrator's permission, which Keep Hub's service can't ask for. Use Fix in the app: it runs keep-hub fix-firewall with Windows' permission prompt.",
        )),
        // (owner decision 2026-11-22: the service has no right to change ufw or firewalld;
        // the package opens the certificate page's port at install, ServicesKeep the rest)
        machine::Os::Linux => Err(Refusal::new(
            409,
            "fix_in_serviceskeep",
            "On Linux, Keep Hub can't change the firewall itself. Run Fix from ServicesKeep.",
        )),
        // a firewall Keep Hub doesn't manage: nothing to do, and check 4 says so
        machine::Os::Mac => Ok(json!({ "check": firewall(hub).first(), "done": [] })),
    }
}

/// Checks 5 to 8 apply only with names on.
fn names_on(hub: &Arc<Hub>) -> bool {
    hub.names.settings().0.enabled
}

fn skipped(number: u8, code: &'static str) -> Vec<Check> {
    vec![other(number, code, Status::Skipped, "Names are off.")]
}

fn name_service(hub: &Arc<Hub>) -> Vec<Check> {
    if !names_on(hub) {
        return skipped(5, "name_service");
    }
    // Any HTTP answer means it can be reached (the service has no route for asking only
    // that, so the hub asks for its base address).
    let service = hub.names.settings().0.service;
    let answer = hub.names.outside().http.send("GET", &service, &[], None);
    vec![match answer {
        Ok(_) => ok(5, "name_service", "The name service can be reached."),
        Err(e) => failed(
            5,
            "name_service_unreachable",
            format!("The name service can't be reached: {e}"),
            Some(json!({ "kind": "retry", "label": "Try again" })),
        ),
    }]
}

fn public_dns(hub: &Arc<Hub>) -> Vec<Check> {
    if !names_on(hub) {
        return skipped(6, "public_dns");
    }
    let (Some(name), Some(ip)) = (hub.names.name(), hub.address()) else {
        return vec![other(
            6,
            "public_dns",
            Status::Unknown,
            "The hub has no name yet.",
        )];
    };
    let update = json!({ "kind": "admin", "label": "Update the name", "method": "POST", "path": "/admin/v1/names/address" });
    vec![match hub.names.outside().lookup.public(&name, Kind::A) {
        Ok(found) if found.contains(&ip.to_string()) => ok(
            6,
            "public_dns",
            format!("Public DNS gives {ip} for {name}."),
        ),
        Ok(found) => failed(
            6,
            "public_dns_wrong",
            format!(
                "Public DNS gives {} for {name}, not this computer's {ip}.",
                if found.is_empty() {
                    "nothing".to_string()
                } else {
                    found.join(", ")
                }
            ),
            Some(update),
        ),
        Err(e) => other(
            6,
            "public_dns",
            Status::Unknown,
            format!("Public DNS couldn't be asked: {e}"),
        ),
    }]
}

fn home_dns(hub: &Arc<Hub>) -> Vec<Check> {
    if !names_on(hub) {
        return skipped(7, "home_dns");
    }
    let (Some(name), Some(ip)) = (hub.names.name(), hub.address()) else {
        return vec![other(
            7,
            "home_dns",
            Status::Unknown,
            "The hub has no name yet.",
        )];
    };
    let home = hub.names.outside().lookup.home(&name).unwrap_or_default();
    vec![if home.contains(&ip) {
        ok(7, "home_dns", "This home's router gives the same address.")
    } else {
        failed(
            7,
            "home_dns_blocked",
            "This home's router refuses the hub's name. Allow the name in the router, or connect phones the other way (the hub's own certificate).",
            Some(json!({
                "kind": "fallback",
                "label": "Use the other way to connect",
                "target": format!("http://{ip}:{}/", hub.helper_port()),
            })),
        )
    }]
}

fn certificate(hub: &Arc<Hub>) -> Vec<Check> {
    if !names_on(hub) {
        return skipped(8, "certificate");
    }
    let warn = i64::from(hub.names.settings().1) * 86_400;
    let renew = json!({ "kind": "admin", "label": "Renew now", "method": "POST", "path": "/admin/v1/names/renew" });
    vec![match hub.names.certificate() {
        Some(c) if c.info.not_after - hub.now() / 1000 > warn => ok(
            8,
            "certificate",
            "The name's certificate has more than 14 days left.",
        ),
        Some(_) => failed(
            8,
            "certificate_ending",
            "The name's certificate ends within 14 days and hasn't been renewed.",
            Some(renew),
        ),
        None => failed(
            8,
            "certificate_missing",
            "The hub has no certificate for its name yet.",
            Some(renew),
        ),
    }]
}

fn apps(hub: &Arc<Hub>) -> Vec<Check> {
    let apps = hub.lock().registry.apps().unwrap_or_default();
    for a in &apps {
        let at = SocketAddr::from((Ipv4Addr::LOCALHOST, a.loopback_port));
        if TcpStream::connect_timeout(&at, Duration::from_millis(500)).is_err() {
            return vec![failed(
                9,
                "app_stopped",
                format!("{} isn't running on this computer.", a.title),
                Some(json!({ "kind": "start_app", "label": "Start that app", "app": a.id })),
            )];
        }
    }
    vec![ok(9, "apps", "Every app's own part is running.")]
}

fn self_check(hub: &Arc<Hub>) -> Vec<Check> {
    let Some(ip) = hub.address() else {
        return Vec::new();
    };
    let own = std::fs::read_to_string(hub.data.join(crate::ca::SERVER_CERT_FILE))
        .ok()
        .and_then(|t| crate::ca::from_pem(&t))
        .unwrap_or_default();
    let named = hub.names.serving();
    let apps = hub.lock().registry.apps().unwrap_or_default();
    for a in &apps {
        let Some(at) = hub.port_of(&a.id) else {
            return vec![failed(
                10,
                "port_closed",
                format!(
                    "The hub couldn't open port {} for {}.",
                    a.public_port, a.title
                ),
                None,
            )];
        };
        let at = SocketAddr::from((ip, at.port()));
        if let Err(e) = hub_check(at, None, &own) {
            return vec![failed(
                10,
                "no_answer_by_address",
                format!("The hub doesn't answer for {} at {at}: {e}", a.title),
                None,
            )];
        }
        if let Some(n) = &named {
            if let Err(e) = hub_check(
                at,
                Some(&n.name),
                n.chain.first().map(Vec::as_slice).unwrap_or(&[]),
            ) {
                return vec![failed(
                    10,
                    "no_answer_by_name",
                    format!("The hub doesn't answer for {} by its name: {e}", a.title),
                    None,
                )];
            }
        }
    }
    vec![ok(
        10,
        "hub_answers",
        "Everything on this computer works. If a phone still can't connect, go through the phone questions.",
    )]
}

/// Trusts exactly one certificate: the one the hub is meant to answer with. (This is a
/// reachability check of the hub itself, not a trust decision for anyone else.)
#[derive(Debug)]
struct Pinned {
    leaf: Vec<u8>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.leaf.as_slice() && !self.leaf.is_empty() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "another certificate answered".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// `GET /hub/check` at `at`, asking for `name` (or by address), expecting `leaf`.
fn hub_check(at: SocketAddr, name: Option<&str>, leaf: &[u8]) -> Result<(), String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous() // (Pinned: exactly the hub's own certificate)
        .with_custom_certificate_verifier(Arc::new(Pinned {
            leaf: leaf.to_vec(),
            provider,
        }))
        .with_no_client_auth();
    let server = match name {
        Some(n) => ServerName::try_from(n.to_string()).map_err(|e| e.to_string())?,
        None => ServerName::from(at.ip()),
    };
    let mut conn =
        rustls::ClientConnection::new(Arc::new(config), server).map_err(|e| e.to_string())?;
    let mut tcp =
        TcpStream::connect_timeout(&at, Duration::from_secs(3)).map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
    let host = name.map(str::to_string).unwrap_or_else(|| at.to_string());
    tls.write_all(
        format!("GET /hub/check HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .map_err(|e| e.to_string())?;
    let mut answer = Vec::new();
    let _ = tls.read_to_end(&mut answer);
    if answer.starts_with(b"HTTP/1.1 200 ") {
        Ok(())
    } else {
        Err("no answer to /hub/check".into())
    }
}
