//! What the hub asks of this computer: its home address, its addresses and network adapters,
//! how Windows treats the network, and the firewall. Behind [`Machine`], so tests use a
//! fake.
//!
//! Started from MoneyKeep's capture server (`services.rs`: the firewall check, Windows' own
//! Block rules, the network profiles, the address list and its parsers), then changed for
//! Keep Hub:
//!
//! - **One rule for the hub program** (owner decision 2026-11-18): inbound TCP to
//!   `keep-hub.exe` on any port, Private and Domain networks only, never Public. Registering
//!   an app needs no firewall change. The hub runs as a service without administrator
//!   rights, so it only *reads* the firewall; `keep-hub fix-firewall` puts the rule back,
//!   run by an app's desktop program with Windows' permission prompt.
//! - **The home address** is the address of the adapter the default route uses
//!   ([`default_route_address`]): the address a UDP socket would send from toward a public
//!   address. Nothing is sent.
//! - **No PowerShell** (owner decision 2026-11-22): on Windows the firewall, the network
//!   profiles and the adapters are read through Windows' own interfaces ([`crate::winfw`]).
//!   Stage 5 ran PowerShell scripts for them, as MoneyKeep does.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::Path;

use serde::{Deserialize, Serialize};

/// The firewall rule's name.
pub const FIREWALL_RULE: &str = "Keep Hub";
/// The program Windows' rules name.
pub const HUB_EXE: &str = "keep-hub.exe";

/// One of this computer's IPv4 addresses on a home or office network, with its adapter.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalAddress {
    pub address: String,
    /// The adapter's name, e.g. `Wi-Fi` or `Ethernet` (`en0` on a Mac).
    #[serde(default)]
    pub adapter: String,
    /// The adapter's MAC address (for a DHCP reservation).
    #[serde(default)]
    pub mac: String,
    /// Windows network profile: `Public`, `Private` or `DomainAuthenticated`.
    #[serde(default)]
    pub profile: String,
    /// The address came from DHCP.
    #[serde(default)]
    pub dhcp: bool,
}

/// A firewall rule found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoundRule {
    /// The rule's id (Windows: its `Name`, often a GUID).
    pub id: String,
    pub display_name: String,
    pub enabled: bool,
    /// `Allow` or `Block`.
    pub action: String,
    /// `Inbound` or `Outbound`.
    pub direction: String,
    /// The program the rule names, when it names one.
    #[serde(default)]
    pub program: String,
}

impl FoundRule {
    pub fn inbound(&self) -> bool {
        self.direction.eq_ignore_ascii_case("inbound")
    }
    pub fn is(&self, action: &str) -> bool {
        self.action.eq_ignore_ascii_case(action)
    }
    /// The rule names this program (by file name, any folder, any case).
    pub fn names_program(&self, program: &str) -> bool {
        let p = self.program.trim().trim_matches('"');
        let file = p.rsplit(['\\', '/']).next().unwrap_or(p);
        !file.is_empty() && file.eq_ignore_ascii_case(program)
    }
}

/// The rules named [`FIREWALL_RULE`], and the rules naming the hub program.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallScan {
    #[serde(default)]
    pub named: Vec<FoundRule>,
    #[serde(default)]
    pub program_rules: Vec<FoundRule>,
    /// On Linux: the firewall that is on and the ports it lets in (the Windows parts are
    /// then empty).
    #[serde(default)]
    pub linux: Option<crate::linuxfw::LinuxFirewall>,
}

/// The state of the hub's rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleState {
    Ok,
    Missing,
    Disabled,
}

/// What the firewall check found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallCheck {
    /// This system's firewall is one the hub manages (Windows).
    pub managed: bool,
    pub rule: RuleState,
    /// Inbound Block rules naming `keep-hub.exe`, turned on (Windows makes these when its
    /// "allow access" pop-up is closed; Fix turns them off). Allow rules are never listed.
    pub block_rules: Vec<FoundRule>,
}

impl FirewallCheck {
    pub fn ok(&self) -> bool {
        !self.managed || (self.rule == RuleState::Ok && self.block_rules.is_empty())
    }
}

/// Read a scan (MoneyKeep's `firewall_check`, for the hub's rule).
pub fn firewall_check(scan: Option<FirewallScan>) -> FirewallCheck {
    let Some(scan) = scan else {
        return FirewallCheck {
            managed: false,
            rule: RuleState::Ok,
            block_rules: Vec::new(),
        };
    };
    let ours: Vec<&FoundRule> = scan
        .named
        .iter()
        .filter(|r| r.display_name == FIREWALL_RULE && r.inbound() && r.is("Allow"))
        .collect();
    let rule = if ours.iter().any(|r| r.enabled) {
        RuleState::Ok
    } else if ours.is_empty() {
        RuleState::Missing
    } else {
        RuleState::Disabled
    };
    let block_rules = scan
        .program_rules
        .iter()
        .filter(|r| r.enabled && r.inbound() && r.is("Block") && r.names_program(HUB_EXE))
        .cloned()
        .collect();
    FirewallCheck {
        managed: true,
        rule,
        block_rules,
    }
}

/// The hub's inbound rule: the hub program, any local port, Private and Domain networks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallRule {
    pub name: String,
    /// Private and Domain only: never Public.
    pub profiles: Vec<String>,
    /// The program the rule is limited to (the installed hub).
    pub program: String,
}

impl FirewallRule {
    pub fn for_program(program: &Path) -> FirewallRule {
        FirewallRule {
            name: FIREWALL_RULE.into(),
            profiles: vec!["Private".into(), "Domain".into()],
            program: program.display().to_string(),
        }
    }

    /// The profiles kept: Private and Domain only, in that order.
    pub fn safe_profiles(&self) -> Vec<&'static str> {
        ["Private", "Domain"]
            .into_iter()
            .filter(|p| self.profiles.iter().any(|q| q.eq_ignore_ascii_case(p)))
            .collect()
    }
}

/// A home or office address (RFC 1918): the only kind the hub publishes.
pub fn is_home(ip: Ipv4Addr) -> bool {
    ip.is_private()
}

fn usable(ip: &str) -> bool {
    ip.parse::<Ipv4Addr>().is_ok_and(is_home)
}

/// Parse `ip -o -4 addr show` (Linux); `mac` reads an adapter's MAC address.
pub fn parse_ip_addr(text: &str, mac: impl Fn(&str) -> String) -> Vec<LocalAddress> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let adapter = f.get(1)?.trim_end_matches(':').to_owned();
            let pos = f.iter().position(|w| *w == "inet")?;
            let address = f.get(pos + 1)?.split('/').next()?.to_owned();
            usable(&address).then(|| LocalAddress {
                mac: mac(&adapter),
                dhcp: f.contains(&"dynamic"),
                address,
                adapter,
                profile: String::new(),
            })
        })
        .collect()
}

/// Parse `ifconfig` (macOS).
pub fn parse_ifconfig(text: &str) -> Vec<LocalAddress> {
    let mut out = Vec::new();
    let mut adapter = String::new();
    let mut mac = String::new();
    let mut found: Vec<String> = Vec::new();
    let flush = |adapter: &str, mac: &str, found: &mut Vec<String>, out: &mut Vec<LocalAddress>| {
        for a in found.drain(..) {
            out.push(LocalAddress {
                address: a,
                adapter: adapter.to_owned(),
                mac: mac.to_owned(),
                profile: String::new(),
                dhcp: false,
            });
        }
    };
    for line in text.lines() {
        if !line.starts_with(['\t', ' ']) && line.contains(':') {
            flush(&adapter, &mac, &mut found, &mut out);
            adapter = line.split(':').next().unwrap_or("").to_owned();
            mac.clear();
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        match (f.first(), f.get(1)) {
            (Some(&"ether"), Some(m)) => mac = (*m).to_owned(),
            (Some(&"inet"), Some(a)) if usable(a) => found.push((*a).to_owned()),
            _ => {}
        }
    }
    flush(&adapter, &mac, &mut found, &mut out);
    out
}

/// The address the default route would use, when it's a home address: the source
/// address of a UDP socket "connected" to a public address. Connecting a UDP socket sends
/// nothing; the system only picks the route.
pub fn default_route_address() -> Option<Ipv4Addr> {
    // TEST-NET-3 (RFC 5737): routed by the default route, never answered
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    sock.connect((Ipv4Addr::new(203, 0, 113, 1), 9)).ok()?;
    match sock.local_addr().ok()? {
        SocketAddr::V4(a) if is_home(*a.ip()) => Some(*a.ip()),
        _ => None,
    }
}

/// The address to use: with `adapter` "automatic" (or empty) the default route's, else
/// the first home address of the adapter of that name (any case). `None`: not on a home
/// network (or the adapter has no home address).
pub fn choose(
    adapter: &str,
    default: Option<Ipv4Addr>,
    list: impl FnOnce() -> Vec<LocalAddress>,
) -> Option<Ipv4Addr> {
    let a = adapter.trim();
    if a.is_empty() || a.eq_ignore_ascii_case("automatic") {
        return default;
    }
    list()
        .into_iter()
        .filter(|l| l.adapter.eq_ignore_ascii_case(a))
        .find_map(|l| l.address.parse().ok())
}

/// What the hub asks of this computer.
/// The kind of system the hub runs on (some checks differ).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Os {
    Windows,
    Mac,
    Linux,
}

impl Os {
    /// The system this program was built for.
    pub fn current() -> Os {
        if cfg!(windows) {
            Os::Windows
        } else if cfg!(target_os = "macos") {
            Os::Mac
        } else {
            Os::Linux
        }
    }
}

pub trait Machine: Send + Sync {
    /// The kind of system (the real one by default; a fake says which it plays).
    fn os(&self) -> Os {
        Os::current()
    }
    /// [`default_route_address`] (cheap: checked every 15 seconds).
    fn default_address(&self) -> Option<Ipv4Addr>;
    /// This computer's home addresses with their adapters (and, on Windows, profiles).
    fn addresses(&self) -> Vec<LocalAddress>;
    /// The firewall's rules for the hub; `Ok(None)` where the hub manages no firewall.
    fn firewall_scan(&self) -> Result<Option<FirewallScan>, String>;
    /// Put the hub's rule back and remove the Block rules given (needs administrator
    /// rights: `keep-hub fix-firewall`).
    fn fix_firewall(&self, rule: &FirewallRule, remove_ids: &[String]) -> Result<(), String>;
}

/// The real computer.
#[derive(Debug, Clone, Copy, Default)]
pub struct System;

/// Run a program without a console window (Windows); its output.
fn run_hidden(program: &str, args: &[&str]) -> Result<std::process::Output, String> {
    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.output()
        .map_err(|e| format!("{program} couldn't start: {e}"))
}

impl Machine for System {
    fn default_address(&self) -> Option<Ipv4Addr> {
        default_route_address()
    }

    fn addresses(&self) -> Vec<LocalAddress> {
        let text = |program: &str, args: &[&str]| {
            run_hidden(program, args)
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        };
        #[cfg(windows)]
        {
            let _ = text;
            crate::winfw::addresses()
        }
        #[cfg(not(windows))]
        if cfg!(target_os = "macos") {
            text("ifconfig", &[])
                .map(|t| parse_ifconfig(&t))
                .unwrap_or_default()
        } else {
            text("ip", &["-o", "-4", "addr", "show"])
                .map(|t| {
                    parse_ip_addr(&t, |a| {
                        std::fs::read_to_string(format!("/sys/class/net/{a}/address"))
                            .map(|m| m.trim().to_owned())
                            .unwrap_or_default()
                    })
                })
                .unwrap_or_default()
        }
    }

    fn firewall_scan(&self) -> Result<Option<FirewallScan>, String> {
        if cfg!(target_os = "linux") {
            return Ok(Some(FirewallScan {
                linux: Some(crate::linuxfw::system()?),
                ..FirewallScan::default()
            }));
        }
        #[cfg(windows)]
        {
            crate::winfw::scan(FIREWALL_RULE, HUB_EXE).map(Some)
        }
        #[cfg(not(windows))]
        Ok(None)
    }

    fn fix_firewall(&self, rule: &FirewallRule, remove_ids: &[String]) -> Result<(), String> {
        #[cfg(windows)]
        {
            crate::winfw::fix(rule, remove_ids)
        }
        #[cfg(not(windows))]
        {
            let _ = (rule, remove_ids);
            Err("only the Windows firewall is managed by Keep Hub".into())
        }
    }
}

/// `keep-hub fix-firewall` (run by an app's desktop program, with Windows' permission
/// prompt): put the hub's rule back for `program`, and remove Windows' Block rules for it.
/// What was done, in words.
pub fn fix_firewall(machine: &dyn Machine, program: &Path) -> Result<Vec<String>, String> {
    let check = firewall_check(machine.firewall_scan()?);
    if !check.managed {
        return Ok(vec![
            "This system's firewall isn't managed by Keep Hub.".into()
        ]);
    }
    if check.ok() {
        return Ok(vec![format!(
            "The firewall rule \"{FIREWALL_RULE}\" is in place."
        )]);
    }
    let rule = FirewallRule::for_program(program);
    let ids: Vec<String> = check.block_rules.iter().map(|r| r.id.clone()).collect();
    machine.fix_firewall(&rule, &ids)?;
    let mut done = vec![format!(
        "The firewall rule \"{FIREWALL_RULE}\" was put back (Private and Domain networks only)."
    )];
    if !ids.is_empty() {
        done.push(format!(
            "{} rule(s) Windows made to block the hub were turned off.",
            ids.len()
        ));
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(name: &str, enabled: bool, action: &str, program: &str) -> FoundRule {
        FoundRule {
            id: format!("{{{name}-{action}}}"),
            display_name: name.into(),
            enabled,
            action: action.into(),
            direction: "Inbound".into(),
            program: program.into(),
        }
    }

    #[test]
    fn the_firewall_check_reads_the_rule_and_windows_block_rules() {
        assert!(firewall_check(None).ok());
        let c = firewall_check(Some(FirewallScan::default()));
        assert_eq!((c.managed, c.rule), (true, RuleState::Missing));
        assert!(!c.ok());
        let c = firewall_check(Some(FirewallScan {
            named: vec![rule(FIREWALL_RULE, false, "Allow", "")],
            program_rules: vec![],
            linux: None,
        }));
        assert_eq!(c.rule, RuleState::Disabled);
        let c = firewall_check(Some(FirewallScan {
            named: vec![rule(FIREWALL_RULE, true, "Allow", "")],
            program_rules: vec![
                rule(
                    "keep-hub",
                    true,
                    "Block",
                    r"C:\Program Files\Keep Hub\KEEP-HUB.EXE",
                ),
                rule(
                    "keep-hub",
                    true,
                    "Allow",
                    r"C:\Program Files\Keep Hub\keep-hub.exe",
                ),
                rule("other", true, "Block", r"C:\x\other.exe"),
                // one Fix turned off: it blocks nothing
                rule(
                    "keep-hub.exe",
                    false,
                    "Block",
                    r"C:\Program Files\Keep Hub\keep-hub.exe",
                ),
            ],
            linux: None,
        }));
        assert_eq!(c.rule, RuleState::Ok);
        assert_eq!(c.block_rules.len(), 1, "only Block rules naming the hub");
        assert!(!c.ok());
    }

    #[test]
    fn mac_and_linux_address_lists_are_read() {
        let ifconfig = "lo0: flags=8049<UP,LOOPBACK> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\nen0: flags=8863<UP> mtu 1500\n\tether 3c:22:fb:00:11:22\n\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255\n";
        let a = parse_ifconfig(ifconfig);
        assert_eq!(a.len(), 1);
        assert_eq!(
            (a[0].adapter.as_str(), a[0].address.as_str()),
            ("en0", "192.168.1.20")
        );
        assert_eq!(a[0].mac, "3c:22:fb:00:11:22");
        let ip = "1: lo    inet 127.0.0.1/8 scope host lo\n2: wlan0    inet 10.0.0.7/24 brd 10.0.0.255 scope global dynamic wlan0\n";
        let a = parse_ip_addr(ip, |_| "m".into());
        assert_eq!(a.len(), 1);
        assert_eq!((a[0].adapter.as_str(), a[0].dhcp), ("wlan0", true));
    }

    #[test]
    fn the_default_routes_adapter_is_used_unless_one_is_chosen() {
        let list = || {
            vec![
                LocalAddress {
                    address: "192.168.1.20".into(),
                    adapter: "Wi-Fi".into(),
                    ..Default::default()
                },
                LocalAddress {
                    address: "10.0.0.5".into(),
                    adapter: "Ethernet".into(),
                    ..Default::default()
                },
            ]
        };
        let wifi = Some(Ipv4Addr::new(192, 168, 1, 20));
        assert_eq!(choose("automatic", wifi, list), wifi);
        assert_eq!(choose("", None, list), None);
        assert_eq!(
            choose("ethernet", wifi, list),
            Some(Ipv4Addr::new(10, 0, 0, 5))
        );
        assert_eq!(choose("Bluetooth", wifi, list), None);
    }

    struct Fake {
        scan: std::sync::Mutex<FirewallScan>,
        fixed: std::sync::Mutex<Vec<(FirewallRule, Vec<String>)>>,
    }

    impl Machine for Fake {
        fn default_address(&self) -> Option<Ipv4Addr> {
            None
        }
        fn addresses(&self) -> Vec<LocalAddress> {
            Vec::new()
        }
        fn firewall_scan(&self) -> Result<Option<FirewallScan>, String> {
            Ok(Some(self.scan.lock().unwrap().clone()))
        }
        fn fix_firewall(&self, rule: &FirewallRule, ids: &[String]) -> Result<(), String> {
            self.fixed
                .lock()
                .unwrap()
                .push((rule.clone(), ids.to_vec()));
            Ok(())
        }
    }

    #[test]
    fn fix_puts_the_rule_back_and_removes_block_rules_only_when_needed() {
        let exe = Path::new(r"C:\Program Files\Keep Hub\keep-hub.exe");
        let f = Fake {
            scan: std::sync::Mutex::new(FirewallScan {
                named: vec![],
                program_rules: vec![rule("keep-hub", true, "Block", r"C:\x\keep-hub.exe")],
                linux: None,
            }),
            fixed: std::sync::Mutex::new(Vec::new()),
        };
        let done = fix_firewall(&f, exe).unwrap();
        assert_eq!(done.len(), 2);
        let fixed = f.fixed.lock().unwrap().clone();
        assert_eq!(fixed.len(), 1);
        assert_eq!(fixed[0].0, FirewallRule::for_program(exe));
        assert_eq!(fixed[0].1, ["{keep-hub-Block}"]);
        // in place: nothing done
        *f.scan.lock().unwrap() = FirewallScan {
            named: vec![rule(FIREWALL_RULE, true, "Allow", "")],
            program_rules: vec![],
            linux: None,
        };
        fix_firewall(&f, exe).unwrap();
        assert_eq!(f.fixed.lock().unwrap().len(), 1);
    }

    #[test]
    fn this_computers_default_route_address_is_a_home_address_or_none() {
        // (whatever this machine has; never a public or loopback address)
        if let Some(ip) = default_route_address() {
            assert!(is_home(ip), "{ip}");
        }
    }
}
