//! What the hub asks of this computer: its home address, its addresses and network adapters,
//! how Windows treats the network, and the firewall. Behind [`Machine`], so tests use a
//! fake.
//!
//! Copied from MoneyKeep's capture server (`services.rs`: the firewall scan, Windows' own
//! Block rules, the network profiles, the firewall script, the address list and its
//! parsers, and how PowerShell is started), then changed for Keep Hub:
//!
//! - **One rule for the hub program** (owner decision 2026-11-18): inbound TCP to
//!   `keep-hub.exe` on any port, Private and Domain networks only, never Public. Registering
//!   an app needs no firewall change. The hub runs as a service without administrator
//!   rights, so it only *reads* the firewall; `keep-hub fix-firewall` puts the rule back,
//!   run by an app's desktop program with Windows' permission prompt.
//! - **The home address** is the address of the adapter the default route uses
//!   ([`default_route_address`]): the address a UDP socket would send from toward a public
//!   address. Nothing is sent.
//!
//! PowerShell is started as MoneyKeep learned: `powershell -NoProfile -NonInteractive`,
//! no console window, and without the caller's `PSModulePath` (Windows PowerShell started
//! from PowerShell 7 otherwise can't load its own modules). A blocked PowerShell is named
//! as such.

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
    /// Inbound Block rules naming `keep-hub.exe` (Windows makes these when its "allow
    /// access" pop-up is closed). Allow rules are never listed.
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
        .filter(|r| r.inbound() && r.is("Block") && r.names_program(HUB_EXE))
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
    /// The ports to let in: every registered app port and the certificate page's. A
    /// Windows rule names the program and covers any port; a firewall that can't name a
    /// program needs the ports.
    #[serde(default)]
    pub ports: Vec<u16>,
}

impl FirewallRule {
    pub fn for_program(program: &Path) -> FirewallRule {
        FirewallRule {
            name: FIREWALL_RULE.into(),
            profiles: vec!["Private".into(), "Domain".into()],
            program: program.display().to_string(),
            ports: Vec::new(),
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

fn ps_literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// The PowerShell commands (Windows Defender Firewall) that put the rule back: an earlier
/// rule of the same name and Windows' Block rules for the hub (by id) are removed first.
pub fn firewall_script(rule: &FirewallRule, remove_ids: &[String]) -> Result<String, String> {
    let profiles = rule.safe_profiles();
    if profiles.is_empty() || rule.name.trim().is_empty() || rule.program.trim().is_empty() {
        return Err(
            "the firewall rule needs a name, the program and the Private or Domain profile".into(),
        );
    }
    let removes: String = remove_ids
        .iter()
        .map(|id| {
            format!(
                "Remove-NetFirewallRule -Name {} -ErrorAction SilentlyContinue; ",
                ps_literal(id)
            )
        })
        .collect();
    Ok(format!(
        "{removes}Remove-NetFirewallRule -DisplayName {name} -ErrorAction SilentlyContinue; \
         New-NetFirewallRule -DisplayName {name} -Description {desc} -Direction Inbound -Action Allow \
         -Protocol TCP -Profile {profiles} -Program {program} | Out-Null",
        name = ps_literal(&rule.name),
        desc = ps_literal("Lets phones on your home or office network reach the Keep and Pick apps on this computer."),
        profiles = profiles.join(","),
        program = ps_literal(&rule.program),
    ))
}

/// The PowerShell script that lists the rules named `rule_name` and the rules naming
/// `program` (by file name) as one JSON object; reads only (no administrator rights).
pub fn firewall_scan_script(rule_name: &str, program: &str) -> String {
    let row = "ForEach-Object { $f = $_ | Get-NetFirewallApplicationFilter; [pscustomobject]@{ id = [string]$_.Name; display_name = [string]$_.DisplayName; enabled = ([string]$_.Enabled -eq 'True'); action = [string]$_.Action; direction = [string]$_.Direction; program = [string]$f.Program } }";
    format!(
        "$ErrorActionPreference = 'SilentlyContinue'; \
         $named = @(Get-NetFirewallRule -DisplayName {name} | {row}); \
         $prog = @(Get-NetFirewallApplicationFilter | Where-Object {{ $_.Program -and ((Split-Path -Leaf $_.Program) -ieq {program}) }} | Get-NetFirewallRule | {row}); \
         ConvertTo-Json -Depth 4 -Compress -InputObject ([pscustomobject]@{{ named = $named; program_rules = $prog }})",
        name = ps_literal(rule_name),
        program = ps_literal(program),
    )
}

/// One object or a list of them (PowerShell's ConvertTo-Json writes a single element
/// without the list).
fn one_or_many<T: serde::de::DeserializeOwned>(v: serde_json::Value) -> Vec<T> {
    match v {
        serde_json::Value::Array(a) => a
            .into_iter()
            .filter_map(|x| serde_json::from_value(x).ok())
            .collect(),
        serde_json::Value::Null => Vec::new(),
        other => serde_json::from_value(other).ok().into_iter().collect(),
    }
}

/// Read [`firewall_scan_script`]'s output.
pub fn parse_firewall_scan(json: &str) -> Result<FirewallScan, String> {
    let text = json.trim();
    if text.is_empty() {
        return Ok(FirewallScan::default());
    }
    let mut v: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| format!("the firewall list was not understood: {e}"))?;
    Ok(FirewallScan {
        named: one_or_many(
            v.get_mut("named")
                .map(serde_json::Value::take)
                .unwrap_or_default(),
        ),
        program_rules: one_or_many(
            v.get_mut("program_rules")
                .map(serde_json::Value::take)
                .unwrap_or_default(),
        ),
        linux: None,
    })
}

/// The PowerShell script listing IPv4 addresses with adapter, MAC address and network
/// profile as JSON (Windows; `Get-NetIPAddress`, `Get-NetAdapter`,
/// `Get-NetConnectionProfile`).
pub const ADDRESSES_SCRIPT: &str = "ConvertTo-Json -Compress -InputObject @(Get-NetIPAddress -AddressFamily IPv4 | \
     ForEach-Object { $a = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue; \
     $p = Get-NetConnectionProfile -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue; \
     [pscustomobject]@{ address = $_.IPAddress; adapter = $_.InterfaceAlias; mac = [string]$a.MacAddress; \
     profile = [string]$p.NetworkCategory; dhcp = ([string]$_.PrefixOrigin -eq 'Dhcp') } })";

/// A home or office address (RFC 1918): the only kind the hub publishes.
pub fn is_home(ip: Ipv4Addr) -> bool {
    ip.is_private()
}

fn usable(ip: &str) -> bool {
    ip.parse::<Ipv4Addr>().is_ok_and(is_home)
}

/// Parse the Windows script's JSON.
pub fn parse_windows_addresses(json: &str) -> Vec<LocalAddress> {
    one_or_many::<LocalAddress>(serde_json::from_str(json.trim()).unwrap_or_default())
        .into_iter()
        .filter(|a| usable(&a.address))
        .map(|mut a| {
            a.mac = a.mac.replace('-', ":").to_ascii_lowercase();
            a
        })
        .collect()
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
    if program.eq_ignore_ascii_case("powershell") {
        cmd.env_remove("PSModulePath");
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.output()
        .map_err(|e| format!("{program} couldn't start: {e}"))
}

/// The error text of a PowerShell step that was blocked rather than failed.
pub fn powershell_blocked(error: &str) -> bool {
    let e = error.to_ascii_lowercase();
    [
        "language mode",
        "constrainedlanguage",
        "only on core types",
        "running scripts is disabled",
        "pssecurityexception",
        "unauthorizedaccess",
        "blocked by group policy",
        "blocked by your system administrator",
        "applocker",
        "cannot run powershell",
    ]
    .iter()
    .any(|w| e.contains(w))
}

/// A PowerShell script's standard output.
fn powershell(script: &str) -> Result<String, String> {
    let out = run_hidden(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", script],
    )?;
    if out.status.success() {
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if powershell_blocked(&err) {
        Err(format!(
            "Windows blocked a PowerShell step (it may be restricted by your organisation). ({err})"
        ))
    } else {
        Err(format!("powershell failed: {err}"))
    }
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
        if cfg!(windows) {
            powershell(ADDRESSES_SCRIPT)
                .map(|t| parse_windows_addresses(&t))
                .unwrap_or_default()
        } else if cfg!(target_os = "macos") {
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
        if !cfg!(windows) {
            return Ok(None);
        }
        parse_firewall_scan(&powershell(&firewall_scan_script(FIREWALL_RULE, HUB_EXE))?).map(Some)
    }

    fn fix_firewall(&self, rule: &FirewallRule, remove_ids: &[String]) -> Result<(), String> {
        if !cfg!(windows) {
            return Err("only the Windows firewall is managed by Keep Hub".into());
        }
        powershell(&firewall_script(rule, remove_ids)?).map(|_| ())
    }
}

/// `keep-hub fix-firewall` (run by an app's desktop program, with Windows' permission
/// prompt): put the hub's rule back for `program`, and remove Windows' Block rules for it.
/// What was done, in words.
pub fn fix_firewall(machine: &dyn Machine, program: &Path) -> Result<Vec<String>, String> {
    fix_firewall_for(machine, program, &[])
}

/// [`fix_firewall`] with the ports the rule must let in (the hub's own Fix, which knows
/// them: `POST /admin/v1/problems/fix`).
pub fn fix_firewall_for(
    machine: &dyn Machine,
    program: &Path,
    ports: &[u16],
) -> Result<Vec<String>, String> {
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
    let mut rule = FirewallRule::for_program(program);
    rule.ports = ports.to_vec();
    let ids: Vec<String> = check.block_rules.iter().map(|r| r.id.clone()).collect();
    machine.fix_firewall(&rule, &ids)?;
    let mut done = vec![format!(
        "The firewall rule \"{FIREWALL_RULE}\" was put back (Private and Domain networks only)."
    )];
    if !ids.is_empty() {
        done.push(format!(
            "{} rule(s) Windows made to block the hub were removed.",
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
            ],
            linux: None,
        }));
        assert_eq!(c.rule, RuleState::Ok);
        assert_eq!(c.block_rules.len(), 1, "only Block rules naming the hub");
        assert!(!c.ok());
    }

    #[test]
    fn the_script_keeps_to_private_and_domain_and_quotes_safely() {
        let mut r = FirewallRule::for_program(Path::new(r"C:\Program Files\Keep Hub\keep-hub.exe"));
        r.profiles.push("Public".into());
        let s = firewall_script(&r, &["{abc'd}".to_string()]).unwrap();
        assert!(s.contains("-Profile Private,Domain "));
        assert!(!s.contains("Public"));
        assert!(s.contains(r"-Program 'C:\Program Files\Keep Hub\keep-hub.exe'"));
        assert!(s.starts_with("Remove-NetFirewallRule -Name '{abc''d}'"));
        assert!(!s.contains("-LocalPort"), "any port the hub listens on");
        r.profiles = vec!["Public".into()];
        assert!(firewall_script(&r, &[]).is_err());
    }

    #[test]
    fn powershells_json_is_read_one_or_many() {
        let one = r#"{"named":{"id":"a","display_name":"Keep Hub","enabled":true,"action":"Allow","direction":"Inbound","program":"x"},"program_rules":[]}"#;
        let s = parse_firewall_scan(one).unwrap();
        assert_eq!(s.named.len(), 1);
        assert!(s.program_rules.is_empty());
        assert_eq!(parse_firewall_scan("  ").unwrap(), FirewallScan::default());
        assert!(parse_firewall_scan("not json").is_err());
        let addrs = parse_windows_addresses(
            r#"[{"address":"192.168.1.20","adapter":"Wi-Fi","mac":"AA-BB-CC-DD-EE-FF","profile":"Private","dhcp":true},
                {"address":"127.0.0.1","adapter":"Loopback","mac":"","profile":"","dhcp":false},
                {"address":"169.254.3.4","adapter":"Ethernet 2","mac":"","profile":"","dhcp":false}]"#,
        );
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(addrs[0].profile, "Private");
        let single = parse_windows_addresses(
            r#"{"address":"10.0.0.5","adapter":"Ethernet","mac":"","profile":"Public","dhcp":false}"#,
        );
        assert_eq!(single[0].adapter, "Ethernet");
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

    #[test]
    fn a_blocked_powershell_is_recognised() {
        assert!(powershell_blocked("Cannot invoke method. Method invocation is supported only on core types in this language mode."));
        assert!(!powershell_blocked(
            "Get-NetFirewallRule: No MSFT_NetFirewallRule objects found"
        ));
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
