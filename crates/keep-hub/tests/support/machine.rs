//! This computer, faked: its home address (the test moves it), its adapters and profiles,
//! and a Windows-like firewall that records what Fix does.

use std::net::Ipv4Addr;
use std::sync::Mutex;

use keep_hub::machine::{FirewallRule, FirewallScan, FoundRule, LocalAddress, Machine, Os};

pub struct FakeMachine {
    /// What the default route would use (`None`: not on a home network).
    pub default: Mutex<Option<Ipv4Addr>>,
    pub addresses: Mutex<Vec<LocalAddress>>,
    /// `None`: a firewall the hub doesn't manage; `Some`: Windows' rules.
    pub firewall: Mutex<Option<FirewallScan>>,
    /// The firewall can't be read (Windows Firewall didn't answer).
    pub firewall_error: Mutex<Option<String>>,
    /// Every Fix: the rule and the Block rules removed.
    pub fixes: Mutex<Vec<(FirewallRule, Vec<String>)>>,
    /// The system it plays (Windows unless a test says otherwise).
    pub os: Mutex<Os>,
}

impl FakeMachine {
    pub fn at(ip: Ipv4Addr) -> FakeMachine {
        FakeMachine {
            default: Mutex::new(Some(ip)),
            addresses: Mutex::new(vec![LocalAddress {
                address: ip.to_string(),
                adapter: "Wi-Fi".into(),
                profile: "Private".into(),
                ..Default::default()
            }]),
            firewall: Mutex::new(None),
            firewall_error: Mutex::new(None),
            fixes: Mutex::new(Vec::new()),
            os: Mutex::new(Os::Windows),
        }
    }

    /// The default route now uses `ip` (and the adapter list says so).
    pub fn move_to(&self, ip: Option<Ipv4Addr>) {
        *self.default.lock().unwrap() = ip;
        let mut list = self.addresses.lock().unwrap();
        if let (Some(ip), Some(first)) = (ip, list.first_mut()) {
            first.address = ip.to_string();
        }
    }

    pub fn set_profile(&self, profile: &str) {
        for a in self.addresses.lock().unwrap().iter_mut() {
            a.profile = profile.into();
        }
    }

    /// A Windows firewall with the hub's rule in place.
    pub fn windows_firewall_ok(&self) {
        *self.firewall.lock().unwrap() = Some(FirewallScan {
            named: vec![rule("Keep Hub", "Allow", "")],
            program_rules: vec![],
            linux: None,
        });
    }
}

pub fn rule(name: &str, action: &str, program: &str) -> FoundRule {
    FoundRule {
        id: format!("{{{name}-{action}}}"),
        display_name: name.into(),
        enabled: true,
        action: action.into(),
        direction: "Inbound".into(),
        program: program.into(),
    }
}

impl Machine for FakeMachine {
    fn os(&self) -> Os {
        *self.os.lock().unwrap()
    }

    fn default_address(&self) -> Option<Ipv4Addr> {
        *self.default.lock().unwrap()
    }

    fn addresses(&self) -> Vec<LocalAddress> {
        self.addresses.lock().unwrap().clone()
    }

    fn firewall_scan(&self) -> Result<Option<FirewallScan>, String> {
        if let Some(e) = self.firewall_error.lock().unwrap().clone() {
            return Err(e);
        }
        Ok(self.firewall.lock().unwrap().clone())
    }

    fn fix_firewall(&self, rule: &FirewallRule, remove_ids: &[String]) -> Result<(), String> {
        self.fixes
            .lock()
            .unwrap()
            .push((rule.clone(), remove_ids.to_vec()));
        let mut fw = self.firewall.lock().unwrap();
        let scan = fw.get_or_insert_with(FirewallScan::default);
        scan.program_rules.retain(|r| !remove_ids.contains(&r.id));
        scan.named.retain(|r| r.display_name != rule.name);
        scan.named
            .push(self::rule(&rule.name, "Allow", &rule.program));
        Ok(())
    }
}
