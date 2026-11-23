//! Linux's firewall, as Find the problem's check 4 reads it (Revision 4 D).
//!
//! The hub runs as the `keep-hub` user with one capability, `CAP_NET_ADMIN`. That is
//! enough to read the kernel's rules (`nft -j list ruleset`), but not to change ufw or
//! firewalld: ufw refuses anyone but root, and firewalld's polkit policy refuses a service
//! user. So the hub only checks (owner decision 2026-11-22). The package opens the
//! certificate page's port at install, and ServicesKeep opens app ports (its Fix).
//!
//! - **Which firewall is on:** ufw when `/etc/ufw/ufw.conf` says `ENABLED=yes`; firewalld
//!   when `systemctl is-active firewalld` says `active`; otherwise plain nftables when a
//!   chain on the input hook drops by default or has a drop or reject rule. Otherwise none.
//! - **Which ports are open:** ufw and firewalld both keep their rules in nftables on
//!   Ubuntu and Fedora (ufw through iptables-nft), so a port is open when a rule matches
//!   `tcp dport` on it (alone, in a set or in a range) and accepts.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A firewall the hub found on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Active {
    Ufw,
    Firewalld,
    Nftables,
}

impl Active {
    pub fn name(self) -> &'static str {
        match self {
            Active::Ufw => "ufw",
            Active::Firewalld => "firewalld",
            Active::Nftables => "nftables",
        }
    }
}

/// What the hub found: the firewall that is on (`None`: none), and the TCP ports its rules
/// accept.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxFirewall {
    pub active: Option<Active>,
    /// Single ports and ranges (inclusive) that a rule accepts.
    pub open: Vec<(u16, u16)>,
}

impl LinuxFirewall {
    pub fn is_open(&self, port: u16) -> bool {
        self.open.iter().any(|(a, b)| (*a..=*b).contains(&port))
    }

    /// The ports of `want` that no rule accepts, in order.
    pub fn closed(&self, want: &[u16]) -> Vec<u16> {
        let set: BTreeSet<u16> = want.iter().copied().filter(|p| !self.is_open(*p)).collect();
        set.into_iter().collect()
    }
}

/// Whether ufw's own settings file says it is on.
pub fn ufw_enabled(conf: &str) -> bool {
    conf.lines().any(|l| {
        let l = l.trim();
        !l.starts_with('#')
            && l.split_once('=').is_some_and(|(k, v)| {
                k.trim() == "ENABLED" && v.trim().trim_matches('"').eq_ignore_ascii_case("yes")
            })
    })
}

/// A port or range on the right of a `tcp dport` match.
fn ports_in(v: &Value, out: &mut Vec<(u16, u16)>) {
    let port = |v: &Value| v.as_u64().and_then(|p| u16::try_from(p).ok());
    if let Some(p) = port(v) {
        out.push((p, p));
    } else if let Some([a, b]) = v.get("range").and_then(Value::as_array).map(Vec::as_slice) {
        if let (Some(a), Some(b)) = (port(a), port(b)) {
            out.push((a.min(b), a.max(b)));
        }
    } else if let Some(items) = v.get("set").and_then(Value::as_array) {
        for i in items {
            ports_in(i, out);
        }
    }
}

/// Whether an expression is a match on TCP's destination port.
fn is_tcp_dport(left: &Value) -> bool {
    let p = &left["payload"];
    p["protocol"] == "tcp" && p["field"] == "dport"
}

/// Read `nft -j list ruleset`: the ports accepted, and whether an input chain restricts
/// what comes in (a drop policy, or a drop or reject rule).
pub fn parse_nft(json: &str) -> Result<(Vec<(u16, u16)>, bool), String> {
    let v: Value =
        serde_json::from_str(json).map_err(|e| format!("nft's answer can't be read: {e}"))?;
    let items = v["nftables"]
        .as_array()
        .ok_or("nft's answer has no ruleset")?;
    let mut input_chains: BTreeSet<(String, String, String)> = BTreeSet::new();
    let mut restricts = false;
    for i in items {
        let c = &i["chain"];
        if c["hook"] == "input" {
            let key = |k: &str| c[k].as_str().unwrap_or("").to_string();
            input_chains.insert((key("family"), key("table"), key("name")));
            if c["policy"] == "drop" {
                restricts = true;
            }
        }
    }
    let mut open = Vec::new();
    for i in items {
        let r = &i["rule"];
        let Some(expr) = r["expr"].as_array() else {
            continue;
        };
        let accepts = expr.iter().any(|e| e.get("accept").is_some());
        let refuses = expr
            .iter()
            .any(|e| e.get("drop").is_some() || e.get("reject").is_some());
        let key = |k: &str| r[k].as_str().unwrap_or("").to_string();
        if refuses && input_chains.contains(&(key("family"), key("table"), key("chain"))) {
            restricts = true;
        }
        if !accepts {
            continue;
        }
        for e in expr {
            let m = &e["match"];
            if is_tcp_dport(&m["left"]) && matches!(m["op"].as_str(), Some("==" | "in")) {
                ports_in(&m["right"], &mut open);
            }
        }
    }
    Ok((open, restricts))
}

/// What the hub found, from what the system said: ufw's settings file, whether firewalld is
/// active, and the ruleset (`Err`: nft couldn't be asked).
pub fn read(
    ufw_conf: Option<&str>,
    firewalld_active: bool,
    ruleset: Result<String, String>,
) -> Result<LinuxFirewall, String> {
    let ufw = ufw_conf.is_some_and(ufw_enabled);
    // (without the ruleset neither the ports nor a plain nftables firewall can be known)
    let (open, restricts) = parse_nft(&ruleset?)?;
    let active = if ufw {
        Some(Active::Ufw)
    } else if firewalld_active {
        Some(Active::Firewalld)
    } else if restricts {
        Some(Active::Nftables)
    } else {
        None
    };
    Ok(LinuxFirewall { active, open })
}

/// The real system: ufw's file, `systemctl`, and `nft` (which needs the service's
/// `CAP_NET_ADMIN`).
pub fn system() -> Result<LinuxFirewall, String> {
    let conf = std::fs::read_to_string("/etc/ufw/ufw.conf").ok();
    let firewalld = std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "firewalld"])
        .status()
        .is_ok_and(|s| s.success());
    let ruleset = std::process::Command::new("nft")
        .args(["-j", "list", "ruleset"])
        .output()
        .map_err(|e| format!("nft couldn't start: {e}"))
        .and_then(|o| {
            if o.status.success() {
                Ok(String::from_utf8_lossy(&o.stdout).into_owned())
            } else {
                Err(format!(
                    "nft couldn't read the firewall's rules: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                ))
            }
        });
    read(conf.as_deref(), firewalld, ruleset)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ruleset as ufw (through iptables-nft) leaves it: a drop policy on input, and the
    /// ports it allows in its user chain.
    pub const UFW: &str = r#"{"nftables":[
      {"metainfo":{"version":"1.0.9"}},
      {"table":{"family":"ip","name":"filter"}},
      {"chain":{"family":"ip","table":"filter","name":"INPUT","type":"filter","hook":"input","prio":0,"policy":"drop"}},
      {"chain":{"family":"ip","table":"filter","name":"ufw-user-input"}},
      {"rule":{"family":"ip","table":"filter","chain":"ufw-user-input","expr":[
        {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":16080}},
        {"counter":{"packets":0,"bytes":0}},
        {"comment":"'dapp_Keep Hub'"},
        {"accept":null}]}},
      {"rule":{"family":"ip","table":"filter","chain":"ufw-user-input","expr":[
        {"match":{"op":"in","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"set":[14443,{"range":[16443,16445]}]}}},
        {"accept":null}]}},
      {"rule":{"family":"ip","table":"filter","chain":"ufw-user-input","expr":[
        {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":15443}},
        {"drop":null}]}}
    ]}"#;

    #[test]
    fn ufws_rules_read_as_the_ports_it_accepts() {
        let (open, restricts) = parse_nft(UFW).unwrap();
        assert!(restricts);
        let fw = LinuxFirewall {
            active: Some(Active::Ufw),
            open,
        };
        for p in [16080, 14443, 16443, 16444, 16445] {
            assert!(fw.is_open(p), "{p}");
        }
        assert!(!fw.is_open(15443), "a drop rule opens nothing");
        assert!(!fw.is_open(16446));
        assert_eq!(fw.closed(&[16080, 16446, 15443, 16446]), [15443, 16446]);
    }

    #[test]
    fn which_firewall_is_on() {
        let empty = r#"{"nftables":[{"metainfo":{}}]}"#;
        let on = "# /etc/ufw/ufw.conf\nENABLED=yes\nLOGLEVEL=low\n";
        let off = "ENABLED=no\n";
        assert!(ufw_enabled(on));
        assert!(!ufw_enabled(off));
        assert!(!ufw_enabled("#ENABLED=yes"));
        let fw = read(Some(on), false, Ok(UFW.into())).unwrap();
        assert_eq!(fw.active, Some(Active::Ufw));
        let fw = read(Some(off), true, Ok(empty.into())).unwrap();
        assert_eq!(fw.active, Some(Active::Firewalld));
        // plain nftables: on when an input chain restricts, otherwise no firewall
        let fw = read(Some(off), false, Ok(UFW.into())).unwrap();
        assert_eq!(fw.active, Some(Active::Nftables));
        let fw = read(None, false, Ok(empty.into())).unwrap();
        assert_eq!(fw.active, None);
        let accept_all = r#"{"nftables":[
          {"chain":{"family":"inet","table":"filter","name":"input","hook":"input","policy":"accept"}}]}"#;
        assert_eq!(
            read(None, false, Ok(accept_all.into())).unwrap().active,
            None
        );
        // nft couldn't be asked: the check can't be made
        assert!(read(Some(on), false, Err("no permission".into())).is_err());
        assert!(parse_nft("not json").is_err());
    }
}
