//! Windows' firewall, network list and adapters, through Windows' own interfaces instead of
//! PowerShell (owner decision 2026-11-22). The rule for Keep Hub's code is no PowerShell on
//! Windows: an organisation may lock PowerShell down, and the hub would then fail.
//!
//! - **The firewall:** Windows Firewall's COM interface (`INetFwPolicy2`, `INetFwRule`). It
//!   gives each rule's own values, never words in the computer's language, as `netsh` would.
//! - **Each network's profile** (Public, Private or Domain, for check 3): the Network List
//!   Manager (`INetworkListManager`), matched to each adapter by its id.
//! - **Adapters and addresses:** `GetAdaptersAddresses`.
//!
//! Windows' Block rules for the hub (made when someone closes its "allow access" pop-up) are
//! turned off, not deleted: the COM interface removes rules by name only, and an Allow rule
//! may share that name.
//!
//! The parts below that need no Windows are tested on every system; the COM and IP Helper
//! calls are compiled and tested on Windows only.

/// The firewall profiles a profile name stands for (`NET_FW_PROFILE2_DOMAIN` is 1,
/// `NET_FW_PROFILE2_PRIVATE` 2). Public (4) is never given: [`crate::machine::FirewallRule`]
/// keeps to Private and Domain.
pub fn profile_mask(profiles: &[&str]) -> i32 {
    profiles
        .iter()
        .map(|p| match p.to_ascii_lowercase().as_str() {
            "domain" => 1,
            "private" => 2,
            _ => 0,
        })
        .fold(0, |a, b| a | b)
}

/// A network's category as the hub's checks name it (`NLM_NETWORK_CATEGORY`): what
/// PowerShell's `NetworkCategory` said, so check 3 reads both alike.
pub fn category_name(category: i32) -> &'static str {
    match category {
        0 => "Public",
        1 => "Private",
        2 => "DomainAuthenticated",
        _ => "",
    }
}

/// A MAC address as the hub shows one: `aa:bb:cc:dd:ee:ff`.
pub fn mac_text(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// An adapter's id as both `GetAdaptersAddresses` (`{6B29FC40-CA47-1067-B31D-00DD010662DA}`)
/// and the Network List Manager (a GUID, printed without braces) give it: upper case, no
/// braces.
pub fn adapter_key(id: &str) -> String {
    id.trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .to_ascii_uppercase()
}

#[cfg(windows)]
pub use sys::{addresses, fix, scan};

#[cfg(windows)]
mod sys {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    use windows::core::{Interface, BSTR};
    use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, VARIANT_FALSE, VARIANT_TRUE};
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, GET_ADAPTERS_ADDRESSES_FLAGS, IF_TYPE_SOFTWARE_LOOPBACK,
        IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_DHCP_ENABLED,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows::Win32::NetworkManagement::WindowsFirewall::{
        INetFwPolicy2, INetFwRule, INetFwRules, NetFwPolicy2, NetFwRule, NET_FW_ACTION_ALLOW,
        NET_FW_ACTION_BLOCK, NET_FW_IP_PROTOCOL_TCP, NET_FW_RULE_DIR_IN,
    };
    use windows::Win32::Networking::NetworkListManager::{
        INetworkConnection, INetworkListManager, NetworkListManager,
    };
    use windows::Win32::Networking::WinSock::{IpPrefixOriginDhcp, AF_INET, SOCKADDR_IN};
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_ALL, CLSCTX_INPROC_SERVER,
        COINIT_MULTITHREADED,
    };
    use windows::Win32::System::Ole::IEnumVARIANT;
    use windows::Win32::System::Variant::{VariantClear, VARIANT, VT_DISPATCH};

    use super::{adapter_key, category_name, mac_text, profile_mask};
    use crate::machine::{FirewallRule, FirewallScan, FoundRule, LocalAddress};

    const DESCRIPTION: &str =
        "Lets phones on your home or office network reach the Keep and Pick apps on this computer.";

    /// COM for this thread while it lives (undone only if this call started it).
    struct Com(bool);

    impl Com {
        fn start() -> Com {
            // SAFETY: no reserved pointer; paired with CoUninitialize in Drop when it worked
            // (S_FALSE, already started on this thread, also needs the pairing call).
            let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            Com(hr.is_ok())
        }
    }

    impl Drop for Com {
        fn drop(&mut self) {
            if self.0 {
                // SAFETY: pairs the successful CoInitializeEx above, on the same thread.
                unsafe { CoUninitialize() }
            }
        }
    }

    fn fail(what: &str) -> impl Fn(windows::core::Error) -> String + '_ {
        move |e| format!("{what}: {e}")
    }

    fn policy() -> Result<INetFwPolicy2, String> {
        // SAFETY: a COM object made on a thread with COM started (the caller's `Com`).
        unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }
            .map_err(fail("Windows Firewall can't be asked"))
    }

    /// Every rule in the firewall.
    fn all_rules(rules: &INetFwRules) -> Result<Vec<INetFwRule>, String> {
        // SAFETY: COM calls on live objects; each VARIANT is cleared after its rule is taken.
        unsafe {
            let unknown = rules
                ._NewEnum()
                .map_err(fail("the firewall's rules can't be listed"))?;
            let list: IEnumVARIANT = unknown
                .cast()
                .map_err(fail("the firewall's rules can't be listed"))?;
            let mut out = Vec::new();
            loop {
                let mut one = [VARIANT::default()];
                let mut fetched = 0u32;
                let hr = list.Next(&mut one, &mut fetched);
                if hr.is_err() || fetched == 0 {
                    break;
                }
                let inner = &one[0].Anonymous.Anonymous;
                let rule = if inner.vt == VT_DISPATCH {
                    (*inner.Anonymous.pdispVal)
                        .as_ref()
                        .and_then(|d| d.cast::<INetFwRule>().ok())
                } else {
                    None
                };
                let _ = VariantClear(&mut one[0]);
                if let Some(r) = rule {
                    out.push(r);
                }
            }
            Ok(out)
        }
    }

    fn text(b: windows::core::Result<BSTR>) -> String {
        b.map(|s| s.to_string()).unwrap_or_default()
    }

    /// A rule as the hub's checks read one. Its id is its name: the COM interface has no
    /// other.
    fn found(r: &INetFwRule) -> FoundRule {
        // SAFETY: property reads on a live rule.
        unsafe {
            let name = text(r.Name());
            FoundRule {
                id: name.clone(),
                display_name: name,
                enabled: r.Enabled().is_ok_and(|b| b != VARIANT_FALSE),
                action: match r.Action() {
                    Ok(a) if a == NET_FW_ACTION_ALLOW => "Allow".into(),
                    Ok(a) if a == NET_FW_ACTION_BLOCK => "Block".into(),
                    _ => String::new(),
                },
                direction: match r.Direction() {
                    Ok(d) if d == NET_FW_RULE_DIR_IN => "Inbound".into(),
                    Ok(_) => "Outbound".into(),
                    Err(_) => String::new(),
                },
                program: text(r.ApplicationName()),
            }
        }
    }

    /// The rules named `rule_name`, and the rules naming `program` (by file name). Reads
    /// only: no administrator rights needed.
    pub fn scan(rule_name: &str, program: &str) -> Result<FirewallScan, String> {
        let _com = Com::start();
        let policy = policy()?;
        // SAFETY: a COM call on a live object.
        let rules =
            unsafe { policy.Rules() }.map_err(fail("the firewall's rules can't be read"))?;
        let all: Vec<FoundRule> = all_rules(&rules)?.iter().map(found).collect();
        Ok(FirewallScan {
            named: all
                .iter()
                .filter(|r| r.display_name == rule_name)
                .cloned()
                .collect(),
            program_rules: all
                .into_iter()
                .filter(|r| r.names_program(program))
                .collect(),
            linux: None,
        })
    }

    /// Put the hub's rule back, and turn off the Block rules named in `block_ids` that name
    /// the hub's program. Needs an administrator (`keep-hub fix-firewall`, run with
    /// Windows' permission prompt).
    pub fn fix(rule: &FirewallRule, block_ids: &[String]) -> Result<(), String> {
        let profiles = rule.safe_profiles();
        if profiles.is_empty() || rule.name.trim().is_empty() || rule.program.trim().is_empty() {
            return Err(
                "the firewall rule needs a name, the program and the Private or Domain profile"
                    .into(),
            );
        }
        let _com = Com::start();
        let policy = policy()?;
        let program = std::path::Path::new(&rule.program)
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();
        // SAFETY: COM calls on live objects made above.
        unsafe {
            let rules = policy
                .Rules()
                .map_err(fail("the firewall's rules can't be read"))?;
            // an earlier rule of the same name goes first (Remove takes one at a time)
            let name = BSTR::from(rule.name.as_str());
            for _ in 0..50 {
                if rules.Item(&name).is_err() {
                    break;
                }
                rules
                    .Remove(&name)
                    .map_err(fail("the old firewall rule can't be removed"))?;
            }
            let new: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)
                .map_err(fail("a firewall rule can't be made"))?;
            let set = fail("the firewall rule can't be set up");
            new.SetName(&name).map_err(&set)?;
            new.SetDescription(&BSTR::from(DESCRIPTION)).map_err(&set)?;
            new.SetApplicationName(&BSTR::from(rule.program.as_str()))
                .map_err(&set)?;
            new.SetProtocol(NET_FW_IP_PROTOCOL_TCP.0).map_err(&set)?;
            new.SetDirection(NET_FW_RULE_DIR_IN).map_err(&set)?;
            new.SetAction(NET_FW_ACTION_ALLOW).map_err(&set)?;
            new.SetProfiles(profile_mask(&profiles)).map_err(&set)?;
            new.SetEnabled(VARIANT_TRUE).map_err(&set)?;
            rules
                .Add(&new)
                .map_err(fail("the firewall rule can't be added"))?;
            // Windows' own Block rules for the hub: turned off, exactly those found
            if !block_ids.is_empty() {
                for r in all_rules(&rules)? {
                    let f = found(&r);
                    if f.inbound()
                        && f.is("Block")
                        && f.enabled
                        && f.names_program(&program)
                        && block_ids.contains(&f.id)
                    {
                        r.SetEnabled(VARIANT_FALSE)
                            .map_err(fail("a rule that blocks the hub can't be turned off"))?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Each connected network's category, by its adapter's id ([`adapter_key`]).
    fn categories() -> HashMap<String, &'static str> {
        let mut out = HashMap::new();
        // SAFETY: COM calls on live objects; the enumerator hands each connection over.
        unsafe {
            let made: windows::core::Result<INetworkListManager> =
                CoCreateInstance(&NetworkListManager, None, CLSCTX_ALL);
            let Ok(nlm) = made else {
                return out;
            };
            let Ok(list) = nlm.GetNetworkConnections() else {
                return out;
            };
            loop {
                let mut one: [Option<INetworkConnection>; 1] = [None];
                let mut fetched = 0u32;
                if list.Next(&mut one, Some(&mut fetched as *mut u32)).is_err() || fetched == 0 {
                    break;
                }
                let Some(c) = one[0].take() else { break };
                let (Ok(id), Ok(net)) = (c.GetAdapterId(), c.GetNetwork()) else {
                    continue;
                };
                if let Ok(cat) = net.GetCategory() {
                    out.insert(adapter_key(&format!("{id:?}")), category_name(cat.0));
                }
            }
        }
        out
    }

    /// This computer's IPv4 home addresses, with each adapter's name, MAC address, DHCP
    /// and network profile.
    pub fn addresses() -> Vec<LocalAddress> {
        let _com = Com::start();
        let profiles = categories();
        let flags = GET_ADAPTERS_ADDRESSES_FLAGS(
            GAA_FLAG_SKIP_ANYCAST.0 | GAA_FLAG_SKIP_MULTICAST.0 | GAA_FLAG_SKIP_DNS_SERVER.0,
        );
        // (u64s: the list is read through pointers that want 8-byte alignment)
        let mut size: u32 = 16 * 1024;
        let mut buf: Vec<u64> = Vec::new();
        for _ in 0..4 {
            buf = vec![0u64; (size as usize).div_ceil(8)];
            // SAFETY: the buffer holds `size` bytes; Windows writes the list into it, or the
            // size it needs.
            let rc = unsafe {
                GetAdaptersAddresses(
                    u32::from(AF_INET.0),
                    flags,
                    None,
                    Some(buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>()),
                    &mut size,
                )
            };
            if rc == ERROR_BUFFER_OVERFLOW.0 {
                continue;
            }
            if rc != 0 {
                return Vec::new();
            }
            break;
        }
        let mut out = Vec::new();
        let mut p = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: a linked list Windows wrote into `buf`, which lives until the end; each
        // pointer in it is null or points inside it.
        unsafe {
            while !p.is_null() {
                let a = &*p;
                p = a.Next;
                if a.OperStatus != IfOperStatusUp || a.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
                    continue;
                }
                let adapter = a.FriendlyName.to_string().unwrap_or_default();
                let len = (a.PhysicalAddressLength as usize).min(a.PhysicalAddress.len());
                let mac = mac_text(&a.PhysicalAddress[..len]);
                let id = a.AdapterName.to_string().unwrap_or_default();
                let profile = profiles.get(&adapter_key(&id)).copied().unwrap_or("");
                let dhcp_on = a.Anonymous2.Flags & IP_ADAPTER_DHCP_ENABLED != 0;
                let mut u = a.FirstUnicastAddress;
                while !u.is_null() {
                    let ua = &*u;
                    u = ua.Next;
                    let sa = ua.Address.lpSockaddr;
                    if sa.is_null() || (*sa).sa_family != AF_INET {
                        continue;
                    }
                    let sin = &*(sa.cast::<SOCKADDR_IN>());
                    let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.S_un.S_addr));
                    if !crate::machine::is_home(ip) {
                        continue;
                    }
                    out.push(LocalAddress {
                        address: ip.to_string(),
                        adapter: adapter.clone(),
                        mac: mac.clone(),
                        profile: profile.to_string(),
                        dhcp: dhcp_on && ua.PrefixOrigin == IpPrefixOriginDhcp,
                    });
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_categories_and_macs_read_as_the_checks_expect() {
        assert_eq!(profile_mask(&["Private", "Domain"]), 3);
        assert_eq!(profile_mask(&["private"]), 2);
        assert_eq!(profile_mask(&["Public"]), 0, "never Public");
        assert_eq!(
            (
                category_name(0),
                category_name(1),
                category_name(2),
                category_name(9)
            ),
            ("Public", "Private", "DomainAuthenticated", "")
        );
        assert_eq!(
            mac_text(&[0xAA, 0xBB, 0x0C, 0xDD, 0xEE, 0x0F]),
            "aa:bb:0c:dd:ee:0f"
        );
        assert_eq!(mac_text(&[]), "");
        // the two ways Windows writes an adapter's id meet
        assert_eq!(
            adapter_key("{6b29fc40-ca47-1067-b31d-00dd010662da}"),
            adapter_key("6B29FC40-CA47-1067-B31D-00DD010662DA")
        );
    }
}
