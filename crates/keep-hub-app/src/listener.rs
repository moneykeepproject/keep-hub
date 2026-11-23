//! Who is listening on the hub's admin address (Revision 5 B).
//!
//! While the hub is stopped (an update, a failed start), any program could listen on
//! 127.0.0.1:16081 and collect the admin token and an administrator's password. So before
//! the library sends anything on a connection to the admin address, it checks who holds the
//! listening socket:
//!
//! - **Windows:** the process listening must be the one the service manager reports for the
//!   `KeepHub` service. Only an administrator of the computer can make a program that service.
//! - **Linux:** the socket must belong to user `keep-hub` (`/proc/net/tcp`'s `uid`).
//! - **A Mac:** not checked yet (owner decision 2026-11-23: a Mac hub is later).
//!
//! Tests and development run hubs under the developer's own account: they say so with
//! [`Listener::ThisAccount`], which only a debug build offers.

#[cfg(debug_assertions)]
use std::sync::atomic::{AtomicBool, Ordering};

use crate::client::HubError;

/// Which account the program listening on the admin address must run as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listener {
    /// The hub's own service: Windows' `KeepHub` service, Linux's user `keep-hub`. The only
    /// choice in a release build.
    KeepHub,
    /// The account this program runs as: a hub a developer or a test started. Never the
    /// default, and not in a release build.
    #[cfg(debug_assertions)]
    ThisAccount,
}

#[cfg(debug_assertions)]
static DEVELOPMENT: AtomicBool = AtomicBool::new(false);

/// Development and tests only (not in a release build): every [`crate::HubClient`] made from
/// now on in this program expects a hub run by this same account
/// ([`Listener::ThisAccount`]), unless told otherwise.
#[cfg(debug_assertions)]
pub fn expect_this_account() {
    DEVELOPMENT.store(true, Ordering::SeqCst);
}

/// What a new client expects.
pub(crate) fn default_listener() -> Listener {
    #[cfg(debug_assertions)]
    if DEVELOPMENT.load(Ordering::SeqCst) {
        return Listener::ThisAccount;
    }
    Listener::KeepHub
}

/// The plain error when the check fails or can't be made.
pub(crate) fn not_confirmed(port: u16) -> HubError {
    HubError::here(
        "hub_not_confirmed",
        format!("Can't confirm that the program on this computer's port {port} is Keep Hub."),
    )
}

/// Whether the program listening on 127.0.0.1:`port` runs as `expected`.
pub(crate) fn confirm(expected: Listener, port: u16) -> Result<(), HubError> {
    if sys::listening_as(expected, port) {
        Ok(())
    } else {
        Err(not_confirmed(port))
    }
}

/// Linux's `/proc/net/tcp` and `tcp6`: the owners (uids) of the sockets listening where a
/// connection to 127.0.0.1:`port` can arrive (127.0.0.1, 0.0.0.0, `::`, `::ffff:127.0.0.1`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn listening_uids(tcp: &str, tcp6: &str, port: u16) -> Vec<u32> {
    let mut out = Vec::new();
    for (text, v6) in [(tcp, false), (tcp6, true)] {
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (Some(local), Some(state), Some(uid)) = (f.get(1), f.get(3), f.get(7)) else {
                continue;
            };
            if *state != "0A" {
                continue; // not listening
            }
            let Some((addr, p)) = local.split_once(':') else {
                continue;
            };
            if u16::from_str_radix(p, 16).ok() != Some(port) {
                continue;
            }
            let Some(bytes) = proc_address(addr) else {
                continue;
            };
            let reaches = if v6 {
                bytes.iter().all(|b| *b == 0)
                    || bytes == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]
            } else {
                bytes == [127, 0, 0, 1] || bytes == [0, 0, 0, 0]
            };
            if let (true, Ok(uid)) = (reaches, uid.parse::<u32>()) {
                out.push(uid);
            }
        }
    }
    out
}

/// An address as `/proc/net/tcp` writes it: 32-bit words in hexadecimal, each in the
/// computer's own byte order (little-endian on the computers the hub runs on).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn proc_address(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(8) || hex.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for i in (0..hex.len()).step_by(8) {
        let word = u32::from_str_radix(hex.get(i..i + 8)?, 16).ok()?;
        out.extend_from_slice(&word.to_le_bytes());
    }
    Some(out)
}

/// The uid of `user` in `/etc/passwd`'s text.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn uid_of(passwd: &str, user: &str) -> Option<u32> {
    passwd.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next() == Some(user))
            .then(|| f.nth(1).and_then(|u| u.parse().ok()))
            .flatten()
    })
}

#[cfg(target_os = "linux")]
mod sys {
    use super::Listener;

    /// The user the hub's service runs as (Revision 4 D).
    const HUB_USER: &str = "keep-hub";

    pub(super) fn listening_as(expected: Listener, port: u16) -> bool {
        let want = match expected {
            Listener::KeepHub => std::fs::read_to_string("/etc/passwd")
                .ok()
                .and_then(|p| super::uid_of(&p, HUB_USER)),
            #[cfg(debug_assertions)]
            Listener::ThisAccount => {
                use std::os::unix::fs::MetadataExt;
                // (/proc/self belongs to this process's effective user)
                std::fs::metadata("/proc/self").ok().map(|m| m.uid())
            }
        };
        let Some(want) = want else {
            return false;
        };
        let tcp = std::fs::read_to_string("/proc/net/tcp").unwrap_or_default();
        let tcp6 = std::fs::read_to_string("/proc/net/tcp6").unwrap_or_default();
        let owners = super::listening_uids(&tcp, &tcp6, port);
        !owners.is_empty() && owners.iter().all(|u| *u == want)
    }
}

#[cfg(windows)]
mod sys {
    use super::Listener;
    use std::mem::{offset_of, size_of};
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
        MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    use windows_sys::Win32::Security::{
        EqualSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
        SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    /// The hub's service (stage 7).
    const SERVICE: &str = "KeepHub";

    pub(super) fn listening_as(expected: Listener, port: u16) -> bool {
        let Some(pids) = listening_pids(port) else {
            return false;
        };
        if pids.is_empty() {
            return false;
        }
        match expected {
            Listener::KeepHub => {
                let Some(service) = service_pid() else {
                    return false;
                };
                service != 0 && pids.iter().all(|p| *p == service)
            }
            #[cfg(debug_assertions)]
            Listener::ThisAccount => {
                // SAFETY: the pseudo-handle of this process needs no closing.
                let own = unsafe { GetCurrentProcess() };
                let Some(mine) = user_sid(own) else {
                    return false;
                };
                pids.iter().all(|p| same_user(*p, &mine))
            }
        }
    }

    /// The table GetExtendedTcpTable fills for `family`, in a buffer aligned for it.
    fn table(family: u16) -> Option<(Vec<u64>, usize)> {
        let mut size: u32 = 0;
        let mut buf: Vec<u64> = Vec::new();
        for _ in 0..4 {
            // SAFETY: the buffer holds `size` bytes (or is empty with size 0, to learn it).
            let rc = unsafe {
                GetExtendedTcpTable(
                    buf.as_mut_ptr().cast(),
                    &mut size,
                    0,
                    u32::from(family),
                    TCP_TABLE_OWNER_PID_LISTENER,
                    0,
                )
            };
            if rc == 0 {
                return Some((buf, size as usize));
            }
            // ERROR_INSUFFICIENT_BUFFER: grow and ask again
            if rc != 122 {
                return None;
            }
            buf = vec![0u64; (size as usize).div_ceil(8) + 1];
        }
        None
    }

    /// The processes listening where a connection to 127.0.0.1:`port` can arrive.
    fn listening_pids(port: u16) -> Option<Vec<u32>> {
        let mut pids = Vec::new();
        let (buf, size) = table(AF_INET)?;
        if size >= size_of::<u32>() {
            // SAFETY: the buffer is aligned for the table and at least its count long.
            let n =
                unsafe { (*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID)).dwNumEntries } as usize;
            let start = offset_of!(MIB_TCPTABLE_OWNER_PID, table);
            if start + n * size_of::<MIB_TCPROW_OWNER_PID>() > size {
                return None;
            }
            // SAFETY: n rows lie inside the buffer, checked just above.
            let rows = unsafe {
                std::slice::from_raw_parts(
                    (buf.as_ptr() as *const u8).add(start) as *const MIB_TCPROW_OWNER_PID,
                    n,
                )
            };
            for r in rows {
                let local = r.dwLocalAddr.to_ne_bytes();
                let p = u16::from_be((r.dwLocalPort & 0xffff) as u16);
                if p == port && (local == [127, 0, 0, 1] || local == [0, 0, 0, 0]) {
                    pids.push(r.dwOwningPid);
                }
            }
        }
        if let Some((buf, size)) = table(AF_INET6) {
            if size >= size_of::<u32>() {
                // SAFETY: as above, for the IPv6 table.
                let n = unsafe { (*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID)).dwNumEntries }
                    as usize;
                let start = offset_of!(MIB_TCP6TABLE_OWNER_PID, table);
                if start + n * size_of::<MIB_TCP6ROW_OWNER_PID>() > size {
                    return None;
                }
                // SAFETY: n rows lie inside the buffer, checked just above.
                let rows = unsafe {
                    std::slice::from_raw_parts(
                        (buf.as_ptr() as *const u8).add(start) as *const MIB_TCP6ROW_OWNER_PID,
                        n,
                    )
                };
                for r in rows {
                    let a = r.ucLocalAddr;
                    let p = u16::from_be((r.dwLocalPort & 0xffff) as u16);
                    let reaches = a.iter().all(|b| *b == 0)
                        || a == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1];
                    if p == port && reaches {
                        pids.push(r.dwOwningPid);
                    }
                }
            }
        }
        Some(pids)
    }

    /// The process id the service manager reports for the hub's service.
    fn service_pid() -> Option<u32> {
        let name: Vec<u16> = SERVICE.encode_utf16().chain(Some(0)).collect();
        // SAFETY: null names mean this computer's active database.
        let scm = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
        if scm.is_null() {
            return None;
        }
        // SAFETY: a valid manager handle and a NUL-terminated name.
        let svc = unsafe { OpenServiceW(scm, name.as_ptr(), SERVICE_QUERY_STATUS) };
        let mut out = None;
        if !svc.is_null() {
            let mut status: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
            let mut needed = 0u32;
            // SAFETY: the buffer is one SERVICE_STATUS_PROCESS, its size given.
            let ok = unsafe {
                QueryServiceStatusEx(
                    svc,
                    SC_STATUS_PROCESS_INFO,
                    (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
                    size_of::<SERVICE_STATUS_PROCESS>() as u32,
                    &mut needed,
                )
            };
            if ok != 0 {
                out = Some(status.dwProcessId);
            }
            // SAFETY: opened above.
            unsafe { CloseServiceHandle(svc) };
        }
        // SAFETY: opened above.
        unsafe { CloseServiceHandle(scm) };
        out
    }

    /// The user SID of the process `process`, as bytes.
    fn user_sid(process: HANDLE) -> Option<Vec<u8>> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: a process handle; the token is closed below.
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return None;
        }
        let mut len = 0u32;
        // SAFETY: asking for the size only.
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len) };
        let mut buf = vec![0u64; (len as usize).div_ceil(8) + 1];
        // SAFETY: the buffer holds `len` bytes, aligned for TOKEN_USER.
        let ok = unsafe {
            GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len)
        };
        let out = if ok != 0 {
            // SAFETY: filled with a TOKEN_USER whose SID lies inside the buffer.
            let sid = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };
            let n = unsafe { windows_sys::Win32::Security::GetLengthSid(sid) } as usize;
            // SAFETY: the SID is n bytes long.
            Some(unsafe { std::slice::from_raw_parts(sid as *const u8, n) }.to_vec())
        } else {
            None
        };
        // SAFETY: opened above.
        unsafe { CloseHandle(token) };
        out
    }

    /// Whether process `pid` runs as the user whose SID is `mine`.
    fn same_user(pid: u32, mine: &[u8]) -> bool {
        // SAFETY: the handle is closed below.
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h.is_null() {
            return false;
        }
        let theirs = user_sid(h);
        // SAFETY: opened above.
        unsafe { CloseHandle(h) };
        let Some(mut theirs) = theirs else {
            return false;
        };
        let mut mine = mine.to_vec();
        // SAFETY: two valid SIDs, as read above.
        unsafe { EqualSid(theirs.as_mut_ptr().cast(), mine.as_mut_ptr().cast()) != 0 }
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod sys {
    use super::Listener;

    /// A Mac: not checked yet (owner decision 2026-11-23, an open point of Revision 5).
    pub(super) fn listening_as(_expected: Listener, _port: u16) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:3ED1 00000000:0000 0A 00000000:00000000 00:00000000 00000000   998        0 1 1
   1: 00000000:3ED0 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1
   2: 0100007F:3ED1 0100007F:C350 01 00000000:00000000 00:00000000 00000000  1000        0 3 1
   3: 0101A8C0:3ED1 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4 1
";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:3ED1 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 5 1
";

    #[test]
    fn the_listeners_on_the_admin_port_and_their_owners() {
        // 127.0.0.1:16081 by 998 (keep-hub), and `[::]:16081` by 1000, which also reaches
        // 127.0.0.1; a connection (01) and another address's listener don't count
        assert_eq!(listening_uids(TCP, TCP6, 16081), [998, 1000]);
        assert_eq!(listening_uids(TCP, "", 16081), [998]);
        // 0.0.0.0:16080 by root
        assert_eq!(listening_uids(TCP, "", 16080), [0]);
        assert!(listening_uids(TCP, TCP6, 9).is_empty());
        let mapped = "h\n 0: 0000000000000000FFFF00000100007F:3ED1 0:0 0A 0:0 0:0 0 1000 0 1 1\n";
        assert_eq!(listening_uids("", mapped, 16081), [1000]);
    }

    #[test]
    fn the_hubs_user_in_passwd() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\nkeep-hub:x:998:998:Keep Hub:/var/lib/keep-hub:/usr/sbin/nologin\n";
        assert_eq!(uid_of(passwd, "keep-hub"), Some(998));
        assert_eq!(uid_of(passwd, "keep"), None);
    }

    #[test]
    fn the_error_is_plain() {
        let e = not_confirmed(16081);
        assert_eq!(e.code, "hub_not_confirmed");
        assert_eq!(
            e.message,
            "Can't confirm that the program on this computer's port 16081 is Keep Hub."
        );
    }
}
