//! Who owns a file or folder (copied from Keep Hub's `owner.rs`, itself from ShareKeep's
//! `sk-client`). The hub's data folder lives in `%ProgramData%`, where any user may create
//! folders: before an app believes the admin token there, the folder and the token must belong
//! to the administrators, SYSTEM or a service account, none of which an ordinary program can
//! be. On other systems these checks pass (the Mac hub keeps its data in the user's own
//! Library).

use std::path::Path;

#[cfg_attr(not(windows), allow(dead_code))] // (used by `protected` on Windows only)
/// Owners an ordinary program can't be: Administrators, SYSTEM, TrustedInstaller and the
/// other service accounts (`NT SERVICE\…`, S-1-5-80-…), such as the hub's own.
pub fn trusted_owner(sid: &str) -> bool {
    sid == "S-1-5-32-544" || sid == "S-1-5-18" || sid.starts_with("S-1-5-80-")
}

/// The owner of a file or folder, as a SID string ("S-1-5-32-544").
#[cfg(windows)]
pub fn owner(path: &Path) -> Result<String, String> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut sid: PSID = null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: the name is NUL-terminated; the descriptor is freed below, and `sid` points into it.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut sid,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sd,
        )
    };
    if rc != 0 {
        return Err(format!(
            "{}: its owner can't be read (error {rc})",
            path.display()
        ));
    }
    let mut text: *mut u16 = null_mut();
    // SAFETY: `sid` is valid while `sd` lives; `text` is allocated by the call and freed below.
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut text) };
    let out = if ok != 0 && !text.is_null() {
        let mut len = 0;
        // SAFETY: a NUL-terminated string from ConvertSidToStringSidW.
        unsafe {
            while *text.add(len) != 0 {
                len += 1;
            }
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
            LocalFree(text as _);
            Ok(s)
        }
    } else {
        Err(format!("{}: its owner can't be read", path.display()))
    };
    // SAFETY: allocated by GetNamedSecurityInfoW.
    unsafe {
        LocalFree(sd as _);
    }
    out
}

/// Whether `path` is owned by an account an ordinary program can't be.
pub fn protected(path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        let sid = owner(path)?;
        if !trusted_owner(&sid) {
            return Err(format!(
                "{} belongs to {sid}, not to the administrators",
                path.display()
            ));
        }
    }
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owners_an_ordinary_program_cant_be() {
        assert!(trusted_owner("S-1-5-32-544"));
        assert!(trusted_owner("S-1-5-18"));
        // NT SERVICE\KeepHub
        assert!(trusted_owner(
            "S-1-5-80-1234567890-1234567890-1234567890-1234567890-1234567890"
        ));
        // a person's account, Users, Everyone
        assert!(!trusted_owner("S-1-5-21-1-2-3-1001"));
        assert!(!trusted_owner("S-1-5-32-545"));
        assert!(!trusted_owner("S-1-1-0"));
    }
}
