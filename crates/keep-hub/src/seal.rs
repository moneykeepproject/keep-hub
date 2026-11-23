//! Secrets sealed by the operating system before they are written to a file (copied from
//! ShareKeep's `sk-client`, `seal.rs`, with Keep Hub's own marker and entropy).
//!
//! On Windows, DPAPI (`CryptProtectData`): a sealed file can't be opened on another computer
//! (and, for [`Scope::User`], not by another Windows user). [`Scope::Machine`] is for the
//! hub's service, whose keys are made by the hub's installer (an administrator) and read by the
//! service's own account; the data folder's permissions keep everyone else out.
//!
//! On Linux (Revision 4 D, owner decision 2026-11-22), with systemd credentials: the
//! package seals one random master key with `systemd-creds` (the TPM when the computer has
//! one, otherwise systemd's own key for this computer), and the service unit gives it to the
//! hub at each start. The hub seals each key with it (AES-256-GCM, ring) behind
//! [`MAGIC_LINUX`] ([`set_master`]). Without it, and on macOS, the file is kept as it is,
//! readable only by its owner.
//!
//! A sealed file starts with [`MAGIC`] or [`MAGIC_LINUX`]; a file without either is read as
//! plain (written before sealing existed, or on another system), so callers can seal it
//! again.

/// Who may open a sealed secret on this computer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Only this Windows user.
    User,
    /// Any program on this computer (the folder's permissions do the rest).
    Machine,
}

/// The start of a DPAPI-sealed file.
pub const MAGIC: &[u8; 4] = b"KHD1";

/// Extra entropy, so another program's DPAPI blob is never mistaken for ours.
#[cfg(windows)]
const ENTROPY: &[u8] = b"Keep Hub sealed secret v1";

/// Whether this system seals by itself (Windows). On Linux sealing depends on the master key
/// ([`seals`]).
pub const SEALS: bool = cfg!(windows);

/// The start of a file sealed with the Linux master key: then a 12-byte nonce, then the
/// secret encrypted with AES-256-GCM and its tag.
pub const MAGIC_LINUX: &[u8; 4] = b"KHL1";
const AAD: &[u8] = b"Keep Hub sealed key v1";

static MASTER: std::sync::OnceLock<zeroize::Zeroizing<[u8; 32]>> = std::sync::OnceLock::new();

/// Use `key` (32 bytes: the systemd credential) to seal keys from now on. Set once, at start.
pub fn set_master(key: &[u8]) -> Result<(), String> {
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| "the master key isn't 32 bytes".to_string())?;
    MASTER
        .set(zeroize::Zeroizing::new(key))
        .map_err(|_| "the master key is already set".to_string())
}

/// Whether secrets written now are sealed.
pub fn seals() -> bool {
    SEALS || MASTER.get().is_some()
}

/// How the hub's keys are kept, for the status: whether they are sealed, and in words.
pub fn protection() -> serde_json::Value {
    let (sealed, words) = if SEALS {
        (true, "Keys are sealed by Windows for this computer.")
    } else if MASTER.get().is_some() {
        (true, "Keys are sealed by systemd for this computer.")
    } else {
        (false, "Keys are protected by file permissions only.")
    };
    serde_json::json!({ "sealed": sealed, "words": words })
}

fn aead_key(key: &[u8; 32]) -> Result<ring::aead::LessSafeKey, String> {
    ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key)
        .map(ring::aead::LessSafeKey::new)
        .map_err(|_| "the master key can't be used".to_string())
}

/// Seal with the master key `key`: [`MAGIC_LINUX`], the nonce, the sealed bytes. (On
/// Windows DPAPI seals, so only the tests use this there.)
#[cfg_attr(windows, allow(dead_code))]
fn seal_with(key: &[u8; 32], secret: &[u8]) -> Result<Vec<u8>, String> {
    let nonce = crate::util::random::<12>()?;
    let mut buf = secret.to_vec();
    aead_key(key)?
        .seal_in_place_append_tag(
            ring::aead::Nonce::assume_unique_for_key(nonce),
            ring::aead::Aad::from(AAD),
            &mut buf,
        )
        .map_err(|_| "the key couldn't be sealed".to_string())?;
    let mut out = MAGIC_LINUX.to_vec();
    out.extend_from_slice(&nonce);
    out.extend(buf);
    Ok(out)
}

/// Open what [`seal_with`] made (the part after [`MAGIC_LINUX`]).
fn unseal_with(key: &[u8; 32], blob: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    let wrong = || {
        "this key was sealed for another computer (or its master key was replaced) and can't be opened here".to_string()
    };
    let (nonce, sealed) = blob.split_at_checked(12).ok_or_else(wrong)?;
    let nonce: [u8; 12] = nonce.try_into().map_err(|_| wrong())?;
    let mut buf = zeroize::Zeroizing::new(sealed.to_vec());
    let plain = aead_key(key)?
        .open_in_place(
            ring::aead::Nonce::assume_unique_for_key(nonce),
            ring::aead::Aad::from(AAD),
            &mut buf,
        )
        .map_err(|_| wrong())?;
    Ok(zeroize::Zeroizing::new(plain.to_vec()))
}

/// The bytes to write for `secret`.
pub fn seal(secret: &[u8], scope: Scope) -> Result<Vec<u8>, String> {
    #[cfg(windows)]
    {
        let mut out = MAGIC.to_vec();
        out.extend(dpapi::protect(secret, scope)?);
        Ok(out)
    }
    #[cfg(not(windows))]
    {
        let _ = scope;
        match MASTER.get() {
            Some(key) => seal_with(key, secret),
            None => Ok(secret.to_vec()),
        }
    }
}

/// The secret in bytes read from a file, and whether they were sealed.
pub fn unseal(bytes: &[u8], scope: Scope) -> Result<(zeroize::Zeroizing<Vec<u8>>, bool), String> {
    if let Some(blob) = bytes.strip_prefix(MAGIC_LINUX.as_slice()) {
        let Some(key) = MASTER.get() else {
            return Err("this key is sealed with systemd's credential, which the hub didn't get at start (is it running as keep-hub.service?)".into());
        };
        return unseal_with(key, blob).map(|k| (k, true));
    }
    match bytes.strip_prefix(MAGIC.as_slice()) {
        Some(blob) => {
            #[cfg(windows)]
            {
                Ok((
                    zeroize::Zeroizing::new(dpapi::unprotect(blob, scope)?),
                    true,
                ))
            }
            #[cfg(not(windows))]
            {
                let _ = (blob, scope);
                Err("this secret was sealed by Windows on another computer and can't be opened here".into())
            }
        }
        None => Ok((zeroize::Zeroizing::new(bytes.to_vec()), false)),
    }
}

#[cfg(windows)]
mod dpapi {
    use super::{Scope, ENTROPY};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE,
        CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    fn blob(b: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: b.len() as u32,
            pbData: b.as_ptr() as *mut u8,
        }
    }

    fn flags(scope: Scope) -> u32 {
        CRYPTPROTECT_UI_FORBIDDEN
            | match scope {
                Scope::Machine => CRYPTPROTECT_LOCAL_MACHINE,
                Scope::User => 0,
            }
    }

    /// Copy DPAPI's output and free it.
    unsafe fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(out.pbData as _);
        v
    }

    pub fn protect(secret: &[u8], scope: Scope) -> Result<Vec<u8>, String> {
        let input = blob(secret);
        let entropy = blob(ENTROPY);
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: the input blobs point at live slices for the call; DPAPI allocates `out`,
        // which `take` copies and frees.
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                flags(scope),
                &mut out,
            )
        };
        if ok == 0 {
            return Err(format!(
                "Windows couldn't seal the secret ({})",
                std::io::Error::last_os_error()
            ));
        }
        Ok(unsafe { take(out) })
    }

    pub fn unprotect(sealed: &[u8], scope: Scope) -> Result<Vec<u8>, String> {
        let input = blob(sealed);
        let entropy = blob(ENTROPY);
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: as in `protect`.
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                flags(scope),
                &mut out,
            )
        };
        if ok == 0 {
            return Err(format!(
                "Windows couldn't open the sealed secret: it was sealed on another computer or by another user ({})",
                std::io::Error::last_os_error()
            ));
        }
        Ok(unsafe { take(out) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_round_trips_and_plain_files_still_read() {
        for scope in [Scope::User, Scope::Machine] {
            let sealed = seal(b"top secret", scope).unwrap();
            assert_eq!(sealed.starts_with(MAGIC), SEALS);
            if SEALS {
                assert!(!sealed.windows(10).any(|w| w == b"top secret"));
            }
            let (back, was) = unseal(&sealed, scope).unwrap();
            assert_eq!(back.as_slice(), b"top secret");
            assert_eq!(was, SEALS);
        }
        let (plain, was) = unseal(b"old key", Scope::Machine).unwrap();
        assert_eq!(plain.as_slice(), b"old key");
        assert!(!was);
    }

    /// The Linux sealing with a master key (tested without the process-wide one, which a
    /// test can't unset).
    #[test]
    fn a_key_sealed_with_the_master_key_opens_with_it_only() {
        let key = [7u8; 32];
        let sealed = seal_with(&key, b"top secret").unwrap();
        assert!(sealed.starts_with(MAGIC_LINUX));
        assert!(!sealed.windows(10).any(|w| w == b"top secret"));
        let back = unseal_with(&key, &sealed[4..]).unwrap();
        assert_eq!(back.as_slice(), b"top secret");
        // a different key (another computer) or a changed byte: refused, in words
        let e = unseal_with(&[8u8; 32], &sealed[4..]).unwrap_err();
        assert!(e.contains("another computer"), "{e}");
        let mut bent = sealed.clone();
        let last = bent.len() - 1;
        bent[last] ^= 1;
        assert!(unseal_with(&key, &bent[4..]).is_err());
        assert!(unseal_with(&key, b"short").is_err());
        // two seals of one secret differ (a fresh nonce each time)
        assert_ne!(seal_with(&key, b"top secret").unwrap(), sealed);
        // without the master key in this process, a Linux-sealed file isn't opened
        if MASTER.get().is_none() {
            let e = unseal(&sealed, Scope::Machine).unwrap_err();
            assert!(e.contains("systemd"), "{e}");
        }
    }
}
