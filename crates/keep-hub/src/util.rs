//! Small helpers shared by the hub's modules (copied from ShareKeep's hub, `util.rs`; the
//! names follow MoneyKeep's capture server).

use std::path::Path;

/// Errors as text: every message is meant for the person at the hub computer.
pub type StoreResult<T> = Result<T, String>;

/// `N` random bytes from the operating system.
pub fn random<const N: usize>() -> StoreResult<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| format!("no random source: {e}"))?;
    Ok(b)
}

/// Lower-case hex.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Compare in constant time (for hashes of secrets).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Write a file only its owner can read (on Unix; on Windows the hub's data folder's
/// permissions apply, set by the hub's installer). Written through a temporary file.
///
/// Each write has its own temporary file, so two threads writing the same file at once
/// (the names engine and an admin request, say) can't take each other's: the later rename
/// wins, and neither fails.
pub fn write_private(path: &Path, bytes: &[u8]) -> StoreResult<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(
        ".{}-{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let tmp = std::path::PathBuf::from(tmp);
    let result = (|| -> std::io::Result<()> {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    result.map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("{} can't be written: {e}", path.display())
    })
}

/// Milliseconds since 1970 UTC.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Percent-encode text for a header value (RFC 3986 section 2.1): everything but letters,
/// digits and `-._~`.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The text a percent-encoded path or value stands for (bytes that aren't UTF-8 are
/// replaced).
pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c == b'%' {
            if let Some(v) = s
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_survive_percent_encoding() {
        let name = "Zoë O'Neil / 2";
        let enc = percent_encode(name);
        assert!(enc.bytes().all(|b| b.is_ascii_graphic() && b != b'/'));
        assert_eq!(percent_decode(&enc), name);
        assert_eq!(percent_decode("%2e%2E/%zz"), "../%zz");
    }

    #[test]
    fn equal_bytes_compare_equal() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    /// Many threads writing one file at once: none fails, no temporary file is left.
    #[test]
    fn writes_of_one_file_at_once_all_succeed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("names.json");
        let threads: Vec<_> = (0..8)
            .map(|i| {
                let p = path.clone();
                std::thread::spawn(move || {
                    for _ in 0..50 {
                        write_private(&p, format!("{i}").as_bytes()).unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let left: Vec<_> = std::fs::read_dir(dir.path()).unwrap().flatten().collect();
        assert_eq!(left.len(), 1);
    }
}
