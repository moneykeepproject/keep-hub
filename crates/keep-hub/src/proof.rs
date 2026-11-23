//! Protocol 2 (Revision 5 A): an app's backend proves it holds the shared secret before the
//! hub sends it anything, and the secret itself never crosses the connection.
//!
//! On each new connection to a protocol 2 backend the hub sends `GET /_keep-hub/hello` with
//! its challenge and nothing from the phone. The backend answers 204 with its proof (the
//! HMAC-SHA256, keyed with the shared secret, of `keep-hub app proof 2`, a line feed and
//! the hub's challenge) and a challenge of its own. Only then does the hub send the phone's
//! request on the same connection, with `Keep-Hub-Auth: 2 <proof>`, its own proof for the
//! backend's challenge. The key is the secret as the hub gave it (its hexadecimal text).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use ring::hmac;

use crate::http;
use crate::util;

/// The hello's path.
pub const HELLO_PATH: &str = "/_keep-hub/hello";
/// The challenge, both ways.
pub const CHALLENGE: &str = "Keep-Hub-Challenge";
/// The backend's proof.
pub const PROOF: &str = "Keep-Hub-Proof";
const APP_PROOF: &str = "keep-hub app proof 2\n";
const HUB_PROOF: &str = "keep-hub hub proof 2\n";
/// The backend answers the hello within this time, or it is not believed.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// The largest answer head to a hello.
const MAX_HELLO_ANSWER: usize = 8 * 1024;

fn key(secret: &str) -> hmac::Key {
    hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes())
}

/// The backend's proof for the hub's `challenge`.
pub fn app_proof(secret: &str, challenge: &str) -> String {
    util::hex(hmac::sign(&key(secret), format!("{APP_PROOF}{challenge}").as_bytes()).as_ref())
}

/// The hub's proof for the backend's `challenge`: what follows `2 ` in `Keep-Hub-Auth`.
pub fn hub_proof(secret: &str, challenge: &str) -> String {
    util::hex(hmac::sign(&key(secret), format!("{HUB_PROOF}{challenge}").as_bytes()).as_ref())
}

/// A challenge: 32 bytes in hexadecimal.
pub fn is_challenge(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| s.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok()))
        .collect()
}

/// Whether `proof` is the backend's proof for `challenge`, compared in constant time.
fn app_proof_ok(secret: &str, challenge: &str, proof: &str) -> bool {
    let Some(given) = unhex(proof.trim()) else {
        return false;
    };
    hmac::verify(
        &key(secret),
        format!("{APP_PROOF}{challenge}").as_bytes(),
        &given,
    )
    .is_ok()
}

/// Why a hello failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hello {
    /// Nothing could be sent: the backend went away (as a stopped app).
    Stopped,
    /// Something answered without proving it holds the secret: wrong, missing or late.
    Unverified,
}

/// The hello on a new connection to a protocol 2 backend. `Ok`: the backend proved it
/// holds the secret, and the value is the `Keep-Hub-Auth` for the request that follows.
/// Nothing from a phone is sent here.
pub fn hello(backend: &mut TcpStream, secret: &str) -> Result<String, Hello> {
    let challenge = util::hex(&util::random::<32>().map_err(|_| Hello::Stopped)?);
    let request = format!(
        "GET {HELLO_PATH} HTTP/1.1\r\nHost: 127.0.0.1\r\n{CHALLENGE}: {challenge}\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n"
    );
    backend
        .write_all(request.as_bytes())
        .and_then(|()| backend.flush())
        .map_err(|_| Hello::Stopped)?;
    let until = Instant::now() + HELLO_TIMEOUT;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let end = loop {
        if let Some(end) = http::head_end(&buf) {
            break end;
        }
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() || buf.len() > MAX_HELLO_ANSWER {
            return Err(Hello::Unverified);
        }
        backend
            .set_read_timeout(Some(left))
            .map_err(|_| Hello::Unverified)?;
        match backend.read(&mut chunk) {
            Ok(n) if n > 0 => buf.extend_from_slice(chunk.get(..n).unwrap_or(&[])),
            _ => return Err(Hello::Unverified),
        }
    };
    // a 204 has no body: anything after the head would be read as the request's answer
    if buf.len() != end + 4 {
        return Err(Hello::Unverified);
    }
    let text = std::str::from_utf8(buf.get(..end).unwrap_or(&[])).map_err(|_| Hello::Unverified)?;
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse::<u16>().ok());
    if status != Some(204) {
        return Err(Hello::Unverified);
    }
    let headers: Vec<(&str, &str)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim(), v.trim()))
        .collect();
    let one = |name: &str| {
        let mut it = headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name));
        match (it.next(), it.next()) {
            (Some((_, v)), None) => Some(*v),
            _ => None,
        }
    };
    let (Some(proof), Some(theirs)) = (one(PROOF), one(CHALLENGE)) else {
        return Err(Hello::Unverified);
    };
    if !app_proof_ok(secret, &challenge, proof) || !is_challenge(theirs) {
        return Err(Hello::Unverified);
    }
    Ok(format!(
        "2 {}",
        hub_proof(secret, &theirs.to_ascii_lowercase())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    const SECRET: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    /// A backend that answers the hello with `answer(challenge)`, then reads one request.
    fn backend(
        answer: fn(&str) -> String,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<Vec<u8>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut got = Vec::new();
            let mut b = [0u8; 1];
            while http::head_end(&got).is_none() && s.read(&mut b).unwrap_or(0) == 1 {
                got.push(b[0]);
            }
            let text = String::from_utf8_lossy(&got).to_string();
            let challenge = text
                .lines()
                .find_map(|l| l.strip_prefix("Keep-Hub-Challenge: "))
                .unwrap_or("")
                .to_string();
            let _ = s.write_all(answer(&challenge).as_bytes());
            let mut rest = Vec::new();
            let _ = s.read_to_end(&mut rest);
            got.extend(rest);
            got
        });
        (addr, t)
    }

    const MINE: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

    #[test]
    fn a_backend_with_the_secret_is_believed_and_gets_the_hubs_proof() {
        let (addr, t) = backend(|c| {
            format!(
                "HTTP/1.1 204 No Content\r\nKeep-Hub-Proof: {}\r\nKeep-Hub-Challenge: {MINE}\r\n\r\n",
                app_proof(SECRET, c)
            )
        });
        let mut s = TcpStream::connect(addr).unwrap();
        let auth = hello(&mut s, SECRET).unwrap();
        assert_eq!(auth, format!("2 {}", hub_proof(SECRET, MINE)));
        drop(s);
        let sent = String::from_utf8(t.join().unwrap()).unwrap();
        assert!(sent.starts_with("GET /_keep-hub/hello HTTP/1.1\r\n"));
        assert!(!sent.contains(SECRET), "the secret never crosses");
    }

    #[test]
    fn a_wrong_missing_or_late_proof_is_not_believed() {
        for answer in [
            (|_: &str| {
                format!("HTTP/1.1 204 No Content\r\nKeep-Hub-Proof: {}\r\nKeep-Hub-Challenge: {MINE}\r\n\r\n", app_proof("another", "x"))
            }) as fn(&str) -> String,
            |_| format!("HTTP/1.1 204 No Content\r\nKeep-Hub-Challenge: {MINE}\r\n\r\n"),
            |c| {
                format!(
                    "HTTP/1.1 200 OK\r\nKeep-Hub-Proof: {}\r\nKeep-Hub-Challenge: {MINE}\r\n\r\n",
                    app_proof(SECRET, c)
                )
            },
            |c| {
                format!("HTTP/1.1 204 No Content\r\nKeep-Hub-Proof: {}\r\nKeep-Hub-Challenge: short\r\n\r\n", app_proof(SECRET, c))
            },
            |c| {
                format!("HTTP/1.1 204 No Content\r\nKeep-Hub-Proof: {}\r\nKeep-Hub-Challenge: {MINE}\r\n\r\nextra", app_proof(SECRET, c))
            },
            |_| String::new(),
        ] {
            let (addr, t) = backend(answer);
            let mut s = TcpStream::connect(addr).unwrap();
            assert_eq!(hello(&mut s, SECRET), Err(Hello::Unverified));
            drop(s);
            t.join().unwrap();
        }
    }
}
