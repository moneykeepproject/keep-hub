//! Looking the hub's name up: through a public resolver over DNS over HTTPS (RFC 8484, the
//! wire format of RFC 1035), and through this computer's own resolver.
//!
//! The public resolver is Cloudflare's, then Google's if Cloudflare can't be reached (owner
//! decision 2026-11-18). Cloudflare also serves the `hub.getmoneykeep.org` zone, so it sees
//! a change soonest.

use std::net::{Ipv4Addr, ToSocketAddrs};
use std::sync::Arc;

use base64::Engine;

use crate::client::Http;

/// The public resolvers, in order.
pub const PUBLIC_RESOLVERS: &[&str] = &[
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
];

/// A record type the hub asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    A,
    Txt,
}

impl Kind {
    fn code(self) -> u16 {
        match self {
            Kind::A => 1,
            Kind::Txt => 16,
        }
    }
}

/// How the hub looks names up. Tests use fakes.
pub trait Lookup: Send + Sync {
    /// Through a public resolver: the A records as dotted text, or the TXT records' text.
    /// `Ok(empty)` when the name has none; `Err` when no resolver answered.
    fn public(&self, name: &str, kind: Kind) -> Result<Vec<String>, String>;
    /// Through this computer's own resolver (the home router, usually): the IPv4 addresses.
    /// `Ok(empty)` when it gives none.
    fn home(&self, name: &str) -> Result<Vec<Ipv4Addr>, String>;
}

/// A DNS query for `name` (RFC 1035 section 4.1; id 0 and recursion desired, as RFC 8484
/// section 4.1 suggests).
pub fn query(name: &str, kind: Kind) -> Option<Vec<u8>> {
    let mut q = vec![0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.trim_end_matches('.').split('.') {
        let len = u8::try_from(label.len())
            .ok()
            .filter(|l| (1..=63).contains(l))?;
        q.push(len);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&kind.code().to_be_bytes());
    q.extend_from_slice(&[0, 1]); // class IN
    Some(q)
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

/// The index after a name starting at `i` (labels, or a compression pointer).
fn skip_name(b: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let len = *b.get(i)?;
        match len {
            0 => return Some(i + 1),
            l if l & 0xC0 == 0xC0 => return Some(i + 2),
            l if l & 0xC0 == 0 => i += 1 + usize::from(l),
            _ => return None,
        }
    }
}

/// The answers of `kind` in a DNS response. `Err` for a failed lookup (not "no such name",
/// which is an empty answer).
pub fn answers(msg: &[u8], kind: Kind) -> Result<Vec<String>, String> {
    let bad = || "the resolver's answer can't be read".to_string();
    let flags = u16_at(msg, 2).ok_or_else(bad)?;
    if flags & 0x8000 == 0 {
        return Err(bad());
    }
    match flags & 0x000F {
        0 | 3 => {} // no error; no such name
        rcode => return Err(format!("the resolver failed (code {rcode})")),
    }
    let questions = u16_at(msg, 4).ok_or_else(bad)?;
    let count = u16_at(msg, 6).ok_or_else(bad)?;
    let mut i = 12;
    for _ in 0..questions {
        i = skip_name(msg, i).ok_or_else(bad)? + 4;
    }
    let mut out = Vec::new();
    for _ in 0..count {
        i = skip_name(msg, i).ok_or_else(bad)?;
        let rtype = u16_at(msg, i).ok_or_else(bad)?;
        let len = usize::from(u16_at(msg, i + 8).ok_or_else(bad)?);
        let data = msg.get(i + 10..i + 10 + len).ok_or_else(bad)?;
        i += 10 + len;
        if rtype != kind.code() {
            continue; // e.g. a CNAME on the way
        }
        match kind {
            Kind::A => {
                let b: [u8; 4] = data.try_into().map_err(|_| bad())?;
                out.push(Ipv4Addr::from(b).to_string());
            }
            Kind::Txt => {
                // one or more character-strings, joined (RFC 7208 section 3.3 does the same)
                let mut text = Vec::new();
                let mut j = 0;
                while let Some(&l) = data.get(j) {
                    let l = usize::from(l);
                    text.extend_from_slice(data.get(j + 1..j + 1 + l).ok_or_else(bad)?);
                    j += 1 + l;
                }
                out.push(String::from_utf8_lossy(&text).into_owned());
            }
        }
    }
    Ok(out)
}

/// The real lookups: the public resolvers over [`Http`], and this computer's resolver.
pub struct SystemLookup {
    http: Arc<dyn Http>,
    resolvers: Vec<String>,
}

impl SystemLookup {
    pub fn new(http: Arc<dyn Http>) -> SystemLookup {
        SystemLookup {
            http,
            resolvers: PUBLIC_RESOLVERS.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Lookup for SystemLookup {
    fn public(&self, name: &str, kind: Kind) -> Result<Vec<String>, String> {
        let q = query(name, kind).ok_or_else(|| format!("\"{name}\" isn't a name"))?;
        let q = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(q);
        let mut last = "no public resolver is set".to_string();
        for r in &self.resolvers {
            let answer = self.http.send(
                "GET",
                &format!("{r}?dns={q}"),
                &[("Accept", "application/dns-message")],
                None,
            );
            match answer {
                Ok(a) if a.status == 200 => return answers(&a.body, kind),
                Ok(a) => last = format!("the public resolver answered {}", a.status),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn home(&self, name: &str) -> Result<Vec<Ipv4Addr>, String> {
        match (name, 443).to_socket_addrs() {
            Ok(addrs) => Ok(addrs
                .filter_map(|a| match a.ip() {
                    std::net::IpAddr::V4(ip) => Some(ip),
                    std::net::IpAddr::V6(_) => None,
                })
                .collect()),
            // a home router that refuses the name usually answers "no such name"
            Err(_) => Ok(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Response;
    use std::sync::Mutex;

    /// A response to `q` with these answers (each name a pointer back to the question).
    fn response(q: &[u8], rcode: u8, records: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut m = q.to_vec();
        m[2] = 0x81; // response, recursion desired
        m[3] = 0x80 | rcode;
        m[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
        for (rtype, data) in records {
            m.extend_from_slice(&[0xC0, 12]);
            m.extend_from_slice(&rtype.to_be_bytes());
            m.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
            m.extend_from_slice(&(data.len() as u16).to_be_bytes());
            m.extend_from_slice(data);
        }
        m
    }

    #[test]
    fn a_query_is_the_rfc_1035_wire_format() {
        let q = query("ab.example.", Kind::Txt).unwrap();
        assert_eq!(
            q,
            [
                0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 2, b'a', b'b', 7, b'e', b'x', b'a', b'm', b'p',
                b'l', b'e', 0, 0, 16, 0, 1
            ]
        );
        assert!(query("a..b", Kind::A).is_none());
        assert!(query(&format!("{}.b", "x".repeat(64)), Kind::A).is_none());
    }

    #[test]
    fn answers_are_read_past_cnames_and_pointers() {
        let q = query("k7m2p9xw4tqa.hub.getmoneykeep.org", Kind::A).unwrap();
        let cname = vec![0xC0, 12]; // (its contents aren't read)
        let m = response(&q, 0, &[(5, cname), (1, vec![192, 168, 1, 20])]);
        assert_eq!(answers(&m, Kind::A).unwrap(), ["192.168.1.20"]);
        let q = query("_acme-challenge.a.example", Kind::Txt).unwrap();
        let mut txt = vec![3];
        txt.extend_from_slice(b"abc");
        txt.push(2);
        txt.extend_from_slice(b"de");
        let m = response(&q, 0, &[(16, txt)]);
        assert_eq!(answers(&m, Kind::Txt).unwrap(), ["abcde"]);
        // no such name: no answers; a server failure: an error
        assert!(answers(&response(&q, 3, &[]), Kind::Txt)
            .unwrap()
            .is_empty());
        assert!(answers(&response(&q, 2, &[]), Kind::Txt).is_err());
        assert!(answers(&q, Kind::Txt).is_err(), "a query isn't an answer");
        let mut cut = response(&q, 0, &[(16, vec![5, b'a'])]);
        assert!(answers(&cut, Kind::Txt).is_err());
        cut.truncate(20);
        assert!(answers(&cut, Kind::Txt).is_err());
    }

    struct Fake {
        asked: Mutex<Vec<String>>,
        cloudflare_down: bool,
    }

    impl Http for Fake {
        fn send(
            &self,
            method: &str,
            url: &str,
            headers: &[(&str, &str)],
            _body: Option<&[u8]>,
        ) -> Result<Response, String> {
            self.asked.lock().unwrap().push(url.to_string());
            assert_eq!(method, "GET");
            assert_eq!(headers, [("Accept", "application/dns-message")]);
            if self.cloudflare_down && url.starts_with("https://cloudflare-dns.com/") {
                return Err("unreachable".into());
            }
            let q = url.split_once("?dns=").unwrap().1;
            let q = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(q)
                .unwrap();
            Ok(Response {
                status: 200,
                headers: vec![("Content-Type".into(), "application/dns-message".into())],
                body: response(&q, 0, &[(1, vec![10, 0, 0, 5])]),
            })
        }
    }

    #[test]
    fn cloudflare_is_asked_first_and_google_if_it_cant_be_reached() {
        let fake = Arc::new(Fake {
            asked: Mutex::new(Vec::new()),
            cloudflare_down: false,
        });
        let l = SystemLookup::new(fake.clone());
        assert_eq!(l.public("a.example", Kind::A).unwrap(), ["10.0.0.5"]);
        assert_eq!(fake.asked.lock().unwrap().len(), 1);
        assert!(
            fake.asked.lock().unwrap()[0].starts_with("https://cloudflare-dns.com/dns-query?dns=")
        );

        let fake = Arc::new(Fake {
            asked: Mutex::new(Vec::new()),
            cloudflare_down: true,
        });
        let l = SystemLookup::new(fake.clone());
        assert_eq!(l.public("a.example", Kind::A).unwrap(), ["10.0.0.5"]);
        let asked = fake.asked.lock().unwrap();
        assert_eq!(asked.len(), 2);
        assert!(asked[1].starts_with("https://dns.google/dns-query?dns="));
    }

    #[test]
    fn this_computers_resolver_answers_for_itself() {
        let l = SystemLookup::new(Arc::new(Fake {
            asked: Mutex::new(Vec::new()),
            cloudflare_down: false,
        }));
        assert!(l.home("localhost").unwrap().contains(&Ipv4Addr::LOCALHOST));
        // A name no one has is an answer, not an error. What the answer holds depends on the
        // computer: some routers and virtual machines' networks answer every name (or the
        // computer's search domain is added on), so the test can't expect it to be empty. The
        // hub only ever looks for its own address in what comes back.
        assert!(l.home("no-such-name.invalid").is_ok());
    }
}
