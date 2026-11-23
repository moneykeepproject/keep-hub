//! The probe (Revision 4 A): one path, `GET /_probe/<nonce>`, that shows a request from
//! outside reached the hub. ServicesKeep (or a phone) asks the admin address for a nonce,
//! opens the address it is given, and asks again whether the hub saw it.
//!
//! - A nonce is 16 to 64 letters and digits. Anything else answers 404 and nothing is kept.
//! - One request a second from one address; above that, 429 and nothing is kept.
//! - A nonce the hub issued is recorded with the time and the source, once (the first time
//!   it is seen). An unknown nonce of the right shape still answers 204, so the path tells
//!   an outsider nothing; it is counted, never kept, and a thousand in an hour is logged
//!   once, without the nonces.
//! - A nonce is kept for `probe.minutes` (10) from when it was issued.
//!
//! The handler reads nothing but the request line, except on the loopback listener that a
//! tunnel's ingress points at. There it also looks for Cloudflare's connecting-address
//! header, and only whether it is present. It needs no device token and forwards to no
//! backend.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use serde::Serialize;

/// The path's beginning.
pub const PREFIX: &str = "/_probe/";
/// The header Cloudflare's connector adds with the visitor's address.
pub const CLOUDFLARE_HEADER: &str = "cf-connecting-ip";
/// Unknown nonces in an hour that are logged (once).
pub const UNKNOWN_LOGGED_AT: u32 = 1000;
const HOUR_MS: i64 = 3_600_000;
const RATE_MS: i64 = 1000;

/// How a probe request came.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// From a private address on the home network, without Cloudflare's header.
    Home,
    /// Through the tunnel: on the loopback listener, with Cloudflare's header.
    Tunnel,
    /// From this computer: a loopback address or its own home address.
    ThisComputer,
    /// From an address that is neither private nor this computer's (a port forwarded
    /// from the internet, say): not one of the spec's three.
    Outside,
}

/// Which listener a request arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arrived {
    /// The home address (the Wi-Fi), or the certificate page's port.
    Home,
    /// The loopback listener a tunnel's ingress points at.
    Loopback,
}

/// The source of a probe request. Cloudflare's header counts only on the loopback listener,
/// never on the home address, where anyone on the Wi-Fi could send it.
pub fn source(peer: IpAddr, arrived: Arrived, cloudflare: bool, home: Option<Ipv4Addr>) -> Source {
    if arrived == Arrived::Loopback && cloudflare {
        return Source::Tunnel;
    }
    let v4 = match peer {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    };
    if peer.is_loopback() || v4.is_some_and(|v| v.is_loopback() || Some(v) == home) {
        return Source::ThisComputer;
    }
    match v4 {
        Some(v) if v.is_private() || v.is_link_local() => Source::Home,
        _ => Source::Outside,
    }
}

/// Whether `nonce` has the shape of one: 16 to 64 letters and digits.
pub fn well_formed(nonce: &str) -> bool {
    (16..=64).contains(&nonce.len()) && nonce.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// The nonce in a request target, when it is a probe path (`None`: not one).
pub fn nonce_of(target: &str) -> Option<&str> {
    target.strip_prefix(PREFIX)
}

/// When a nonce was seen, and how.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Seen {
    pub when: i64,
    pub source: Source,
}

struct Issued {
    expires: i64,
    seen: Option<Seen>,
}

/// What the hub keeps: the nonces it issued, the last request from each address, and the
/// count of unknown nonces this hour.
#[derive(Default)]
pub struct Probes {
    issued: HashMap<String, Issued>,
    last: HashMap<IpAddr, i64>,
    hour_start: i64,
    unknown: u32,
}

/// What a probe request gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// 204, recorded (a nonce the hub issued).
    Recorded,
    /// 204, counted, not kept (an unknown nonce of the right shape).
    Unknown {
        /// Log the hour's one line now.
        log: bool,
    },
    /// 404: not the shape of a nonce.
    NotANonce,
    /// 429: a second request from this address within a second.
    TooSoon,
}

impl Outcome {
    pub fn status(self) -> u16 {
        match self {
            Outcome::Recorded | Outcome::Unknown { .. } => 204,
            Outcome::NotANonce => 404,
            Outcome::TooSoon => 429,
        }
    }
}

impl Probes {
    fn prune(&mut self, now: i64) {
        self.issued.retain(|_, i| i.expires > now);
        self.last.retain(|_, t| now - *t < RATE_MS);
    }

    /// Keep a new nonce for `minutes`.
    pub fn issue(&mut self, nonce: String, now: i64, minutes: u32) -> i64 {
        self.prune(now);
        let expires = now + i64::from(minutes.max(1)) * 60_000;
        self.issued.insert(
            nonce,
            Issued {
                expires,
                seen: None,
            },
        );
        expires
    }

    /// A probe request for `nonce` from `peer`, which came as `source`.
    pub fn request(&mut self, nonce: &str, peer: IpAddr, source: Source, now: i64) -> Outcome {
        if !well_formed(nonce) {
            return Outcome::NotANonce;
        }
        self.prune(now);
        if self.last.contains_key(&peer) {
            return Outcome::TooSoon;
        }
        self.last.insert(peer, now);
        match self.issued.get_mut(nonce) {
            Some(i) => {
                if i.seen.is_none() {
                    i.seen = Some(Seen { when: now, source });
                }
                Outcome::Recorded
            }
            None => {
                if now - self.hour_start >= HOUR_MS {
                    self.hour_start = now;
                    self.unknown = 0;
                }
                self.unknown = self.unknown.saturating_add(1);
                Outcome::Unknown {
                    log: self.unknown == UNKNOWN_LOGGED_AT,
                }
            }
        }
    }

    /// A nonce the hub issued and still keeps: whether it was seen (`None`: not known).
    pub fn lookup(&mut self, nonce: &str, now: i64) -> Option<Option<Seen>> {
        self.prune(now);
        self.issued.get(nonce).map(|i| i.seen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 20);

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Acceptance tests 56 and 58, the part that needs addresses a test can't send from.
    #[test]
    fn the_source_is_home_tunnel_or_this_computer() {
        // a phone on the Wi-Fi: home, with or without the header (58: ignored there)
        for cf in [false, true] {
            assert_eq!(
                source(ip("192.168.1.31"), Arrived::Home, cf, Some(HOME)),
                Source::Home
            );
        }
        assert_eq!(
            source(ip("10.0.0.7"), Arrived::Home, false, Some(HOME)),
            Source::Home
        );
        // the connector on loopback, with the header: the tunnel
        assert_eq!(
            source(ip("127.0.0.1"), Arrived::Loopback, true, Some(HOME)),
            Source::Tunnel
        );
        // loopback without it, or this computer's own address: this computer
        assert_eq!(
            source(ip("127.0.0.1"), Arrived::Loopback, false, Some(HOME)),
            Source::ThisComputer
        );
        assert_eq!(
            source(IpAddr::V4(HOME), Arrived::Home, true, Some(HOME)),
            Source::ThisComputer
        );
        assert_eq!(
            source(ip("::1"), Arrived::Home, false, None),
            Source::ThisComputer
        );
        // a public address on the home listener: neither
        assert_eq!(
            source(ip("203.0.113.9"), Arrived::Home, true, Some(HOME)),
            Source::Outside
        );
    }

    #[test]
    fn a_nonce_is_16_to_64_letters_and_digits() {
        assert!(well_formed(&"a".repeat(16)));
        assert!(well_formed(&"Z9".repeat(32)));
        assert!(!well_formed(&"a".repeat(15)));
        assert!(!well_formed(&"a".repeat(65)));
        assert!(!well_formed("abcdefgh abcdefgh"));
        assert!(!well_formed("abcdefgh-abcdefgh"));
        assert!(!well_formed("abcdefgh%20bcdefgh"));
    }

    #[test]
    fn a_nonce_is_recorded_once_and_kept_for_its_life() {
        let mut p = Probes::default();
        let n = "0123456789abcdef0123";
        let expires = p.issue(n.into(), 1_000, 10);
        assert_eq!(expires, 1_000 + 600_000);
        assert_eq!(p.lookup(n, 2_000), Some(None));
        let peer = ip("192.168.1.31");
        assert_eq!(p.request(n, peer, Source::Home, 3_000), Outcome::Recorded);
        // within a second: refused and not kept (and the first record stays)
        assert_eq!(
            p.request(n, ip("192.168.1.31"), Source::Tunnel, 3_999),
            Outcome::TooSoon
        );
        let seen = Seen {
            when: 3_000,
            source: Source::Home,
        };
        assert_eq!(p.lookup(n, 4_000), Some(Some(seen)));
        // a second later it is fine again; the first sighting is what is kept
        assert_eq!(p.request(n, peer, Source::Tunnel, 4_000), Outcome::Recorded);
        assert_eq!(p.lookup(n, 5_000), Some(Some(seen)));
        // gone after its life
        assert_eq!(p.lookup(n, 1_000 + 600_000), None);
    }

    #[test]
    fn unknown_and_badly_shaped_nonces_keep_nothing() {
        let mut p = Probes::default();
        let peer = ip("192.168.1.31");
        assert_eq!(
            p.request("short", peer, Source::Home, 0),
            Outcome::NotANonce
        );
        // a bad shape doesn't use up the address's second
        let unknown = "ffffffffffffffffffff";
        assert_eq!(
            p.request(unknown, peer, Source::Home, 1),
            Outcome::Unknown { log: false }
        );
        assert_eq!(p.lookup(unknown, 2), None);
        // a thousand in an hour: logged once
        let mut logged = 0;
        for i in 0..1_500i64 {
            let peer = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i as u32));
            if let Outcome::Unknown { log: true } = p.request(unknown, peer, Source::Home, 10 + i) {
                logged += 1;
            }
        }
        assert_eq!(logged, 1);
        // a new hour starts the count again
        let mut again = false;
        for i in 0..1_000i64 {
            let peer = IpAddr::V4(Ipv4Addr::from(0x0b00_0000 + i as u32));
            if let Outcome::Unknown { log: true } =
                p.request(unknown, peer, Source::Home, HOUR_MS + 100 + i)
            {
                again = true;
            }
        }
        assert!(again);
    }
}
