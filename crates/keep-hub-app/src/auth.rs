//! The backend's side: is this request from the hub, and from whom?
//!
//! The hub removes every `Keep-` header a phone sends and adds its own (the spec, "How a
//! request travels"). `Keep-Hub-Auth` carries the secret the hub and this app share. On
//! `/api/...` requests the hub also says who sent it. A backend refuses anything without
//! the right secret, and listens on 127.0.0.1 only.

use std::net::{Ipv4Addr, TcpListener};
use std::path::Path;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::client::HubError;

/// The headers the hub adds.
pub const HUB_AUTH: &str = "Keep-Hub-Auth";
pub const MEMBER: &str = "Keep-Member";
pub const MEMBER_NAME: &str = "Keep-Member-Name";
pub const DEVICE: &str = "Keep-Device";
pub const DEVICE_NAME: &str = "Keep-Device-Name";
pub const GUEST_SCOPE: &str = "Keep-Guest-Scope";
pub const MEMBER_CLASS: &str = "Keep-Member-Class";
pub const REQUEST_ID: &str = "Keep-Request-Id";

/// Who sent an `/api/` request: a member of the household (or a guest) and one of their
/// paired phones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// The member's id in the hub. An app links its own records to this.
    pub member: u32,
    pub member_name: String,
    /// `administrator`, `standard` or `guest` (`Keep-Member-Class`). The app may use it for
    /// its own rules; the hub doesn't decide what a class may do inside an app. `None` from
    /// an older hub, which didn't send it.
    pub class: Option<String>,
    /// The device's id: this app on one phone.
    pub device: u32,
    pub device_name: String,
    /// Present only for a guest: what the invite was for (the app's own text). The app
    /// limits the guest to it; the hub doesn't interpret it.
    pub guest_scope: Option<String>,
    /// The request id the phone sent, for safe resends.
    pub request_id: Option<String>,
}

impl Caller {
    pub fn is_guest(&self) -> bool {
        self.guest_scope.is_some()
    }

    /// Whether the member is one of the household's administrators.
    pub fn is_administrator(&self) -> bool {
        self.class.as_deref() == Some("administrator")
    }
}

/// Why a request was refused: the status and code to answer with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused {
    pub status: u16,
    pub code: &'static str,
    pub message: &'static str,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for Refused {}

const NOT_FROM_HUB: Refused = Refused {
    status: 403,
    code: "not_from_hub",
    message: "This app answers only requests that come through Keep Hub.",
};

const BAD_IDENTITY: Refused = Refused {
    status: 400,
    code: "bad_identity",
    message: "Keep Hub's description of the phone couldn't be read.",
};

const NOT_PAIRED: Refused = Refused {
    status: 401,
    code: "not_paired",
    message: "This request needs a paired phone.",
};

/// The shared secret, for checking requests. It is held only as its SHA-256, so it is
/// compared without timing hints and never printed.
#[derive(Clone)]
pub struct HubAuth {
    digest: [u8; 32],
}

impl std::fmt::Debug for HubAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HubAuth(..)")
    }
}

fn digest(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

impl HubAuth {
    /// The secret the hub gave at registration.
    pub fn new(secret: &str) -> HubAuth {
        HubAuth {
            digest: digest(secret.as_bytes()),
        }
    }

    /// The secret [`crate::ensure_registered`] kept in the app's data folder, sealed for
    /// this computer. The backend calls this at start; it doesn't contact the hub.
    pub fn load(app_data: &Path) -> Result<HubAuth, HubError> {
        let secret: Zeroizing<String> = crate::register::read_secret(app_data)?;
        Ok(HubAuth::new(&secret))
    }

    /// Whether `value` is the shared secret.
    pub fn matches(&self, value: &str) -> bool {
        let given = digest(value.as_bytes());
        // the same work whatever the bytes
        given
            .iter()
            .zip(self.digest.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }

    /// Check a request's headers (names in any case). `Ok(Some)`: an `/api/` request with
    /// the phone's identity. `Ok(None)`: from the hub without one (the web client's files).
    /// `Err`: not from the hub, or an identity that can't be read.
    pub fn check<I>(&self, headers: I) -> Result<Option<Caller>, Refused>
    where
        I: IntoIterator,
        I::Item: Header,
    {
        let h = Headers::collect(headers);
        let mut auth = h.all(HUB_AUTH);
        match (auth.next(), auth.next()) {
            (Some(v), None) if self.matches(v) => {}
            _ => return Err(NOT_FROM_HUB),
        }
        let Some(member) = h.one(MEMBER)? else {
            // from the hub, without a phone: none of the other identity headers either
            for k in [MEMBER_NAME, MEMBER_CLASS, DEVICE, DEVICE_NAME, GUEST_SCOPE] {
                if h.all(k).next().is_some() {
                    return Err(BAD_IDENTITY);
                }
            }
            return Ok(None);
        };
        let member = member.parse::<u32>().map_err(|_| BAD_IDENTITY)?;
        let device = h
            .one(DEVICE)?
            .ok_or(BAD_IDENTITY)?
            .parse::<u32>()
            .map_err(|_| BAD_IDENTITY)?;
        let name =
            |k| -> Result<String, Refused> { Ok(percent_decode(h.one(k)?.ok_or(BAD_IDENTITY)?)) };
        let class = match h.one(MEMBER_CLASS)? {
            None => None,
            Some(c @ ("administrator" | "standard" | "guest")) => Some(c.to_string()),
            Some(_) => return Err(BAD_IDENTITY),
        };
        Ok(Some(Caller {
            member,
            member_name: name(MEMBER_NAME)?,
            class,
            device,
            device_name: name(DEVICE_NAME)?,
            guest_scope: h.one(GUEST_SCOPE)?.map(str::to_string),
            request_id: h.one(REQUEST_ID)?.map(str::to_string),
        }))
    }

    /// As [`Self::check`], for a request that needs a phone (`/api/...`).
    pub fn caller<I>(&self, headers: I) -> Result<Caller, Refused>
    where
        I: IntoIterator,
        I::Item: Header,
    {
        self.check(headers)?.ok_or(NOT_PAIRED)
    }
}

/// One request header, as a server hands it over: a `(name, value)` pair of strings,
/// owned or borrowed, or a reference to one.
pub trait Header {
    fn name(&self) -> &str;
    fn value(&self) -> &str;
}

impl<K: AsRef<str>, V: AsRef<str>> Header for (K, V) {
    fn name(&self) -> &str {
        self.0.as_ref()
    }
    fn value(&self) -> &str {
        self.1.as_ref()
    }
}

impl<H: Header + ?Sized> Header for &H {
    fn name(&self) -> &str {
        (**self).name()
    }
    fn value(&self) -> &str {
        (**self).value()
    }
}

/// The request's headers, names compared without case.
struct Headers(Vec<(String, String)>);

impl Headers {
    fn collect<I>(headers: I) -> Headers
    where
        I: IntoIterator,
        I::Item: Header,
    {
        Headers(
            headers
                .into_iter()
                .map(|h| (h.name().trim().to_string(), h.value().trim().to_string()))
                .collect(),
        )
    }

    fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.0
            .iter()
            .filter(move |(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// At most one value (the hub sends each once).
    fn one<'a>(&'a self, name: &'a str) -> Result<Option<&'a str>, Refused> {
        let mut it = self.all(name);
        match (it.next(), it.next()) {
            (v, None) => Ok(v),
            _ => Err(BAD_IDENTITY),
        }
    }
}

/// The text a percent-encoded value stands for (bytes that aren't UTF-8 are replaced).
fn percent_decode(s: &str) -> String {
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

/// Bind the app's backend to 127.0.0.1 only (the spec: a backend never listens on the
/// Wi-Fi address; the hub does).
pub fn listen(loopback_port: u16) -> std::io::Result<TcpListener> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, loopback_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "4f1c2d3e4f1c2d3e4f1c2d3e4f1c2d3e4f1c2d3e4f1c2d3e4f1c2d3e4f1c2d3e";

    fn auth() -> HubAuth {
        HubAuth::new(SECRET)
    }

    #[test]
    fn a_request_without_the_right_secret_is_refused() {
        let a = auth();
        let none: [(&str, &str); 0] = [];
        assert_eq!(a.check(none), Err(NOT_FROM_HUB));
        assert_eq!(a.check([("Keep-Hub-Auth", "guess")]), Err(NOT_FROM_HUB));
        assert_eq!(a.check([("Keep-Hub-Auth", "")]), Err(NOT_FROM_HUB));
        let almost = format!("{}0", &SECRET[..SECRET.len() - 1]);
        assert_eq!(
            a.check([("Keep-Hub-Auth", almost.as_str())]),
            Err(NOT_FROM_HUB)
        );
        // twice, even once right
        assert_eq!(
            a.check([("Keep-Hub-Auth", SECRET), ("keep-hub-auth", "guess")]),
            Err(NOT_FROM_HUB)
        );
        // a phone's identity without the secret is refused too
        assert_eq!(
            a.check([("Keep-Member", "1"), ("Keep-Device", "1")]),
            Err(NOT_FROM_HUB)
        );
        assert_eq!(NOT_FROM_HUB.status, 403);
    }

    #[test]
    fn the_secret_from_the_hub_without_a_phone_is_the_web_clients_files() {
        let a = auth();
        assert_eq!(a.check([("keep-hub-auth", SECRET)]), Ok(None));
        assert_eq!(
            a.check([("KEEP-HUB-AUTH", format!(" {SECRET} "))]),
            Ok(None)
        );
        assert_eq!(a.caller([("Keep-Hub-Auth", SECRET)]), Err(NOT_PAIRED));
        // half an identity is not an identity
        assert_eq!(
            a.check([("Keep-Hub-Auth", SECRET), ("Keep-Device", "3")]),
            Err(BAD_IDENTITY)
        );
    }

    #[test]
    fn the_phone_is_read_from_the_hubs_headers() {
        let a = auth();
        let headers = [
            ("Host", "192.168.1.20:16443"),
            ("Keep-Hub-Auth", SECRET),
            ("Keep-Member", "7"),
            ("Keep-Member-Class", "standard"),
            ("Keep-Member-Name", "Zo%C3%AB"),
            ("Keep-Device", "3"),
            ("Keep-Device-Name", "Zo%C3%AB%27s%20phone"),
            ("Keep-Request-Id", "req-42"),
        ];
        let c = a.caller(headers).unwrap();
        assert_eq!(
            c,
            Caller {
                member: 7,
                member_name: "Zoë".into(),
                class: Some("standard".into()),
                device: 3,
                device_name: "Zoë's phone".into(),
                guest_scope: None,
                request_id: Some("req-42".into()),
            }
        );
        assert!(!c.is_guest() && !c.is_administrator());
        let guest = a
            .caller(
                headers
                    .iter()
                    .copied()
                    .chain([("Keep-Guest-Scope", "trip-12")]),
            )
            .unwrap();
        assert_eq!(guest.guest_scope.as_deref(), Some("trip-12"));
        assert!(guest.is_guest());
        // owned headers (as most servers hand them over)
        let owned: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(a.caller(&owned).unwrap().member, 7);
        assert_eq!(a.caller(owned).unwrap().member, 7);
    }

    #[test]
    fn an_identity_that_cant_be_read_is_refused() {
        let a = auth();
        let base = [
            ("Keep-Hub-Auth", SECRET),
            ("Keep-Member-Name", "A"),
            ("Keep-Device-Name", "B"),
        ];
        for bad in [
            vec![("Keep-Member", "x"), ("Keep-Device", "1")],
            vec![("Keep-Member", "1")],
            vec![("Keep-Member", "1"), ("Keep-Device", "-1")],
            vec![
                ("Keep-Member", "1"),
                ("Keep-Member", "2"),
                ("Keep-Device", "1"),
            ],
            // a class the hub never sends
            vec![
                ("Keep-Member", "1"),
                ("Keep-Device", "1"),
                ("Keep-Member-Class", "owner"),
            ],
        ] {
            let all: Vec<(&str, &str)> = base.iter().copied().chain(bad.clone()).collect();
            assert_eq!(a.check(all), Err(BAD_IDENTITY), "{bad:?}");
        }
        // names are needed
        assert_eq!(
            a.check([
                ("Keep-Hub-Auth", SECRET),
                ("Keep-Member", "1"),
                ("Keep-Device", "1")
            ]),
            Err(BAD_IDENTITY)
        );
    }

    #[test]
    fn the_secret_is_never_printed() {
        let a = auth();
        assert!(!format!("{a:?}").contains(&SECRET[..8]));
        assert!(a.matches(SECRET));
        assert!(!a.matches(&SECRET[1..]));
    }

    #[test]
    fn the_backend_listens_on_loopback_only() {
        let l = listen(0).unwrap();
        assert_eq!(l.local_addr().unwrap().ip(), Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn percent_decoding_matches_the_hubs_encoding() {
        assert_eq!(percent_decode("a%20b%2Fc"), "a b/c");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }
}
