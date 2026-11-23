//! The backend's side: is this request from the hub, and from whom?
//!
//! The hub removes every `Keep-` header a phone sends and adds its own (the spec, "How a
//! request travels"). `Keep-Hub-Auth` shows the request came from the hub. On `/api/...`
//! requests the hub also says who sent it. A backend refuses anything without the right
//! `Keep-Hub-Auth`, and listens on 127.0.0.1 only.
//!
//! - **Protocol 2** (Revision 5 A): the hub opens each connection with a hello,
//!   `GET /_keep-hub/hello` with its challenge. [`HubAuth::hello`] answers it with this
//!   backend's proof that it holds the shared secret and a challenge of its own; the request
//!   that follows on the same connection carries `Keep-Hub-Auth: 2 <proof>`, the hub's proof
//!   for that challenge, which [`HubAuth::check_from`] accepts once, on that connection only.
//!   The secret itself never crosses the connection.
//! - **Protocol 1**: `Keep-Hub-Auth` carries the secret itself ([`HubAuth::check`]).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ring::hmac;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::client::HubError;

/// The path of the hub's hello (protocol 2).
pub const HELLO_PATH: &str = "/_keep-hub/hello";
/// The hello's challenge, both ways: 32 random bytes in hexadecimal.
pub const CHALLENGE: &str = "Keep-Hub-Challenge";
/// The backend's proof, in its answer to the hello.
pub const PROOF: &str = "Keep-Hub-Proof";
/// What the backend's proof is made of, before the hub's challenge.
const APP_PROOF: &str = "keep-hub app proof 2\n";
/// What the hub's proof is made of, before the backend's challenge.
const HUB_PROOF: &str = "keep-hub hub proof 2\n";
/// How long a challenge this backend gave waits for the hub's request.
const CHALLENGE_LIFE: Duration = Duration::from_secs(30);
/// Challenges waiting at once (the oldest goes first).
const MAX_CHALLENGES: usize = 256;

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

/// The shared secret, for checking requests: as its SHA-256 (protocol 1) and as an HMAC
/// key (protocol 2), so it is compared without timing hints and never printed. Clones share
/// the challenges given on open connections.
#[derive(Clone)]
pub struct HubAuth {
    digest: [u8; 32],
    key: hmac::Key,
    protocol: u32,
    /// The challenge given on each open connection from the hub, by its address.
    given: Arc<Mutex<HashMap<SocketAddr, (String, Instant)>>>,
}

impl std::fmt::Debug for HubAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HubAuth(protocol {}, ..)", self.protocol)
    }
}

fn digest(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// The answer to the hub's hello: send `status` with these headers and no body, and keep
/// the connection open for the request that follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
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

/// A challenge as the hub and the library make them: 32 bytes in hexadecimal.
fn is_challenge(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// 32 random bytes in hexadecimal, from the operating system (as the hub's own).
fn new_challenge() -> Option<String> {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 32];
    ring::rand::SystemRandom::new().fill(&mut b).ok()?;
    Some(hex(&b))
}

impl HubAuth {
    /// The secret the hub gave at registration, for an app registered with protocol 1.
    pub fn new(secret: &str) -> HubAuth {
        Self::with_protocol(secret, 1)
    }

    /// The secret the hub gave, for an app registered with `protocol`. From protocol 2 the
    /// secret itself is refused in `Keep-Hub-Auth`: only a proof on its own connection
    /// counts.
    pub fn with_protocol(secret: &str, protocol: u32) -> HubAuth {
        HubAuth {
            digest: digest(secret.as_bytes()),
            key: hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes()),
            protocol,
            given: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The secret [`crate::ensure_registered`] kept in the app's data folder, sealed for
    /// this computer, with the protocol it was registered with. The backend calls this at
    /// start; it doesn't contact the hub.
    pub fn load(app_data: &Path) -> Result<HubAuth, HubError> {
        let secret: Zeroizing<String> = crate::register::read_secret(app_data)?;
        let protocol = crate::register::registered_protocol(app_data);
        Ok(HubAuth::with_protocol(&secret, protocol))
    }

    /// The protocol the app was registered with.
    pub fn protocol(&self) -> u32 {
        self.protocol
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

    /// For every request, first (protocol 2): `None` when it isn't the hub's hello, and
    /// the request goes on to [`Self::check_from`]. `Some(Ok)`: the answer to send, keeping
    /// the connection open. `Some(Err)`: a hello that isn't the hub's; answer the refusal.
    /// `peer` is the connection's remote address, as the server gives it.
    pub fn hello<I>(
        &self,
        peer: SocketAddr,
        path: &str,
        headers: I,
    ) -> Option<Result<Hello, Refused>>
    where
        I: IntoIterator,
        I::Item: Header,
    {
        if path.split('?').next() != Some(HELLO_PATH) {
            return None;
        }
        let h = Headers::collect(headers);
        let theirs = match h.one(CHALLENGE) {
            Ok(Some(c)) if is_challenge(c) => c.to_ascii_lowercase(),
            _ => return Some(Err(NOT_FROM_HUB)),
        };
        let Some(mine) = new_challenge() else {
            return Some(Err(NOT_FROM_HUB));
        };
        let proof = hmac::sign(&self.key, format!("{APP_PROOF}{theirs}").as_bytes());
        if let Ok(mut given) = self.given.lock() {
            let now = Instant::now();
            given.retain(|_, (_, at)| now.duration_since(*at) < CHALLENGE_LIFE);
            while given.len() >= MAX_CHALLENGES {
                let Some(oldest) = given.iter().min_by_key(|(_, (_, at))| *at).map(|(k, _)| *k)
                else {
                    break;
                };
                given.remove(&oldest);
            }
            given.insert(peer, (mine.clone(), now));
        }
        Some(Ok(Hello {
            status: 204,
            headers: vec![
                (PROOF, hex(proof.as_ref())),
                (CHALLENGE, mine),
                ("Connection", "keep-alive".into()),
            ],
        }))
    }

    /// Check a request's headers (names in any case), from the connection at `peer`.
    /// `Ok(Some)`: an `/api/` request with the phone's identity. `Ok(None)`: from the hub
    /// without one (the web client's files). `Err`: not from the hub, or an identity that
    /// can't be read. In protocol 2 the hub's proof is for the challenge this backend gave
    /// on that connection ([`Self::hello`]), and it counts once.
    pub fn check_from<I>(&self, peer: SocketAddr, headers: I) -> Result<Option<Caller>, Refused>
    where
        I: IntoIterator,
        I::Item: Header,
    {
        let h = Headers::collect(headers);
        if self.protocol < 2 {
            return self.checked(h, |v| self.matches(v));
        }
        // the challenge is used up whatever the request carries
        let given = self
            .given
            .lock()
            .ok()
            .and_then(|mut g| g.remove(&peer))
            .filter(|(_, at)| at.elapsed() < CHALLENGE_LIFE);
        self.checked(h, |v| {
            let Some((challenge, _)) = &given else {
                return false;
            };
            let Some(proof) = v.strip_prefix("2 ").and_then(|p| unhex(p.trim())) else {
                return false;
            };
            hmac::verify(
                &self.key,
                format!("{HUB_PROOF}{challenge}").as_bytes(),
                &proof,
            )
            .is_ok()
        })
    }

    /// As [`Self::check_from`], for a request that needs a phone (`/api/...`).
    pub fn caller_from<I>(&self, peer: SocketAddr, headers: I) -> Result<Caller, Refused>
    where
        I: IntoIterator,
        I::Item: Header,
    {
        self.check_from(peer, headers)?.ok_or(NOT_PAIRED)
    }

    /// Check a request's headers, for an app registered with protocol 1 (the secret in
    /// `Keep-Hub-Auth`). An app registered with protocol 2 uses [`Self::check_from`]: here
    /// every request is refused, since the hub never sends it the secret.
    pub fn check<I>(&self, headers: I) -> Result<Option<Caller>, Refused>
    where
        I: IntoIterator,
        I::Item: Header,
    {
        let h = Headers::collect(headers);
        self.checked(h, |v| self.protocol < 2 && self.matches(v))
    }

    /// As [`Self::check`], for a request that needs a phone (`/api/...`).
    pub fn caller<I>(&self, headers: I) -> Result<Caller, Refused>
    where
        I: IntoIterator,
        I::Item: Header,
    {
        self.check(headers)?.ok_or(NOT_PAIRED)
    }

    /// The headers, once `Keep-Hub-Auth` (exactly one) passes `from_hub`.
    fn checked(
        &self,
        h: Headers,
        from_hub: impl Fn(&str) -> bool,
    ) -> Result<Option<Caller>, Refused> {
        let mut auth = h.all(HUB_AUTH);
        match (auth.next(), auth.next()) {
            (Some(v), None) if from_hub(v) => {}
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
}

/// The hub's side of protocol 2, for the hub's own tests and for anyone checking a backend:
/// the backend's proof for a challenge, and the hub's.
pub mod proofs {
    use ring::hmac;

    fn sign(secret: &str, text: &str) -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        super::hex(hmac::sign(&key, text.as_bytes()).as_ref())
    }

    /// What a backend holding `secret` answers to the hub's `challenge`.
    pub fn app(secret: &str, challenge: &str) -> String {
        sign(secret, &format!("{}{challenge}", super::APP_PROOF))
    }

    /// What the hub sends in `Keep-Hub-Auth` (after `2 `) for the backend's `challenge`.
    pub fn hub(secret: &str, challenge: &str) -> String {
        sign(secret, &format!("{}{challenge}", super::HUB_PROOF))
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

    fn challenge_of(h: &Hello) -> String {
        h.headers
            .iter()
            .find(|(k, _)| *k == CHALLENGE)
            .map(|(_, v)| v.clone())
            .unwrap()
    }

    /// Protocol 2: the backend's answer to the hello proves the secret for the hub's own
    /// challenge, and holds a fresh challenge of its own.
    #[test]
    fn the_hello_is_answered_with_a_proof_and_a_challenge() {
        let a = HubAuth::with_protocol(SECRET, 2);
        let peer: SocketAddr = "127.0.0.1:50001".parse().unwrap();
        let theirs = "ab".repeat(32);
        let none: [(&str, &str); 0] = [];
        assert!(a.hello(peer, "/api/items", none).is_none(), "not a hello");
        let h = a
            .hello(peer, HELLO_PATH, [(CHALLENGE, theirs.as_str())])
            .unwrap()
            .unwrap();
        assert_eq!(h.status, 204);
        let proof = h
            .headers
            .iter()
            .find(|(k, _)| *k == PROOF)
            .unwrap()
            .1
            .clone();
        assert_eq!(proof, proofs::app(SECRET, &theirs));
        assert!(is_challenge(&challenge_of(&h)));
        assert!(!format!("{h:?}").contains(SECRET));
        // a hello without a proper challenge isn't the hub's
        assert_eq!(
            a.hello(peer, HELLO_PATH, [(CHALLENGE, "short")]),
            Some(Err(NOT_FROM_HUB))
        );
    }

    /// Acceptance test 67: the hub's proof counts only on the connection whose challenge it
    /// answers, and only once; and a protocol 2 backend refuses the secret itself.
    #[test]
    fn at67_a_proof_counts_once_on_its_own_connection() {
        let a = HubAuth::with_protocol(SECRET, 2);
        let one: SocketAddr = "127.0.0.1:50001".parse().unwrap();
        let two: SocketAddr = "127.0.0.1:50002".parse().unwrap();
        let theirs = "cd".repeat(32);
        let h1 = a
            .hello(one, HELLO_PATH, [(CHALLENGE, theirs.as_str())])
            .unwrap()
            .unwrap();
        let h2 = a
            .hello(two, HELLO_PATH, [(CHALLENGE, theirs.as_str())])
            .unwrap()
            .unwrap();
        let for_one = format!("2 {}", proofs::hub(SECRET, &challenge_of(&h1)));
        let for_two = format!("2 {}", proofs::hub(SECRET, &challenge_of(&h2)));
        // the proof for connection one, sent on connection two
        assert_eq!(
            a.check_from(two, [(HUB_AUTH, for_one.as_str())]),
            Err(NOT_FROM_HUB)
        );
        // connection two's challenge was used up by that try
        assert_eq!(
            a.check_from(two, [(HUB_AUTH, for_two.as_str())]),
            Err(NOT_FROM_HUB)
        );
        // on its own connection it passes, once
        assert_eq!(a.check_from(one, [(HUB_AUTH, for_one.as_str())]), Ok(None));
        assert_eq!(
            a.check_from(one, [(HUB_AUTH, for_one.as_str())]),
            Err(NOT_FROM_HUB)
        );
        // the secret itself is no longer enough, on any path
        let h = a
            .hello(one, HELLO_PATH, [(CHALLENGE, theirs.as_str())])
            .unwrap()
            .unwrap();
        let _ = h;
        assert_eq!(a.check_from(one, [(HUB_AUTH, SECRET)]), Err(NOT_FROM_HUB));
        assert_eq!(a.check([(HUB_AUTH, SECRET)]), Err(NOT_FROM_HUB));
        // and a clone shares the connections' challenges (a server's threads)
        let b = a.clone();
        let h = a
            .hello(one, HELLO_PATH, [(CHALLENGE, theirs.as_str())])
            .unwrap()
            .unwrap();
        let proof = format!("2 {}", proofs::hub(SECRET, &challenge_of(&h)));
        assert_eq!(b.check_from(one, [(HUB_AUTH, proof.as_str())]), Ok(None));
    }

    /// A protocol 1 backend checks the secret itself, as before, with or without a peer.
    #[test]
    fn protocol_1_checks_the_secret() {
        let a = auth();
        let peer: SocketAddr = "127.0.0.1:50003".parse().unwrap();
        assert_eq!(a.protocol(), 1);
        assert_eq!(a.check_from(peer, [(HUB_AUTH, SECRET)]), Ok(None));
        assert_eq!(a.check([(HUB_AUTH, SECRET)]), Ok(None));
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
