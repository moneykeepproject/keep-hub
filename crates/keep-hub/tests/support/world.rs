//! The world outside the hub, faked: the name service, an ACME server and DNS. Nothing
//! here touches the network.
//!
//! - **The name service** follows `name-service.md`: Register with a code, Set address,
//!   Set proof, Clear proof, its tokens and errors. Its records are the "public DNS".
//! - **The ACME server** follows RFC 8555 for the DNS challenge, strictly enough to check
//!   the hub: every request's nonce, URL and ES256 signature are checked against the
//!   account's key, the proof must be in the name service's TXT record, and the
//!   certificate is issued for the public key in the hub's request, by a test CA.
//! - **DNS**: the public view is the name service's records; the home view is chosen by
//!   the test (the same, a router that refuses the name, or another address).
//!
//! The ACME server answers on `https://acme.test/` and on Let's Encrypt's two directory
//! addresses (only to see which one the hub asked for).

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use keep_hub::client::{Http, Response};
use keep_hub::dns::{Kind, Lookup};
use keep_hub::names::Outside;
use rcgen::{CertificateParams, Issuer, KeyPair, PublicKeyData, SignatureAlgorithm};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const SERVICE: &str = "https://names.test/v1";
pub const ACME_DIR: &str = "https://acme.test/directory";
pub const HUB_DOMAIN: &str = "hub-test.getmoneykeep.org";
pub const CODE: &str = "ABCD-EFGH-JKLM-NPQR";

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn unb64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap_or_default()
}

fn answer(status: u16, headers: &[(&str, String)], body: Vec<u8>) -> Response {
    Response {
        status,
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect(),
        body,
    }
}

fn json_answer(status: u16, v: Value) -> Response {
    answer(
        status,
        &[("Content-Type", "application/json".into())],
        v.to_string().into_bytes(),
    )
}

/// What this computer's own resolver says about the hub's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Home {
    /// What public DNS says.
    SameAsPublic,
    /// Nothing: a router with DNS rebinding protection.
    Refuses,
    /// Another address.
    Other(Ipv4Addr),
}

#[derive(Default)]
pub struct NameServiceState {
    /// Unused registration codes, as typed without dashes, upper case.
    pub codes: Vec<String>,
    /// id → (token, name)
    pub hubs: HashMap<String, (String, String)>,
    /// The A records: name → address.
    pub a: HashMap<String, String>,
    /// The TXT records: record name → value.
    pub txt: HashMap<String, String>,
    pub set_proofs: u32,
    pub registrations: u32,
    /// Every request: "METHOD path".
    pub calls: Vec<String>,
}

struct Order {
    name: String,
    account: String,
    status: String,
    authz: String,
    cert: Option<String>,
}

struct Authz {
    name: String,
    account: String,
    token: String,
    status: String,
    error: Option<String>,
}

pub struct AcmeState {
    nonces: HashSet<String>,
    next: u64,
    /// kid → JWK
    accounts: HashMap<String, Value>,
    orders: HashMap<String, Order>,
    authzs: HashMap<String, Authz>,
    certs: HashMap<String, String>,
    issuer: Issuer<'static, KeyPair>,
    pub ca_pem: String,
    /// newOrder requests received: what the hub's 7-day limit counts.
    pub new_orders: u32,
    pub new_accounts: u32,
    /// Answer newOrder with `rateLimited` and this Retry-After.
    pub rate_limited: Option<u64>,
    /// Find the proof wrong.
    pub fail_validation: bool,
    /// Lifetime of issued certificates.
    pub cert_days: i64,
    /// Directories the hub read.
    pub directories: Vec<String>,
    /// Requests refused for a bad signature, nonce or URL (the hub's mistakes).
    pub bad_requests: Vec<String>,
}

pub struct World {
    pub clock: Arc<AtomicI64>,
    pub ns: Mutex<NameServiceState>,
    pub acme: Mutex<AcmeState>,
    pub home: Mutex<Home>,
    /// No public resolver answers.
    pub public_down: AtomicBool,
    /// Public DNS doesn't show proofs (as if never propagated).
    pub proofs_hidden: AtomicBool,
    /// The name service doesn't answer.
    pub service_down: AtomicBool,
    /// The name service also takes 127.0.0.1 (the test hub's address). The real one, and
    /// this fake by default, take home addresses only.
    pub allow_loopback: AtomicBool,
}

/// A raw P-256 public key, for rcgen to certify.
struct RawKey(Vec<u8>);

impl PublicKeyData for RawKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }
    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl World {
    pub fn new(clock: Arc<AtomicI64>) -> Arc<World> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.distinguished_name
            .push(rcgen::DnType::CommonName, "Fake ACME test CA");
        let ca = p.self_signed(&key).unwrap();
        Arc::new(World {
            clock,
            ns: Mutex::new(NameServiceState {
                codes: vec![CODE.replace('-', "")],
                ..Default::default()
            }),
            acme: Mutex::new(AcmeState {
                nonces: HashSet::new(),
                next: 0,
                accounts: HashMap::new(),
                orders: HashMap::new(),
                authzs: HashMap::new(),
                certs: HashMap::new(),
                issuer: Issuer::new(p, key),
                ca_pem: ca.pem(),
                new_orders: 0,
                new_accounts: 0,
                rate_limited: None,
                fail_validation: false,
                cert_days: 90,
                directories: Vec::new(),
                bad_requests: Vec::new(),
            }),
            home: Mutex::new(Home::SameAsPublic),
            public_down: AtomicBool::new(false),
            proofs_hidden: AtomicBool::new(false),
            service_down: AtomicBool::new(false),
            allow_loopback: AtomicBool::new(false),
        })
    }

    /// The hub's outside: this world, with waiting that moves the clock.
    pub fn outside(self: &Arc<Self>) -> Outside {
        let clock = self.clock.clone();
        Outside {
            http: Arc::new(FakeHttp(self.clone())),
            lookup: Arc::new(FakeLookup(self.clone())),
            wait: Arc::new(move |d: Duration| {
                clock.fetch_add(d.as_millis() as i64, Ordering::SeqCst);
            }),
        }
    }

    /// The certificate authority the fake ACME server issues from (DER), for a phone to trust.
    pub fn acme_ca(&self) -> Vec<u8> {
        keep_hub::der::pem_certificates(&self.acme.lock().unwrap().ca_pem).remove(0)
    }

    pub fn now_s(&self) -> i64 {
        self.clock.load(Ordering::SeqCst) / 1000
    }

    pub fn add_code(&self, code: &str) {
        self.ns
            .lock()
            .unwrap()
            .codes
            .push(code.replace('-', "").to_uppercase());
    }

    // ----- the name service -----------------------------------------------------------------

    fn name_service(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Response {
        let mut ns = self.ns.lock().unwrap();
        ns.calls.push(format!("{method} {path}"));
        let err = |status: u16, code: &str| {
            json_answer(
                status,
                json!({ "error": code, "message": format!("fake: {code}") }),
            )
        };
        let body: Value = body
            .and_then(|b| serde_json::from_slice(b).ok())
            .unwrap_or(Value::Null);
        if method == "POST" && path == "/hubs" {
            let code = body["registration_code"]
                .as_str()
                .unwrap_or("")
                .replace('-', "")
                .to_uppercase();
            let Some(i) = ns.codes.iter().position(|c| *c == code) else {
                return err(403, "bad_code");
            };
            ns.codes.remove(i);
            ns.registrations += 1;
            let id = format!("k7m2p9xw4t{:02}", ns.registrations);
            let name = format!("{id}.{HUB_DOMAIN}");
            let token = b64(&rand_bytes());
            ns.hubs.insert(id.clone(), (token.clone(), name.clone()));
            return json_answer(201, json!({ "id": id, "name": name, "token": token }));
        }
        let token = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .and_then(|(_, v)| v.strip_prefix("Bearer "))
            .unwrap_or("");
        let Some((id, rest)) = path.strip_prefix("/hubs/").and_then(|p| p.split_once('/')) else {
            return err(404, "not_found");
        };
        let Some((_, name)) = ns.hubs.get(id).filter(|(t, _)| t == token).cloned() else {
            return err(401, "unauthorized");
        };
        match (method, rest) {
            ("PUT", "address") => {
                let a = body["address"].as_str().unwrap_or("").to_string();
                let ip: Option<Ipv4Addr> = a.parse().ok();
                let loopback = self.allow_loopback.load(Ordering::SeqCst);
                if !ip.is_some_and(|ip| ip.is_private() || (loopback && ip.is_loopback())) {
                    return err(400, "address_not_private");
                }
                ns.a.insert(name.clone(), a.clone());
                json_answer(200, json!({ "name": name, "address": a, "ttl": 60 }))
            }
            ("PUT", "proof") => {
                let v = body["value"].as_str().unwrap_or("").to_string();
                if v.len() != 43 {
                    return err(400, "proof_invalid");
                }
                ns.set_proofs += 1;
                let record = format!("_acme-challenge.{name}");
                ns.txt.insert(record.clone(), v);
                json_answer(200, json!({ "record": record }))
            }
            ("DELETE", "proof") => {
                ns.txt.remove(&format!("_acme-challenge.{name}"));
                answer(204, &[], Vec::new())
            }
            _ => err(404, "not_found"),
        }
    }

    // ----- the ACME server ------------------------------------------------------------------

    fn acme(&self, method: &str, url: &str, body: Option<&[u8]>) -> Response {
        let mut st = self.acme.lock().unwrap();
        st.next += 1;
        let nonce = format!("nonce-{}", st.next);
        st.nonces.insert(nonce.clone());
        let with_nonce = |mut r: Response, nonce: &str| {
            r.headers.push(("Replay-Nonce".into(), nonce.to_string()));
            r
        };
        let problem = |status: u16, kind: &str, detail: &str| {
            answer(
                status,
                &[("Content-Type", "application/problem+json".into())],
                json!({ "type": format!("urn:ietf:params:acme:error:{kind}"), "detail": detail })
                    .to_string()
                    .into_bytes(),
            )
        };
        let base = "https://acme.test";
        if method == "GET" && url.ends_with("/directory") {
            st.directories.push(url.to_string());
            let d = json!({
                "newNonce": format!("{base}/new-nonce"),
                "newAccount": format!("{base}/new-acct"),
                "newOrder": format!("{base}/new-order"),
            });
            return json_answer(200, d);
        }
        if method == "HEAD" && url == format!("{base}/new-nonce") {
            return with_nonce(answer(200, &[], Vec::new()), &nonce);
        }
        if method != "POST" {
            return problem(405, "malformed", "fake: method");
        }

        // the JWS
        let jws: Value = body
            .and_then(|b| serde_json::from_slice(b).ok())
            .unwrap_or(Value::Null);
        let (p64, pay64, sig64) = (
            jws["protected"].as_str().unwrap_or(""),
            jws["payload"].as_str().unwrap_or(""),
            jws["signature"].as_str().unwrap_or(""),
        );
        let protected: Value = serde_json::from_slice(&unb64(p64)).unwrap_or(Value::Null);
        let bad = |st: &mut AcmeState, why: &str| {
            st.bad_requests.push(why.to_string());
            why.to_string()
        };
        if protected["alg"] != "ES256" {
            let w = bad(&mut st, "alg");
            return with_nonce(problem(400, "malformed", &w), &nonce);
        }
        let used = protected["nonce"].as_str().unwrap_or("").to_string();
        if !st.nonces.remove(&used) {
            // (not a hub mistake when the hub retries: counted apart)
            return with_nonce(problem(400, "badNonce", "fake: nonce"), &nonce);
        }
        if protected["url"].as_str() != Some(url) {
            let w = bad(&mut st, "url");
            return with_nonce(problem(400, "malformed", &w), &nonce);
        }
        let (jwk, kid) = match (protected.get("jwk"), protected["kid"].as_str()) {
            (Some(j), None) if url.ends_with("/new-acct") => (j.clone(), None),
            (None, Some(k)) => match st.accounts.get(k) {
                Some(j) => (j.clone(), Some(k.to_string())),
                None => return with_nonce(problem(400, "accountDoesNotExist", "fake"), &nonce),
            },
            _ => {
                let w = bad(&mut st, "jwk or kid");
                return with_nonce(problem(400, "malformed", &w), &nonce);
            }
        };
        let mut point = vec![4u8];
        point.extend(unb64(jwk["x"].as_str().unwrap_or("")));
        point.extend(unb64(jwk["y"].as_str().unwrap_or("")));
        let key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_FIXED,
            &point,
        );
        if key
            .verify(format!("{p64}.{pay64}").as_bytes(), &unb64(sig64))
            .is_err()
        {
            let w = bad(&mut st, "signature");
            return with_nonce(problem(400, "malformed", &w), &nonce);
        }
        let payload: Option<Value> = if pay64.is_empty() {
            None
        } else {
            serde_json::from_slice(&unb64(pay64)).ok()
        };
        let path = url.strip_prefix(base).unwrap_or("");
        let thumb = keep_hub::acme::thumbprint(&jwk);
        let r = self.acme_route(&mut st, path, kid, &thumb, payload, base);
        with_nonce(r, &nonce)
    }

    fn acme_route(
        &self,
        st: &mut AcmeState,
        path: &str,
        kid: Option<String>,
        thumb: &str,
        payload: Option<Value>,
        base: &str,
    ) -> Response {
        let problem = |status: u16, kind: &str, detail: &str| {
            json_answer(
                status,
                json!({ "type": format!("urn:ietf:params:acme:error:{kind}"), "detail": detail }),
            )
        };
        let located = |status: u16, at: String, v: Value| {
            let mut r = json_answer(status, v);
            r.headers.push(("Location".into(), at));
            r
        };
        let order_json = |o: &Order, id: &str| {
            json!({
                "status": o.status,
                "identifiers": [{ "type": "dns", "value": o.name }],
                "authorizations": [format!("{base}/authz/{}", o.authz)],
                "finalize": format!("{base}/finalize/{id}"),
                "certificate": o.cert.as_ref().map(|c| format!("{base}/cert/{c}")),
            })
        };
        if path == "/new-acct" {
            if payload.as_ref().map(|p| &p["termsOfServiceAgreed"]) != Some(&json!(true)) {
                return problem(400, "malformed", "fake: terms");
            }
            let kid = format!("{base}/acct/{thumb}");
            if st.accounts.contains_key(&kid) {
                return located(200, kid, json!({ "status": "valid" }));
            }
            st.new_accounts += 1;
            // the JWK is the one the request was signed with; find it again from the thumbprint
            return located(201, kid, json!({ "status": "valid" }));
        }
        let Some(kid) = kid else {
            return problem(400, "malformed", "fake: kid needed");
        };
        if path == "/new-order" {
            st.new_orders += 1;
            if let Some(s) = st.rate_limited {
                let mut r = problem(429, "rateLimited", "too many certificates for this name");
                r.headers.push(("Retry-After".into(), s.to_string()));
                return r;
            }
            let name = payload
                .as_ref()
                .and_then(|p| p["identifiers"][0]["value"].as_str())
                .unwrap_or("")
                .to_string();
            st.next += 1;
            let (oid, aid) = (format!("o{}", st.next), format!("a{}", st.next));
            st.authzs.insert(
                aid.clone(),
                Authz {
                    name: name.clone(),
                    account: kid.clone(),
                    token: b64(&rand_bytes()),
                    status: "pending".into(),
                    error: None,
                },
            );
            let o = Order {
                name,
                account: kid,
                status: "pending".into(),
                authz: aid,
                cert: None,
            };
            let v = order_json(&o, &oid);
            st.orders.insert(oid.clone(), o);
            return located(201, format!("{base}/order/{oid}"), v);
        }
        if let Some(aid) = path.strip_prefix("/authz/") {
            let Some(a) = st.authzs.get(aid).filter(|a| a.account == kid) else {
                return problem(404, "malformed", "fake: no authz");
            };
            let mut ch = json!({ "type": "dns-01", "url": format!("{base}/chall/{aid}"), "token": a.token, "status": a.status });
            if let Some(e) = &a.error {
                ch["error"] =
                    json!({ "type": "urn:ietf:params:acme:error:incorrectResponse", "detail": e });
            }
            let other = json!({ "type": "http-01", "url": format!("{base}/chall/http-{aid}"), "token": "x", "status": "pending" });
            return json_answer(
                200,
                json!({ "status": a.status, "identifier": { "type": "dns", "value": a.name }, "challenges": [other, ch] }),
            );
        }
        if let Some(aid) = path.strip_prefix("/chall/") {
            let fail = st.fail_validation;
            let Some(a) = st.authzs.get_mut(aid).filter(|a| a.account == kid) else {
                return problem(404, "malformed", "fake: no challenge");
            };
            let want = b64(&Sha256::digest(format!("{}.{thumb}", a.token).as_bytes()));
            let found = self
                .ns
                .lock()
                .unwrap()
                .txt
                .get(&format!("_acme-challenge.{}", a.name))
                .cloned();
            if !fail && found.as_deref() == Some(want.as_str()) {
                a.status = "valid".into();
            } else {
                a.status = "invalid".into();
                a.error = Some(format!("fake: no matching TXT record (found {found:?})"));
            }
            return json_answer(200, json!({ "type": "dns-01", "status": a.status }));
        }
        if let Some(oid) = path.strip_prefix("/order/") {
            return match st.orders.get(oid).filter(|o| o.account == kid) {
                Some(o) => json_answer(200, order_json(o, oid)),
                None => problem(404, "malformed", "fake: no order"),
            };
        }
        if let Some(oid) = path.strip_prefix("/finalize/") {
            let now = self.now_s();
            let days = st.cert_days;
            let ready = st.orders.get(oid).filter(|o| o.account == kid).map(|o| {
                (
                    o.name.clone(),
                    st.authzs.get(&o.authz).map(|a| a.status.clone()),
                )
            });
            let Some((name, Some(status))) = ready else {
                return problem(404, "malformed", "fake: no order");
            };
            if status != "valid" {
                return problem(403, "orderNotReady", "fake: not authorized");
            }
            let csr = unb64(
                payload
                    .as_ref()
                    .and_then(|p| p["csr"].as_str())
                    .unwrap_or(""),
            );
            let Some((_, raw)) = keep_hub::der::csr_public_key(&csr) else {
                return problem(400, "badCSR", "fake: csr");
            };
            let mut p = CertificateParams::new(vec![name]).unwrap();
            p.not_before = time::OffsetDateTime::from_unix_timestamp(now).unwrap();
            p.not_after = time::OffsetDateTime::from_unix_timestamp(now + days * 86_400).unwrap();
            let cert = p.signed_by(&RawKey(raw), &st.issuer).unwrap();
            let pem = format!("{}{}", cert.pem(), st.ca_pem);
            st.next += 1;
            let cid = format!("c{}", st.next);
            st.certs.insert(cid.clone(), pem);
            let o = st.orders.get_mut(oid).unwrap();
            o.status = "valid".into();
            o.cert = Some(cid);
            let o = st.orders.get(oid).unwrap();
            return json_answer(200, order_json(o, oid));
        }
        if let Some(cid) = path.strip_prefix("/cert/") {
            return match st.certs.get(cid) {
                Some(pem) => answer(
                    200,
                    &[("Content-Type", "application/pem-certificate-chain".into())],
                    pem.clone().into_bytes(),
                ),
                None => problem(404, "malformed", "fake: no cert"),
            };
        }
        problem(404, "malformed", "fake: unknown")
    }
}

fn rand_bytes() -> [u8; 24] {
    let mut b = [0u8; 24];
    getrandom::fill(&mut b).unwrap();
    b
}

struct FakeHttp(Arc<World>);

impl Http for FakeHttp {
    fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<Response, String> {
        let w = &self.0;
        if let Some(path) = url.strip_prefix(SERVICE) {
            if w.service_down.load(Ordering::SeqCst) {
                return Err("fake: the name service can't be reached".into());
            }
            return Ok(w.name_service(method, path, headers, body));
        }
        let acme_hosts = [
            "https://acme.test/",
            "https://acme-v02.api.letsencrypt.org/",
            "https://acme-staging-v02.api.letsencrypt.org/",
        ];
        if acme_hosts.iter().any(|h| url.starts_with(h)) {
            if method == "POST" {
                let ct = headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                    .map(|(_, v)| *v);
                assert_eq!(ct, Some("application/jose+json"), "ACME POSTs are JWS");
            }
            // keep the account's JWK for kid requests
            let r = w.acme(method, url, body);
            if url.ends_with("/new-acct") && r.status < 300 {
                let jws: Value = serde_json::from_slice(body.unwrap_or(&[])).unwrap();
                let p: Value =
                    serde_json::from_slice(&unb64(jws["protected"].as_str().unwrap())).unwrap();
                let kid = r.header("location").unwrap().to_string();
                w.acme
                    .lock()
                    .unwrap()
                    .accounts
                    .insert(kid, p["jwk"].clone());
            }
            return Ok(r);
        }
        Err(format!("fake: nothing at {url}"))
    }
}

struct FakeLookup(Arc<World>);

impl Lookup for FakeLookup {
    fn public(&self, name: &str, kind: Kind) -> Result<Vec<String>, String> {
        let w = &self.0;
        if w.public_down.load(Ordering::SeqCst) {
            return Err("fake: no public resolver answers".into());
        }
        let ns = w.ns.lock().unwrap();
        Ok(match kind {
            Kind::A => ns.a.get(name).cloned().into_iter().collect(),
            Kind::Txt if w.proofs_hidden.load(Ordering::SeqCst) => Vec::new(),
            Kind::Txt => ns.txt.get(name).cloned().into_iter().collect(),
        })
    }

    fn home(&self, name: &str) -> Result<Vec<Ipv4Addr>, String> {
        let w = &self.0;
        Ok(match *w.home.lock().unwrap() {
            Home::SameAsPublic => {
                let ns = w.ns.lock().unwrap();
                ns.a.get(name)
                    .and_then(|a| a.parse().ok())
                    .into_iter()
                    .collect()
            }
            Home::Refuses => Vec::new(),
            Home::Other(ip) => vec![ip],
        })
    }
}
