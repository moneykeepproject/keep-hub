//! The hub's ACME client (RFC 8555), for one certificate for its own name with the DNS
//! challenge (section 8.4). Written for the hub (owner decision 2026-11-18) rather than
//! taken from a crate: synchronous like the rest of the hub, signing with ring (already in
//! the build through rustls) and making the request with rcgen.
//!
//! The account key is ECDSA P-256; requests are JWS with `ES256` (RFC 7515, RFC 7518
//! section 3.4), the account's key given as a JWK (RFC 7517) until the account has its URL.

use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::client::{Http, Response};

/// Let's Encrypt's directories (`names.acme`; `names.staging` picks the second).
pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

const PROBLEM: &str = "urn:ietf:params:acme:error:";

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Why an ACME step failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcmeError {
    /// Let's Encrypt's limit: try again after this many seconds, if it said.
    RateLimited {
        retry_after: Option<u64>,
        detail: String,
    },
    /// The certificate authority refused, with its problem type (RFC 8555 section 6.7).
    Refused { kind: String, detail: String },
    /// No answer, or one that can't be read.
    Unreachable(String),
}

impl std::fmt::Display for AcmeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcmeError::RateLimited { detail, .. } => {
                write!(f, "Let's Encrypt's limit was reached: {detail}")
            }
            AcmeError::Refused { detail, .. } => write!(f, "Let's Encrypt refused: {detail}"),
            AcmeError::Unreachable(e) => write!(f, "Let's Encrypt can't be reached: {e}"),
        }
    }
}

/// A new account key (PKCS#8), kept sealed by the hub.
pub fn new_account_key() -> Result<Zeroizing<Vec<u8>>, String> {
    let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
        .map_err(|_| "an account key can't be made".to_string())?;
    Ok(Zeroizing::new(doc.as_ref().to_vec()))
}

/// The JWK of an uncompressed P-256 point (`04 || x || y`).
fn jwk(point: &[u8]) -> Option<Value> {
    let (x, y) = (point.get(1..33)?, point.get(33..65)?);
    Some(json!({ "crv": "P-256", "kty": "EC", "x": b64(x), "y": b64(y) }))
}

/// The JWK thumbprint (RFC 7638): SHA-256 of the required members in lexical order.
pub fn thumbprint(jwk: &Value) -> String {
    let text = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        jwk["crv"].as_str().unwrap_or(""),
        jwk["kty"].as_str().unwrap_or(""),
        jwk["x"].as_str().unwrap_or(""),
        jwk["y"].as_str().unwrap_or("")
    );
    b64(&Sha256::digest(text.as_bytes()))
}

/// The TXT value for a DNS challenge (RFC 8555 section 8.4): base64url of the SHA-256 of
/// the key authorization, 43 characters.
pub fn dns_proof(token: &str, thumbprint: &str) -> String {
    b64(&Sha256::digest(format!("{token}.{thumbprint}").as_bytes()))
}

/// An order for a certificate (RFC 8555 section 7.1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Order {
    pub url: String,
    pub status: String,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
}

impl Order {
    fn from(url: String, v: &Value) -> Result<Order, AcmeError> {
        let s = |k: &str| v[k].as_str().map(str::to_string);
        Ok(Order {
            url,
            status: s("status").unwrap_or_default(),
            authorizations: v["authorizations"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
            finalize: s("finalize").ok_or_else(|| unreadable("the order"))?,
            certificate: s("certificate"),
        })
    }
}

/// A DNS challenge to answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub url: String,
    pub status: String,
    /// The value for `_acme-challenge.<name>`.
    pub proof: String,
}

fn unreadable(what: &str) -> AcmeError {
    AcmeError::Unreachable(format!("{what} from Let's Encrypt can't be read"))
}

/// A conversation with the certificate authority, as one account.
pub struct Acme<'a> {
    http: &'a dyn Http,
    directory_url: String,
    new_nonce: String,
    new_account: String,
    new_order: String,
    nonce: Option<String>,
    key: EcdsaKeyPair,
    rng: SystemRandom,
    jwk: Value,
    /// The account's URL, once known.
    pub kid: Option<String>,
}

impl<'a> Acme<'a> {
    /// Read the directory, with the account key (PKCS#8) and its URL if known.
    pub fn new(
        http: &'a dyn Http,
        directory_url: &str,
        account_key: &[u8],
        kid: Option<String>,
    ) -> Result<Acme<'a>, AcmeError> {
        let rng = SystemRandom::new();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, account_key, &rng)
            .map_err(|_| AcmeError::Unreachable("the account key is damaged".into()))?;
        let jwk = jwk(key.public_key().as_ref()).ok_or_else(|| unreadable("the key"))?;
        let r = http
            .send("GET", directory_url, &[], None)
            .map_err(AcmeError::Unreachable)?;
        let d = r
            .json()
            .filter(|_| r.status == 200)
            .ok_or_else(|| unreadable("the directory"))?;
        let url = |k: &str| {
            d[k].as_str()
                .map(str::to_string)
                .ok_or_else(|| unreadable("the directory"))
        };
        Ok(Acme {
            http,
            directory_url: directory_url.to_string(),
            new_nonce: url("newNonce")?,
            new_account: url("newAccount")?,
            new_order: url("newOrder")?,
            nonce: None,
            key,
            rng,
            jwk,
            kid,
        })
    }

    pub fn directory_url(&self) -> &str {
        &self.directory_url
    }

    /// The thumbprint of the account key.
    pub fn thumbprint(&self) -> String {
        thumbprint(&self.jwk)
    }

    fn fresh_nonce(&mut self) -> Result<String, AcmeError> {
        if let Some(n) = self.nonce.take() {
            return Ok(n);
        }
        let r = self
            .http
            .send("HEAD", &self.new_nonce, &[], None)
            .map_err(AcmeError::Unreachable)?;
        r.header("replay-nonce")
            .map(str::to_string)
            .ok_or_else(|| unreadable("a nonce"))
    }

    /// A signed POST; `payload` `None` is POST-as-GET (section 6.3). A bad nonce is tried
    /// once more with a new one (section 6.5).
    fn post(&mut self, url: &str, payload: Option<&Value>) -> Result<Response, AcmeError> {
        let mut tried = false;
        loop {
            let nonce = self.fresh_nonce()?;
            let mut protected = json!({ "alg": "ES256", "nonce": nonce, "url": url });
            match &self.kid {
                Some(kid) => protected["kid"] = json!(kid),
                None => protected["jwk"] = self.jwk.clone(),
            }
            let protected = b64(protected.to_string().as_bytes());
            let payload = payload
                .map(|p| b64(p.to_string().as_bytes()))
                .unwrap_or_default();
            let sig = self
                .key
                .sign(&self.rng, format!("{protected}.{payload}").as_bytes())
                .map_err(|_| AcmeError::Unreachable("the request can't be signed".into()))?;
            let body = json!({ "protected": protected, "payload": payload, "signature": b64(sig.as_ref()) })
                .to_string();
            let r = self
                .http
                .send(
                    "POST",
                    url,
                    &[("Content-Type", "application/jose+json")],
                    Some(body.as_bytes()),
                )
                .map_err(AcmeError::Unreachable)?;
            self.nonce = r.header("replay-nonce").map(str::to_string);
            if r.status < 400 {
                return Ok(r);
            }
            let problem = r.json().unwrap_or(Value::Null);
            let kind = problem["type"]
                .as_str()
                .unwrap_or("")
                .strip_prefix(PROBLEM)
                .unwrap_or("")
                .to_string();
            let detail = problem["detail"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| format!("status {}", r.status));
            if kind == "badNonce" && !tried {
                tried = true;
                continue;
            }
            if kind == "rateLimited" {
                return Err(AcmeError::RateLimited {
                    retry_after: r.retry_after(),
                    detail,
                });
            }
            return Err(AcmeError::Refused { kind, detail });
        }
    }

    fn post_json(
        &mut self,
        url: &str,
        payload: Option<&Value>,
    ) -> Result<(Response, Value), AcmeError> {
        let r = self.post(url, payload)?;
        let v = r.json().ok_or_else(|| unreadable("an answer"))?;
        Ok((r, v))
    }

    /// Make the account, or find it again by its key (section 7.3). The hub gives no
    /// contact address.
    pub fn account(&mut self) -> Result<String, AcmeError> {
        let url = self.new_account.clone();
        let r = self.post(&url, Some(&json!({ "termsOfServiceAgreed": true })))?;
        let kid = r
            .header("location")
            .map(str::to_string)
            .ok_or_else(|| unreadable("the account"))?;
        self.kid = Some(kid.clone());
        Ok(kid)
    }

    /// Order a certificate for `name` (section 7.4).
    pub fn new_order(&mut self, name: &str) -> Result<Order, AcmeError> {
        let url = self.new_order.clone();
        let payload = json!({ "identifiers": [{ "type": "dns", "value": name }] });
        let (r, v) = self.post_json(&url, Some(&payload))?;
        let at = r
            .header("location")
            .map(str::to_string)
            .ok_or_else(|| unreadable("the order"))?;
        Order::from(at, &v)
    }

    /// The order as it stands now.
    pub fn order(&mut self, url: &str) -> Result<(Order, Option<u64>), AcmeError> {
        let (r, v) = self.post_json(url, None)?;
        Ok((Order::from(url.to_string(), &v)?, r.retry_after()))
    }

    /// The DNS challenge of an authorization, with the proof to publish.
    pub fn dns_challenge(&mut self, authorization: &str) -> Result<(String, Challenge), AcmeError> {
        let (_, v) = self.post_json(authorization, None)?;
        let status = v["status"].as_str().unwrap_or("").to_string();
        let c = v["challenges"]
            .as_array()
            .and_then(|a| a.iter().find(|c| c["type"] == "dns-01"))
            .ok_or_else(|| AcmeError::Refused {
                kind: "noDnsChallenge".into(),
                detail: "no DNS challenge was offered".into(),
            })?;
        let token = c["token"]
            .as_str()
            .ok_or_else(|| unreadable("the challenge"))?;
        Ok((
            status,
            Challenge {
                url: c["url"]
                    .as_str()
                    .ok_or_else(|| unreadable("the challenge"))?
                    .to_string(),
                status: c["status"].as_str().unwrap_or("").to_string(),
                proof: dns_proof(token, &self.thumbprint()),
            },
        ))
    }

    /// Tell the certificate authority the proof is in place (section 7.5.1).
    pub fn respond(&mut self, challenge: &str) -> Result<(), AcmeError> {
        self.post(challenge, Some(&json!({}))).map(|_| ())
    }

    /// An authorization's status, why it failed if it did, and how long to wait.
    pub fn authorization(
        &mut self,
        url: &str,
    ) -> Result<(String, Option<String>, Option<u64>), AcmeError> {
        let (r, v) = self.post_json(url, None)?;
        let why = v["challenges"]
            .as_array()
            .and_then(|a| a.iter().find_map(|c| c["error"]["detail"].as_str()))
            .map(str::to_string);
        Ok((
            v["status"].as_str().unwrap_or("").to_string(),
            why,
            r.retry_after(),
        ))
    }

    /// Send the certificate request (DER) (section 7.4).
    pub fn finalize(&mut self, order: &Order, csr: &[u8]) -> Result<Order, AcmeError> {
        let (_, v) = self.post_json(&order.finalize, Some(&json!({ "csr": b64(csr) })))?;
        Order::from(order.url.clone(), &v)
    }

    /// The certificate chain, PEM (section 7.4.2).
    pub fn certificate(&mut self, url: &str) -> Result<String, AcmeError> {
        let r = self.post(url, None)?;
        String::from_utf8(r.body).map_err(|_| unreadable("the certificate"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_proof_is_43_base64url_characters() {
        let p = dns_proof("evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA", "thumb");
        assert_eq!(p.len(), 43);
        assert!(p
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert_ne!(p, dns_proof("other", "thumb"));
    }

    #[test]
    fn the_thumbprint_uses_the_required_members_in_order() {
        // RFC 7638 section 3.2 builds the input this way; any extra member is left out.
        let k = json!({ "y": "Y", "x": "X", "kty": "EC", "crv": "P-256", "kid": "ignored" });
        let want = b64(&Sha256::digest(
            br#"{"crv":"P-256","kty":"EC","x":"X","y":"Y"}"#,
        ));
        assert_eq!(thumbprint(&k), want);
    }

    #[test]
    fn an_account_key_gives_a_p256_jwk() {
        let pkcs8 = new_account_key().unwrap();
        let rng = SystemRandom::new();
        let k = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8, &rng).unwrap();
        let j = jwk(k.public_key().as_ref()).unwrap();
        assert_eq!(j["crv"], "P-256");
        assert_eq!(j["x"].as_str().unwrap().len(), 43);
        assert_eq!(j["y"].as_str().unwrap().len(), 43);
    }
}
