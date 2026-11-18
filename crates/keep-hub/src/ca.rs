//! The hub's own certificate authority and the TLS settings of the app ports (copied from
//! ShareKeep's hub, `wifi.rs`, which copied MoneyKeep's capture server).
//!
//! - **The certificate authority (CA)** made on this computer: ECDSA P-256, valid 10
//!   years, "Keep Hub CA (<computer name>)", basicConstraints CA (no intermediates), key
//!   usage certificate signing only, and **name constraints** (RFC 5280 section
//!   4.2.1.10) permitting only the hub's IP address (and the reserved name `invalid`,
//!   RFC 2606, so no DNS name passes) and excluding every IPv6 address, so trusting it on
//!   a phone cannot vouch for any other site.
//! - **The server certificate**: P-256, valid 825 days from one day before issue (small
//!   clock differences), subjectAltName the IP address; renewed by the hub 30 days before
//!   it ends, with the same CA.
//! - **The keys** in the hub's key store ([`crate::keys`]).
//!
//! Stage 1 uses this certificate on every app port, for phones that connect by address.
//! The hub name and its public certificate (stage 3), and the certificate page and the
//! choice between the two certificates by the name asked for (stage 4), are not here yet.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::{Arc, RwLock};

use base64::Engine;
use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints, SanType, SerialNumber,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::keys::KeyStore as Secrets;
use crate::util::{self as store, StoreResult};

pub const CA_CERT_FILE: &str = "hub-ca.crt";
pub const SERVER_CERT_FILE: &str = "hub-server.crt";
pub const INFO_FILE: &str = "hub-ca.json";
/// The names of the two private keys ([`Secrets`]).
pub const CA_KEY: &str = "hub-ca-key";
pub const TLS_KEY: &str = "hub-tls-key";

const DAY: i64 = 86_400;
pub const CA_DAYS: i64 = 3652;
pub const SERVER_DAYS: i64 = 825;
pub const RENEW_DAYS: i64 = 30;
/// The address phones use when they connect by address: the hub computer's IPv4 address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub ip: Ipv4Addr,
}

impl Target {
    /// The host phones open.
    pub fn host(&self) -> String {
        self.ip.to_string()
    }
}

/// An IPv4 address of a private network (RFC 1918) or link-local, as the hub
/// needs.
pub fn check_address(text: &str) -> Result<Ipv4Addr, String> {
    let ip: Ipv4Addr = text.trim().parse().map_err(|_| {
        format!(
            "\"{}\" is not an IPv4 address such as 192.168.1.20.",
            text.trim()
        )
    })?;
    // Loopback addresses serve only this computer (tests, or trying it out).
    if ip.is_private() || ip.is_link_local() || ip.is_loopback() {
        Ok(ip)
    } else {
        Err(format!(
            "{ip} is not a home or office network address (10.x, 172.16–31.x or 192.168.x)."
        ))
    }
}

/// This computer has `ip` (binding a socket to it works only then).
pub fn address_present(ip: Ipv4Addr) -> bool {
    std::net::UdpSocket::bind((ip, 0)).is_ok()
}

/// The computer's name for the CA's name.
pub fn computer_name() -> String {
    let raw = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .unwrap_or_default();
    clean_computer(&raw)
}

fn clean_computer(raw: &str) -> String {
    let c: String = raw
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '))
        .take(40)
        .collect();
    if c.trim().is_empty() {
        "this computer".to_owned()
    } else {
        c.trim().to_owned()
    }
}

/// What was made, kept next to the certificates (public facts only).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Info {
    pub ca_name: String,
    pub address: String,
    pub ca_not_before: i64,
    pub ca_not_after: i64,
    pub cert_not_before: i64,
    pub cert_not_after: i64,
    pub fingerprint: String,
}

/// The CA's SHA-256 fingerprint as 8 groups of 4 upper-case hex digits (its first
/// 128 bits), for comparing by eye with what the phone shows.
pub fn fingerprint(der: &[u8]) -> String {
    let h = Sha256::digest(der);
    h.get(..16)
        .unwrap_or(&[])
        .chunks(2)
        .map(|c| store::hex(c).to_ascii_uppercase())
        .collect::<Vec<_>>()
        .join(" ")
}

fn when(secs: i64) -> Result<time::OffsetDateTime, String> {
    time::OffsetDateTime::from_unix_timestamp(secs).map_err(|e| e.to_string())
}

fn serial() -> StoreResult<SerialNumber> {
    let mut b = store::random::<16>()?;
    if let Some(first) = b.first_mut() {
        *first &= 0x7f;
    }
    Ok(SerialNumber::from_slice(&b))
}

fn rc(e: rcgen::Error) -> String {
    format!("the certificate could not be made: {e}")
}

/// The CA's settings (also rebuilt to sign a renewal: the issuer's name, key
/// identifier method and key usages come from here).
pub fn ca_params(
    ca_name: &str,
    target: &Target,
    not_before: i64,
) -> Result<CertificateParams, String> {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, ca_name);
    dn.push(DnType::OrganizationName, "Keep Hub");
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    p.not_before = when(not_before)?;
    p.not_after = when(not_before.saturating_add(CA_DAYS * DAY))?;
    p.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![
            GeneralSubtree::IpAddress(CidrSubnet::from_v4_prefix(target.ip.octets(), 32)),
            GeneralSubtree::DnsName("invalid".to_owned()),
        ],
        excluded_subtrees: vec![GeneralSubtree::IpAddress(CidrSubnet::from_v6_prefix(
            [0; 16], 0,
        ))],
    });
    Ok(p)
}

/// A new CA: its certificate (DER) and private key (PKCS#8).
pub fn new_ca(
    ca_name: &str,
    target: &Target,
    now: i64,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), String> {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(rc)?;
    let mut p = ca_params(ca_name, target, now - DAY)?;
    p.serial_number = Some(serial()?);
    let cert = p.self_signed(&key).map_err(rc)?;
    Ok((cert.der().to_vec(), Zeroizing::new(key.serialize_der())))
}

/// A new server certificate signed by the CA: its certificate (DER) and private key.
pub fn new_server_cert(
    ca_name: &str,
    ca_target: &Target,
    ca_not_before: i64,
    ca_key: &[u8],
    target: &Target,
    now: i64,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), String> {
    let ca_pair = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(ca_key),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .map_err(rc)?;
    let issuer = Issuer::new(ca_params(ca_name, ca_target, ca_not_before)?, ca_pair);
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(rc)?;
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, target.host());
    p.distinguished_name = dn;
    p.subject_alt_names = vec![SanType::IpAddress(IpAddr::V4(target.ip))];
    p.is_ca = IsCa::ExplicitNoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    p.use_authority_key_identifier_extension = true;
    p.serial_number = Some(serial()?);
    let start = now - DAY;
    p.not_before = when(start)?;
    p.not_after = when(start.saturating_add(SERVER_DAYS * DAY))?;
    let cert = p.signed_by(&key, &issuer).map_err(rc)?;
    Ok((cert.der().to_vec(), Zeroizing::new(key.serialize_der())))
}

/// PEM text of a certificate.
pub fn pem(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// The DER of PEM text (one certificate).
pub fn from_pem(text: &str) -> Option<Vec<u8>> {
    let body: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .concat();
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .ok()
}

/// The certificates and the server key in use.
pub struct Material {
    pub info: Info,
    pub ca_der: Vec<u8>,
    pub cert_der: Vec<u8>,
    pub key: Zeroizing<Vec<u8>>,
    /// A new CA was made by this call.
    pub ca_created: bool,
    /// A new server certificate was made by this call.
    pub renewed: bool,
}

impl std::fmt::Debug for Material {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Material")
            .field("info", &self.info)
            .field("key", &"(hidden)")
            .finish_non_exhaustive()
    }
}

pub fn read_info(dir: &Path) -> Option<Info> {
    std::fs::read(dir.join(INFO_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
}

fn read_cert(dir: &Path, file: &str) -> Option<Vec<u8>> {
    std::fs::read_to_string(dir.join(file))
        .ok()
        .and_then(|t| from_pem(&t))
}

/// Make what is missing for `target` and renew what is due: a new CA when there is
/// none, it ends, or the address (its name constraints) changed; a new server
/// certificate with a new CA, a changed address, or within 30 days of its end.
///
/// Hub setup only (it may make a new certificate authority, which every device must
/// install again); the server itself uses [`ensure_existing`].
pub fn ensure(
    dir: &Path,
    secrets: &Secrets,
    target: &Target,
    computer: &str,
    now: i64,
) -> Result<Material, String> {
    ensure_with(dir, secrets, target, computer, now, true)
}

/// The hub's damaged certificate files, as its status says it.
pub const DAMAGED: &str = "Keep Hub can't start: its certificate files are damaged";

/// What the server uses at start and when renewing: the certificate
/// authority is never replaced here. When `hub-ca.json`, the CA certificate or the CA
/// key can't be read (or they are for another address, or the CA ended), [`DAMAGED`]
/// (with why) and nothing is written; the server certificate is renewed when due.
pub fn ensure_existing(
    dir: &Path,
    secrets: &Secrets,
    target: &Target,
    now: i64,
) -> Result<Material, String> {
    ensure_with(dir, secrets, target, "", now, false)
}

fn ensure_with(
    dir: &Path,
    secrets: &Secrets,
    target: &Target,
    computer: &str,
    now: i64,
    may_make_ca: bool,
) -> Result<Material, String> {
    let old = read_info(dir);
    let ca_key = match secrets.get(CA_KEY) {
        Ok(k) => k,
        // Setup replaces a key that can't be opened; the server never does.
        Err(_) if may_make_ca => None,
        Err(e) => return Err(format!("{DAMAGED} ({e})")),
    };
    let ca_der = read_cert(dir, CA_CERT_FILE);
    let same_place = |i: &Info| i.address == target.ip.to_string();
    let (mut info, ca_der, ca_key, ca_created) = match (old, ca_key, ca_der) {
        (Some(i), Some(k), Some(d)) if same_place(&i) && now < i.ca_not_after - DAY => {
            (i, d, k, false)
        }
        (old, key, der) if !may_make_ca => {
            let why = match (old, key, der) {
                (None, ..) => format!("{INFO_FILE} can't be read"),
                (_, None, _) => "the certificate authority's key is missing".to_owned(),
                (_, _, None) => format!("{CA_CERT_FILE} can't be read"),
                (Some(i), ..) if !same_place(&i) => {
                    format!("the certificate is for {}, not {}", i.address, target.ip)
                }
                _ => "the certificate authority has ended".to_owned(),
            };
            return Err(format!("{DAMAGED} ({why})"));
        }
        _ => {
            let ca_name = format!("Keep Hub CA ({})", clean_computer(computer));
            let (der, key) = new_ca(&ca_name, target, now)?;
            secrets.set(CA_KEY, &key)?;
            store::write_private(&dir.join(CA_CERT_FILE), pem(&der).as_bytes())?;
            let info = Info {
                ca_name,
                address: target.ip.to_string(),
                ca_not_before: now - DAY,
                ca_not_after: now - DAY + CA_DAYS * DAY,
                cert_not_before: 0,
                cert_not_after: 0,
                fingerprint: fingerprint(&der),
            };
            (info, der, key, true)
        }
    };
    let cert = read_cert(dir, SERVER_CERT_FILE);
    // A damaged server key is simply made again (phones trust the CA, not it).
    let tls = secrets.get(TLS_KEY).ok().flatten();
    let due = now >= info.cert_not_after - RENEW_DAYS * DAY;
    let (cert_der, key, renewed) = match (cert, tls) {
        (Some(c), Some(k)) if !ca_created && !due => (c, k, false),
        _ => {
            let ca_target = Target {
                ip: info
                    .address
                    .parse()
                    .map_err(|_| format!("{INFO_FILE} is damaged"))?,
            };
            let (der, key) = new_server_cert(
                &info.ca_name,
                &ca_target,
                info.ca_not_before,
                &ca_key,
                target,
                now,
            )?;
            secrets.set(TLS_KEY, &key)?;
            store::write_private(&dir.join(SERVER_CERT_FILE), pem(&der).as_bytes())?;
            info.cert_not_before = now - DAY;
            info.cert_not_after = now - DAY + SERVER_DAYS * DAY;
            (der, key, true)
        }
    };
    if ca_created || renewed {
        let json = serde_json::to_vec_pretty(&info).map_err(|e| e.to_string())?;
        store::write_private(&dir.join(INFO_FILE), &json)?;
    }
    Ok(Material {
        info,
        ca_der,
        cert_der,
        key,
        ca_created,
        renewed,
    })
}

/// Remove the certificates and keys.
pub fn remove(dir: &Path, secrets: &Secrets) -> Vec<String> {
    let mut done = Vec::new();
    for f in [CA_CERT_FILE, SERVER_CERT_FILE, INFO_FILE] {
        if std::fs::remove_file(dir.join(f)).is_ok() {
            done.push(format!("{f} removed"));
        }
    }
    for k in [CA_KEY, TLS_KEY] {
        if secrets.delete(k).is_ok() {
            done.push(format!("{k} removed"));
        }
    }
    done
}
// ----- the TLS settings -------------------------------------------------------------------------

/// The server certificate in use; a renewal swaps it without dropping phones.
#[derive(Debug)]
pub struct Resolver {
    current: RwLock<Arc<rustls::sign::CertifiedKey>>,
}

fn certified(m: &Material) -> Result<Arc<rustls::sign::CertifiedKey>, String> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(m.key.to_vec()));
    let signer = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| format!("the server key cannot be used: {e}"))?;
    Ok(Arc::new(rustls::sign::CertifiedKey::new(
        vec![CertificateDer::from(m.cert_der.clone())],
        signer,
    )))
}

impl Resolver {
    pub fn new(m: &Material) -> Result<Self, String> {
        Ok(Self {
            current: RwLock::new(certified(m)?),
        })
    }
    pub fn set(&self, m: &Material) -> Result<(), String> {
        let c = certified(m)?;
        if let Ok(mut cur) = self.current.write() {
            *cur = c;
        }
        Ok(())
    }
}

impl rustls::server::ResolvesServerCert for Resolver {
    fn resolve(
        &self,
        _hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.current.read().ok().map(|c| c.clone())
    }
}

/// The TLS settings of the app ports.
pub fn server_config(resolver: Arc<Resolver>) -> Result<Arc<rustls::ServerConfig>, String> {
    let mut c = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_no_client_auth()
    .with_cert_resolver(resolver);
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(c))
}
