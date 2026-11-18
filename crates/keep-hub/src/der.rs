//! A small reader for the DER encoding (ITU-T X.690) of the few X.509 fields the hub needs
//! (RFC 5280): a certificate's dates, its public key and its DNS names, and the public key
//! in a certificate request (RFC 2986). It reads; it never checks signatures (rustls does
//! that when it matters).

/// One element: its tag, its contents, everything after it, and its whole encoding.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub value: &'a [u8],
    pub whole: &'a [u8],
}

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;
const BOOLEAN: u8 = 0x01;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
/// `[0]` constructed (a certificate's version; a request's attributes).
const CONTEXT_0: u8 = 0xA0;
/// `[3]` constructed (a certificate's extensions).
const CONTEXT_3: u8 = 0xA3;
/// `dNSName` in a GeneralName (`[2]` primitive).
const DNS_NAME: u8 = 0x82;
/// The subjectAltName extension, 2.5.29.17.
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1D, 0x11];

/// The first element of `input`, and what follows it.
pub fn read(input: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *input.first()?;
    if tag & 0x1F == 0x1F {
        return None; // high tag numbers: never in what the hub reads
    }
    let first = *input.get(1)?;
    let (len, head) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7F);
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for b in input.get(2..2 + n)? {
            len = (len << 8) | usize::from(*b);
        }
        (len, 2 + n)
    };
    let end = head.checked_add(len)?;
    let value = input.get(head..end)?;
    let whole = input.get(..end)?;
    Some((Tlv { tag, value, whole }, input.get(end..)?))
}

/// The element of `input` with tag `tag`, and what follows.
fn expect(input: &[u8], tag: u8) -> Option<(Tlv<'_>, &[u8])> {
    let (t, rest) = read(input)?;
    (t.tag == tag).then_some((t, rest))
}

/// Seconds since 1970 of an X.509 time (UTCTime or GeneralizedTime, `Z` form, RFC 5280
/// section 4.1.2.5).
fn time(t: &Tlv<'_>) -> Option<i64> {
    let s = std::str::from_utf8(t.value).ok()?;
    let s = s.strip_suffix('Z')?;
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (year, rest) = match (t.tag, s.len()) {
        (UTC_TIME, 12) => {
            let yy: i32 = s.get(..2)?.parse().ok()?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, s.get(2..)?)
        }
        (GENERALIZED_TIME, 14) => (s.get(..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    let n = |a: usize| -> Option<u8> { rest.get(a..a + 2)?.parse().ok() };
    let month = time::Month::try_from(n(0)?).ok()?;
    let date = time::Date::from_calendar_date(year, month, n(2)?).ok()?;
    let at = date.with_hms(n(4)?, n(6)?, n(8)?).ok()?;
    Some(at.assume_utc().unix_timestamp())
}

/// What the hub reads from a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    /// Seconds since 1970.
    pub not_before: i64,
    pub not_after: i64,
    /// The whole SubjectPublicKeyInfo, to compare with a key's.
    pub spki: Vec<u8>,
    /// The DNS names in its subjectAltName.
    pub dns_names: Vec<String>,
}

/// Read a certificate (DER).
pub fn cert_info(der: &[u8]) -> Option<CertInfo> {
    let (cert, _) = expect(der, SEQUENCE)?;
    let (tbs, _) = expect(cert.value, SEQUENCE)?;
    let mut rest = tbs.value;
    if rest.first() == Some(&CONTEXT_0) {
        rest = read(rest)?.1; // version
    }
    rest = expect(rest, INTEGER)?.1; // serial number
    rest = expect(rest, SEQUENCE)?.1; // signature algorithm
    rest = expect(rest, SEQUENCE)?.1; // issuer
    let (validity, after) = expect(rest, SEQUENCE)?;
    let (nb, v) = read(validity.value)?;
    let (na, _) = read(v)?;
    rest = expect(after, SEQUENCE)?.1; // subject
    let (spki, mut rest) = expect(rest, SEQUENCE)?;
    let mut dns_names = Vec::new();
    while let Some((t, next)) = read(rest) {
        if t.tag == CONTEXT_3 {
            dns_names = san_dns_names(t.value)?;
        }
        rest = next;
    }
    Some(CertInfo {
        not_before: time(&nb)?,
        not_after: time(&na)?,
        spki: spki.whole.to_vec(),
        dns_names,
    })
}

/// The DNS names of the subjectAltName in an `[3]` extensions block.
fn san_dns_names(block: &[u8]) -> Option<Vec<String>> {
    let (exts, _) = expect(block, SEQUENCE)?;
    let mut rest = exts.value;
    while !rest.is_empty() {
        let (ext, next) = expect(rest, SEQUENCE)?;
        rest = next;
        let (oid, mut inner) = expect(ext.value, OID)?;
        if inner.first() == Some(&BOOLEAN) {
            inner = read(inner)?.1; // critical
        }
        if oid.value != SUBJECT_ALT_NAME {
            continue;
        }
        let (octets, _) = expect(inner, OCTET_STRING)?;
        let (names, _) = expect(octets.value, SEQUENCE)?;
        let mut out = Vec::new();
        let mut n = names.value;
        while !n.is_empty() {
            let (name, next) = read(n)?;
            if name.tag == DNS_NAME {
                out.push(String::from_utf8(name.value.to_vec()).ok()?);
            }
            n = next;
        }
        return Some(out);
    }
    Some(Vec::new())
}

/// The SubjectPublicKeyInfo of a certificate request (DER): the whole element, and the raw
/// public key in its BIT STRING (for an EC key, the point `04 || x || y`).
pub fn csr_public_key(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (req, _) = expect(der, SEQUENCE)?;
    let (info, _) = expect(req.value, SEQUENCE)?;
    let rest = expect(info.value, INTEGER)?.1; // version
    let rest = expect(rest, SEQUENCE)?.1; // subject
    let (spki, _) = expect(rest, SEQUENCE)?;
    let after_alg = expect(spki.value, SEQUENCE)?.1;
    let (bits, _) = expect(after_alg, BIT_STRING)?;
    // the first byte of a BIT STRING counts the unused bits: 0 for a key
    let raw = bits.value.strip_prefix(&[0u8])?;
    Some((spki.whole.to_vec(), raw.to_vec()))
}

/// The DER of every certificate in PEM text, in order.
pub fn pem_certificates(text: &str) -> Vec<Vec<u8>> {
    use base64::Engine;
    let mut out = Vec::new();
    let mut inside: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line == "-----BEGIN CERTIFICATE-----" {
            inside = Some(String::new());
        } else if line == "-----END CERTIFICATE-----" {
            if let Some(b) = inside.take() {
                if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(b) {
                    out.push(der);
                }
            }
        } else if let Some(b) = inside.as_mut() {
            b.push_str(line);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair, PublicKeyData};

    #[test]
    fn a_certificates_dates_key_and_names_are_read() {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = CertificateParams::new(vec![
            "k7m2p9xw4tqa.hub.getmoneykeep.org".to_string(),
            "other.example".to_string(),
        ])
        .unwrap();
        p.not_before = time::OffsetDateTime::from_unix_timestamp(1_795_000_000).unwrap();
        // past 2049: written as GeneralizedTime
        p.not_after = time::OffsetDateTime::from_unix_timestamp(2_600_000_000).unwrap();
        let cert = p.self_signed(&key).unwrap();
        let info = cert_info(cert.der()).unwrap();
        assert_eq!(info.not_before, 1_795_000_000);
        assert_eq!(info.not_after, 2_600_000_000);
        assert_eq!(info.spki, key.subject_public_key_info());
        assert_eq!(
            info.dns_names,
            ["k7m2p9xw4tqa.hub.getmoneykeep.org", "other.example"]
        );
        // in PEM, with a second certificate after it
        let pem = format!("{}\n{}", cert.pem(), cert.pem());
        assert_eq!(pem_certificates(&pem), vec![cert.der().to_vec(); 2]);
    }

    #[test]
    fn a_requests_public_key_is_read() {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let p = CertificateParams::new(vec!["a.example".to_string()]).unwrap();
        let csr = p.serialize_request(&key).unwrap();
        let (spki, raw) = csr_public_key(csr.der()).unwrap();
        assert_eq!(spki, key.subject_public_key_info());
        assert_eq!(raw, key.public_key_raw());
        assert_eq!(raw.len(), 65);
    }

    #[test]
    fn damaged_input_is_refused_without_panicking() {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let p = CertificateParams::new(vec!["a.example".to_string()]).unwrap();
        let der = p.self_signed(&key).unwrap().der().to_vec();
        for cut in 0..der.len() {
            assert_eq!(cert_info(&der[..cut]), None);
        }
        assert_eq!(cert_info(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]), None);
        assert_eq!(csr_public_key(b"junk"), None);
        assert!(pem_certificates("no pem here").is_empty());
    }
}
