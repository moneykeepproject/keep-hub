//! The hub's own requests to the internet: to the name service, to Let's Encrypt and to a
//! public DNS resolver. HTTPS (HTTP/1.1, RFC 9112) over rustls with ring, one request per
//! connection.
//!
//! Every outside request goes through [`Http`], so tests put fakes behind it and no test
//! needs the network. [`HttpsClient::system`] trusts what this computer trusts
//! (rustls-platform-verifier: Windows' and macOS's own certificate checks).

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName};

/// The largest answer the hub reads (a certificate chain is a few KB).
const MAX_ANSWER: usize = 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);

/// An answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.body).ok()
    }

    /// `Retry-After` in seconds (RFC 9110 section 10.2.3; the date form isn't read).
    pub fn retry_after(&self) -> Option<u64> {
        self.header("retry-after")?.trim().parse().ok()
    }
}

/// Where the hub's outside requests go.
pub trait Http: Send + Sync {
    /// One request; `Err` when no answer came (no connection, a broken one, a timeout).
    fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<Response, String>;
}

/// The parts of an `https://` address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub host: String,
    pub port: u16,
    /// The path and query, starting with `/`.
    pub target: String,
}

impl Url {
    pub fn parse(url: &str) -> Result<Url, String> {
        let bad = || format!("\"{url}\" isn't an https:// address");
        let rest = url.strip_prefix("https://").ok_or_else(bad)?;
        let (authority, target) = match rest.find(['/', '?']) {
            Some(i) => (
                rest.get(..i).ok_or_else(bad)?,
                rest.get(i..).ok_or_else(bad)?,
            ),
            None => (rest, "/"),
        };
        let target = if target.starts_with('?') {
            format!("/{target}")
        } else {
            target.to_string()
        };
        if authority.is_empty() || authority.contains(['@', '[', ' ']) {
            return Err(bad());
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().map_err(|_| bad())?),
            None => (authority, 443),
        };
        if host.is_empty() || target.bytes().any(|b| b <= b' ') {
            return Err(bad());
        }
        Ok(Url {
            host: host.to_ascii_lowercase(),
            port,
            target,
        })
    }
}

/// HTTPS from this computer.
#[derive(Debug, Clone)]
pub struct HttpsClient {
    config: Arc<rustls::ClientConfig>,
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

impl HttpsClient {
    /// Trusting what this computer trusts.
    pub fn system() -> Result<HttpsClient, String> {
        let provider = provider();
        let verifier = rustls_platform_verifier::Verifier::new(provider.clone())
            .map_err(|e| format!("this computer's certificate checks can't be used: {e}"))?;
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .dangerous() // (the platform verifier is a full verifier, not a shortcut)
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        Ok(Self::with_config(config))
    }

    /// Trusting only these certificate authorities (tests).
    pub fn with_roots(roots: &[Vec<u8>]) -> Result<HttpsClient, String> {
        let mut store = rustls::RootCertStore::empty();
        for der in roots {
            store
                .add(CertificateDer::from(der.clone()))
                .map_err(|e| e.to_string())?;
        }
        let config = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(store)
            .with_no_client_auth();
        Ok(Self::with_config(config))
    }

    fn with_config(mut config: rustls::ClientConfig) -> HttpsClient {
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        HttpsClient {
            config: Arc::new(config),
        }
    }
}

/// The first of `addrs` that answers, tried in order (Revision 5 H: a name whose first
/// address is IPv6 still works where IPv6 doesn't).
fn connect_any(addrs: &[std::net::SocketAddr]) -> Result<TcpStream, String> {
    let mut last = "no address".to_string();
    for a in addrs {
        match TcpStream::connect_timeout(a, TIMEOUT) {
            Ok(t) => return Ok(t),
            Err(e) => last = e.to_string(),
        }
    }
    Err(last)
}

impl Http for HttpsClient {
    fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<Response, String> {
        let u = Url::parse(url)?;
        let where_ = format!("{}:{}", u.host, u.port);
        let addrs: Vec<std::net::SocketAddr> = where_
            .to_socket_addrs()
            .map_err(|e| format!("{} can't be found: {e}", u.host))?
            .collect();
        let name = ServerName::try_from(u.host.clone()).map_err(|e| e.to_string())?;
        let mut conn =
            rustls::ClientConnection::new(self.config.clone(), name).map_err(|e| e.to_string())?;
        let mut tcp =
            connect_any(&addrs).map_err(|e| format!("{} can't be reached: {e}", u.host))?;
        tcp.set_read_timeout(Some(TIMEOUT))
            .map_err(|e| e.to_string())?;
        tcp.set_write_timeout(Some(TIMEOUT))
            .map_err(|e| e.to_string())?;
        let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
        let host = if u.port == 443 {
            u.host.clone()
        } else {
            where_.clone()
        };
        let mut req = format!(
            "{method} {} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: keep-hub/{}\r\n",
            u.target,
            env!("CARGO_PKG_VERSION")
        );
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        if let Some(b) = body {
            req.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        req.push_str("\r\n");
        let mut bytes = req.into_bytes();
        bytes.extend_from_slice(body.unwrap_or(&[]));
        tls.write_all(&bytes)
            .map_err(|e| format!("{} didn't take the request: {e}", u.host))?;
        let mut answer = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        loop {
            match tls.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    answer.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
                    if answer.len() > MAX_ANSWER {
                        return Err(format!("{} answered too much", u.host));
                    }
                }
                // (some servers close without the TLS goodbye; the length says if it's whole)
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(format!("{} stopped answering: {e}", u.host)),
            }
        }
        parse_response(&answer)
            .ok_or_else(|| format!("{} gave an answer that can't be read", u.host))
    }
}

/// An HTTP/1.1 answer read to its end (`Connection: close`): `Content-Length`, chunked, or
/// up to the close. `None` when it isn't whole.
pub fn parse_response(answer: &[u8]) -> Option<Response> {
    let split = answer.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(answer.get(..split)?).ok()?;
    let mut lines = head.split("\r\n");
    let status: u16 = lines.next()?.split(' ').nth(1)?.parse().ok()?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let rest = answer.get(split + 4..)?;
    let find = |n: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.as_str())
    };
    let body = if find("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        let mut out = Vec::new();
        let mut r = rest;
        loop {
            let eol = r.windows(2).position(|w| w == b"\r\n")?;
            let size_text = std::str::from_utf8(r.get(..eol)?).ok()?;
            let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
            if size == 0 {
                break;
            }
            out.extend_from_slice(r.get(eol + 2..eol + 2 + size)?);
            r = r.get(eol + 4 + size..)?;
        }
        out
    } else if let Some(len) = find("content-length") {
        let len: usize = len.parse().ok()?;
        rest.get(..len)?.to_vec()
    } else {
        rest.to_vec()
    };
    Some(Response {
        status,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_read() {
        assert_eq!(
            Url::parse("https://names.getmoneykeep.org/v1/hubs").unwrap(),
            Url {
                host: "names.getmoneykeep.org".into(),
                port: 443,
                target: "/v1/hubs".into()
            }
        );
        let u = Url::parse("https://127.0.0.1:16443?dns=AAAB").unwrap();
        assert_eq!((u.port, u.target.as_str()), (16443, "/?dns=AAAB"));
        assert_eq!(Url::parse("https://Dns.Google").unwrap().target, "/");
        for bad in [
            "http://a.example/",
            "https://",
            "https://user@a.example/",
            "https://a.example:x/",
            "https://a.example/a b",
        ] {
            assert!(Url::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn answers_are_read_by_length_chunks_or_close() {
        let r = parse_response(
            b"HTTP/1.1 201 Created\r\nLocation: /a\r\nContent-Length: 2\r\n\r\nokEXTRA",
        )
        .unwrap();
        assert_eq!((r.status, r.body.as_slice()), (201, &b"ok"[..]));
        assert_eq!(r.header("location"), Some("/a"));
        let r = parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=1\r\nde\r\n0\r\n\r\n").unwrap();
        assert_eq!(r.body, b"abcde");
        let r = parse_response(b"HTTP/1.1 200 OK\r\nRetry-After: 120\r\n\r\nall of it").unwrap();
        assert_eq!(r.body, b"all of it");
        assert_eq!(r.retry_after(), Some(120));
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort"),
            None
        );
        assert_eq!(parse_response(b"not http"), None);
    }

    /// Revision 5 H: every address a name resolves to is tried, in order.
    #[test]
    fn each_address_is_tried_in_order() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let good = l.local_addr().unwrap();
        // a port nothing listens on, first
        let dead = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let t = connect_any(&[dead, good]).unwrap();
        assert_eq!(t.peer_addr().unwrap(), good);
        assert!(connect_any(&[dead]).is_err());
        assert!(connect_any(&[]).is_err());
    }

    #[test]
    fn the_systems_trust_can_be_set_up() {
        // (no request is sent: only that the platform verifier starts on this system)
        assert!(HttpsClient::system().is_ok());
    }
}
