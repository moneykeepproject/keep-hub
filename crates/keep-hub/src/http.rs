//! The little HTTP/1.1 (RFC 9110, RFC 9112) the app ports need: reading a request's head
//! strictly, and writing the hub's own answers.
//!
//! The hub reads one request per connection and closes after the answer, so what it
//! checked (the path, the token) is all that reaches an app's backend. A head it cannot
//! read one way only is refused, so the hub and a backend never disagree about where a
//! request ends.

use serde_json::{json, Value};

/// The largest request head the hub reads.
pub const MAX_HEAD: usize = 16 * 1024;

/// A request's first line and headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub method: String,
    /// The path and query, as sent.
    pub target: String,
    /// Names as sent, values trimmed.
    pub headers: Vec<(String, String)>,
}

fn token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

impl Head {
    /// Read a head (the bytes before the empty line). `None` when it isn't a request this
    /// hub passes on: not HTTP/1.x, a target that isn't a path, a header name with a space,
    /// a folded header line, or bytes that aren't text.
    pub fn parse(bytes: &[u8]) -> Option<Head> {
        let text = std::str::from_utf8(bytes).ok()?;
        let mut lines = text.split("\r\n");
        let mut first = lines.next()?.split(' ');
        let (method, target, version) = (first.next()?, first.next()?, first.next()?);
        if first.next().is_some()
            || method.is_empty()
            || !method.bytes().all(|b| b.is_ascii_uppercase())
            || !(version == "HTTP/1.1" || version == "HTTP/1.0")
            || !target.starts_with('/')
            || target.bytes().any(|b| b <= b' ' || b == 0x7f)
        {
            return None;
        }
        let mut headers = Vec::new();
        for line in lines {
            let (name, value) = line.split_once(':')?;
            if name.is_empty()
                || !name.bytes().all(token_char)
                || value.bytes().any(|b| (b < b' ' && b != b'\t') || b == 0x7f)
            {
                return None;
            }
            headers.push((name.to_string(), value.trim().to_string()));
        }
        Some(Head {
            method: method.to_string(),
            target: target.to_string(),
            headers,
        })
    }

    /// The path, without the query.
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or("")
    }

    /// The first header of this name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The token of `Authorization: Bearer` (RFC 6750).
    pub fn bearer(&self) -> Option<&str> {
        self.header("authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|t| !t.is_empty())
    }

    /// How many bytes of body follow. `Err` when the head doesn't say so one way only: a
    /// `Transfer-Encoding`, or `Content-Length` headers that differ or aren't a number.
    pub fn content_length(&self) -> Result<u64, LengthError> {
        if self.header("transfer-encoding").is_some() {
            return Err(LengthError::Chunked);
        }
        let mut found: Option<u64> = None;
        for (k, v) in &self.headers {
            if !k.eq_ignore_ascii_case("content-length") {
                continue;
            }
            if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(LengthError::Unclear);
            }
            let n: u64 = v.parse().map_err(|_| LengthError::Unclear)?;
            if found.is_some_and(|f| f != n) {
                return Err(LengthError::Unclear);
            }
            found = Some(n);
        }
        Ok(found.unwrap_or(0))
    }
}

/// Why a request's length can't be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthError {
    /// The body is sent in chunks, which the hub doesn't pass on (it needs `Content-Length`).
    Chunked,
    /// `Content-Length` is missing its number, or is given twice with different numbers.
    Unclear,
}

/// Where a head ends in `buf`: the index of its empty line.
pub fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// One of the hub's own answers.
#[derive(Debug, Clone, PartialEq)]
pub struct Answer {
    pub status: u16,
    pub body: Value,
}

impl Answer {
    pub fn ok(body: Value) -> Answer {
        Answer { status: 200, body }
    }

    /// A refusal: a short code for programs and plain words for people.
    pub fn error(status: u16, code: &str, message: &str) -> Answer {
        Answer {
            status,
            body: json!({ "error": code, "message": message }),
        }
    }

    /// The bytes to send (`head_only` for an answer to HEAD; `hsts` when the phone used
    /// the hub name).
    pub fn to_bytes(&self, head_only: bool, hsts: bool) -> Vec<u8> {
        let body = serde_json::to_vec(&self.body).unwrap_or_default();
        let mut out = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\n{}Connection: close\r\n\r\n",
            self.status,
            reason(self.status),
            body.len(),
            added(hsts)
                .map(|(k, v)| format!("{k}: {v}\r\n"))
                .collect::<String>()
        )
        .into_bytes();
        if !head_only {
            out.extend_from_slice(&body);
        }
        out
    }
}

/// The words after a status code (RFC 9110 section 15).
pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

/// The headers the hub adds to every answer, its own and those it passes on (the spec's
/// "Headers the hub adds to every answer").
pub const HUB_HEADERS: &[(&str, &str)] = &[
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
];

/// Added too when the phone used the hub name with its real certificate (RFC 6797). One day
/// (owner decision 2026-11-18): little lock-in if the name's certificate ever lapses. No
/// `includeSubDomains`: the name is this hub's alone.
pub const HSTS: (&str, &str) = ("Strict-Transport-Security", "max-age=86400");

/// The headers to add to one answer.
fn added(hsts: bool) -> impl Iterator<Item = &'static (&'static str, &'static str)> {
    HUB_HEADERS.iter().chain(hsts.then_some(&HSTS))
}

/// An app backend's answer head, made ready for the phone: its status, and its lines with
/// the connection headers replaced by `Connection: close` (the hub closes after every
/// answer), and the hub's own headers ([`HUB_HEADERS`], and [`HSTS`] when `hsts`) in place
/// of any of the same name the backend sent (the hub's are already the strictest values).
/// Everything else, the content type, encoding, caching headers and security policy
/// included, is passed on as the backend sent it. `None` when it isn't an HTTP answer.
pub fn answer_head(head: &[u8], hsts: bool) -> Option<(u16, Vec<u8>)> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let first = lines.next()?;
    let mut parts = first.splitn(3, ' ');
    let version = parts.next()?;
    let status: u16 = parts.next()?.parse().ok()?;
    if !version.starts_with("HTTP/1.") || !(100..=599).contains(&status) {
        return None;
    }
    let mut out = String::with_capacity(text.len() + 32);
    out.push_str(first);
    out.push_str("\r\n");
    for line in lines {
        let name = line.split(':').next().unwrap_or("").trim();
        let replaced = ["connection", "keep-alive", "proxy-connection"]
            .iter()
            .chain(HUB_HEADERS.iter().chain([&HSTS]).map(|(k, _)| k))
            .any(|h| name.eq_ignore_ascii_case(h));
        if replaced {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    for (k, v) in added(hsts) {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("Connection: close\r\n\r\n");
    Some((status, out.into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_head_is_read() {
        let h = Head::parse(
            b"POST /api/v1/items?x=1 HTTP/1.1\r\nHost: 192.168.1.20:16443\r\nauthorization: Bearer abc\r\nContent-Length: 12",
        )
        .unwrap();
        assert_eq!(h.method, "POST");
        assert_eq!(h.path(), "/api/v1/items");
        assert_eq!(h.target, "/api/v1/items?x=1");
        assert_eq!(h.bearer(), Some("abc"));
        assert_eq!(h.content_length(), Ok(12));
        assert_eq!(h.header("HOST"), Some("192.168.1.20:16443"));
        assert_eq!(
            Head::parse(b"GET / HTTP/1.1").unwrap().content_length(),
            Ok(0)
        );
    }

    #[test]
    fn heads_that_could_be_read_two_ways_are_refused() {
        for bad in [
            &b"GET http://elsewhere/ HTTP/1.1"[..],
            b"GET / HTTP/2",
            b"GET  / HTTP/1.1",
            b"get / HTTP/1.1",
            b"GET / HTTP/1.1\r\nContent-Length : 3",
            b"GET / HTTP/1.1\r\nX: a\r\n folded",
            b"GET / HTTP/1.1\r\nno colon",
            b"GET /a\tb HTTP/1.1",
            b"GET / HTTP/1.1\r\nX: \xff",
        ] {
            assert_eq!(Head::parse(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
        let h = |t: &[u8]| Head::parse(t).unwrap().content_length();
        assert_eq!(
            h(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked"),
            Err(LengthError::Chunked)
        );
        assert_eq!(
            h(b"POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4"),
            Err(LengthError::Unclear)
        );
        assert_eq!(
            h(b"POST / HTTP/1.1\r\nContent-Length: 3\r\ncontent-length: 3"),
            Ok(3)
        );
        assert_eq!(
            h(b"POST / HTTP/1.1\r\nContent-Length: +3"),
            Err(LengthError::Unclear)
        );
        assert_eq!(
            h(b"POST / HTTP/1.1\r\nContent-Length:"),
            Err(LengthError::Unclear)
        );
    }

    #[test]
    fn the_hubs_own_answers_close_and_carry_its_headers() {
        let a = Answer::error(401, "not_paired", "Pair this phone first.");
        let text = String::from_utf8(a.to_bytes(false, false)).unwrap();
        assert!(text.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
        assert!(text.contains("X-Content-Type-Options: nosniff\r\n"));
        assert!(text.contains("Referrer-Policy: no-referrer\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        assert!(text.ends_with(r#"{"error":"not_paired","message":"Pair this phone first."}"#));
        let head = String::from_utf8(a.to_bytes(true, false)).unwrap();
        assert!(head.ends_with("\r\n\r\n"));
    }

    #[test]
    fn a_backends_answer_head_is_passed_on_but_closes() {
        let (status, head) = answer_head(
            b"HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\nContent-Security-Policy: default-src 'self'\r\nreferrer-policy: origin\r\nX-Content-Type-Options: nosniff",
            false,
        )
        .unwrap();
        assert_eq!(status, 304);
        assert_eq!(
            String::from_utf8(head).unwrap(),
            "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nContent-Security-Policy: default-src 'self'\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(answer_head(b"SSH-2.0-OpenSSH", false), None);
        assert_eq!(answer_head(b"HTTP/1.1 abc OK", false), None);
        // by the hub name: the hub's HSTS, in place of the backend's
        let (_, head) = answer_head(
            b"HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=63072000; includeSubDomains",
            true,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(head).unwrap(),
            "HTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nStrict-Transport-Security: max-age=86400\r\nConnection: close\r\n\r\n"
        );
        let own =
            String::from_utf8(Answer::ok(serde_json::json!({})).to_bytes(false, true)).unwrap();
        assert!(own.contains("Strict-Transport-Security: max-age=86400\r\n"));
    }
}
