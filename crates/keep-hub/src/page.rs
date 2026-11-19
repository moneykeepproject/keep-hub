//! The certificate page (`http://<address>:16080`, plain HTTP on the home network): how to
//! trust the hub's own certificate authority, for homes where the hub name can't be used.
//! Copied from ShareKeep's hub (`wifi.rs` and `server.rs`: the page, the iPhone profile,
//! the small front with its limits; the steps from `sk-view`'s `phone.rs`), then changed
//! for several apps and given steps for computers.
//!
//! - `/`: the fingerprint to compare, both downloads, the steps for the phone that asked
//!   first, then the others, and a link to each app. Opened from a pairing QR code
//!   (`?app=<id>&pair=<code>`, or `invite=` for a guest), it ends with the link that pairs.
//! - `/keep-hub-ca.crt`: the authority's certificate (Android, computers).
//! - `/keep-hub-ca.mobileconfig`: the same in an iPhone/iPad configuration profile
//!   (`com.apple.security.root`, Apple Configuration Profile Reference).
//!
//! No scripts; nothing secret. Anything else redirects to `/`.

use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use sha2::{Digest, Sha256};
use tiny_http::{Header, Request, Response};

use crate::ca::{self, Info};
use crate::hub::Hub;
use crate::relay::Slot;
use crate::util as store;

pub const CA_CRT_PATH: &str = "/keep-hub-ca.crt";
pub const CA_MOBILECONFIG_PATH: &str = "/keep-hub-ca.mobileconfig";

/// The certificate page's connections at once, in all.
const MAX_HELPER: usize = 32;
/// A certificate-page connection that sends or takes nothing for this long is closed.
const HELPER_IDLE: Duration = Duration::from_secs(15);

/// The page's own headers (no scripts at all).
pub const HELPER_HEADERS: [(&str, &str); 4] = [
    (
        "Content-Security-Policy",
        "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    ),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Frame-Options", "DENY"),
];

// ----- the steps --------------------------------------------------------------------------------
// `**…**` marks words to show in bold.

/// Before downloading anything: the phone must be talking to the real hub.
pub const COMPARE: &str = "**Compare** the fingerprint on this page with the one on the hub computer, digit for digit. If they differ, stop: don't download anything.";

/// iPhone or iPad.
pub const APPLE: [&str; 5] = [
    "Open this page in **Safari** (the Camera app opens Safari).",
    COMPARE,
    "Tap **Download certificate (iPhone or iPad)**, then **Allow**.",
    "Open **Settings**: tap **Profile Downloaded** near the top (or **General** > **VPN & Device Management**), then **Install**, and enter the phone's passcode.",
    "Open **Settings** > **General** > **About** > **Certificate Trust Settings** and turn on full trust for “Keep Hub CA”.",
];

/// Android phone or tablet.
pub const ANDROID: [&str; 6] = [
    COMPARE,
    "Tap **Download certificate (Android)**. If Chrome asks, keep the file.",
    "Open **Settings** > **Security** (or **Security & privacy**) > **More security settings** > **Encryption & credentials**. The words differ a little between phone makers; searching Settings for “certificate” also finds it.",
    "Tap **Install a certificate** > **CA certificate**, then **Install anyway**.",
    "Choose the downloaded file **keep-hub-ca.crt** (in Downloads). The phone may ask for its screen lock.",
    "Check under **Trusted credentials** > **User** that “Keep Hub CA” is listed.",
];

/// A Windows computer.
pub const WINDOWS: [&str; 4] = [
    COMPARE,
    "Click **Download certificate (Android)**: the same file works on a computer. Open **keep-hub-ca.crt** from Downloads.",
    "Click **Install Certificate…**, choose **Current User**, then **Place all certificates in the following store** > **Browse…** > **Trusted Root Certification Authorities**.",
    "Click **Finish**, then **Yes** when Windows asks about the certificate.",
];

/// A Mac.
pub const MAC: [&str; 4] = [
    COMPARE,
    "Click **Download certificate (Android)**: the same file works on a computer. Open **keep-hub-ca.crt** from Downloads: Keychain Access adds it to the **login** keychain.",
    "In Keychain Access, double-click “Keep Hub CA”, open **Trust** and set **When using this certificate** to **Always Trust**.",
    "Close the window and enter the Mac's password.",
];

/// A step as HTML: escaped, with `**…**` in bold.
pub fn html(step: &str) -> String {
    let escaped = xml(step);
    let mut out = String::new();
    for (i, part) in escaped.split("**").enumerate() {
        if i % 2 == 1 {
            out.push_str("<b>");
            out.push_str(part);
            out.push_str("</b>");
        } else {
            out.push_str(part);
        }
    }
    out
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn steps(title: &str, list: &[&str]) -> String {
    let items: String = list
        .iter()
        .map(|s| format!("<li>{}</li>", html(s)))
        .collect();
    format!("<section><h2>{title}</h2><ol>{items}</ol></section>")
}

/// Which device asked (by its browser's User-Agent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Device {
    Apple,
    Android,
    Computer,
}

pub fn device(user_agent: &str) -> Device {
    if ["iPhone", "iPad", "iPod"]
        .iter()
        .any(|k| user_agent.contains(k))
    {
        Device::Apple
    } else if user_agent.contains("Android") {
        Device::Android
    } else {
        Device::Computer
    }
}

// ----- the iPhone profile -----------------------------------------------------------------------

/// A UUID (version 4 form) from 16 bytes.
fn uuid(b: [u8; 16]) -> String {
    let h = store::hex(&b).to_ascii_uppercase();
    let p = |a: usize, z: usize| h.get(a..z).unwrap_or("").to_owned();
    let v = format!("4{}", h.get(13..16).unwrap_or(""));
    format!("{}-{}-{}-{}-{}", p(0, 8), p(8, 12), v, p(16, 20), p(20, 32))
}

/// The iPhone/iPad configuration profile carrying the CA certificate. The identifiers come
/// from the certificate, so the same CA always gives the same profile.
pub fn mobileconfig(ca_der: &[u8], ca_name: &str) -> String {
    let h = Sha256::digest(ca_der);
    let mut a = [0u8; 16];
    let mut b = [0u8; 16];
    a.copy_from_slice(h.get(..16).unwrap_or(&[0; 16]));
    b.copy_from_slice(h.get(16..32).unwrap_or(&[0; 16]));
    let data = base64::engine::general_purpose::STANDARD.encode(ca_der);
    let id = store::hex(h.get(..6).unwrap_or(&[]));
    let name = xml(ca_name);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadCertificateFileName</key>
      <string>keep-hub-ca.cer</string>
      <key>PayloadContent</key>
      <data>{data}</data>
      <key>PayloadDescription</key>
      <string>Lets this iPhone or iPad trust the household's Keep Hub on its Wi-Fi address only.</string>
      <key>PayloadDisplayName</key>
      <string>{name}</string>
      <key>PayloadIdentifier</key>
      <string>org.getmoneykeep.keephub.ca.{id}.cert</string>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadUUID</key>
      <string>{u1}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDescription</key>
  <string>Installs the certificate of the household's Keep Hub. It is valid only for the hub computer's Wi-Fi address.</string>
  <key>PayloadDisplayName</key>
  <string>{name}</string>
  <key>PayloadIdentifier</key>
  <string>org.getmoneykeep.keephub.ca.{id}</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>{u2}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
"#,
        u1 = uuid(a),
        u2 = uuid(b),
    )
}

// ----- the page ---------------------------------------------------------------------------------

/// An app on the page: its title and public port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppLink {
    pub id: String,
    pub title: String,
    pub port: u16,
}

/// Where the page was opened from: a pairing code (or guest invite) for one app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Join {
    pub app: AppLink,
    /// `pair` or `invite`.
    pub key: &'static str,
    /// Shown as `ABCD-EFGH`.
    pub code: String,
}

/// A pairing code or invite from the page's address, if it is one (8 letters and digits,
/// with or without the dash). Anything else is ignored and never echoed.
pub fn code_param(raw: &str) -> Option<String> {
    let c: String = raw.chars().filter(|c| *c != '-').collect();
    (c.len() == 8 && c.bytes().all(|b| b.is_ascii_alphanumeric()))
        .then(|| format!("{}-{}", &c[..4], &c[4..]).to_ascii_uppercase())
}

/// The page for one device.
pub fn page(info: &Info, device: Device, apps: &[AppLink], join: Option<&Join>) -> String {
    let address = xml(&info.address);
    let open = |a: &AppLink, fragment: &str| {
        format!(
            r#"<a class="button" href="https://{address}:{}/{fragment}">Open {}</a>"#,
            a.port,
            xml(&a.title)
        )
    };
    let step2 = join
        .map(|j| {
            format!(
                r#"<div class="card"><h2>Step 2: join</h2>
<p>After the certificate is installed, open {title}:</p>
{link}
<p class="muted">The code is <b>{code}</b>. It works once.</p></div>"#,
                title = xml(&j.app.title),
                link = open(&j.app, &format!("#{}={}", j.key, xml(&j.code))),
                code = xml(&j.code),
            )
        })
        .unwrap_or_default();
    let mut sections = [
        (Device::Android, steps("Android phone or tablet", &ANDROID)),
        (Device::Apple, steps("iPhone or iPad", &APPLE)),
        (
            Device::Computer,
            format!(
                "{}{}",
                steps("Windows computer", &WINDOWS),
                steps("Mac", &MAC)
            ),
        ),
    ];
    // the device that asked first
    sections.sort_by_key(|(d, _)| *d != device);
    let cards: String = sections
        .iter()
        .map(|(_, s)| format!(r#"<div class="card">{s}</div>"#))
        .collect();
    let links: String = if apps.is_empty() {
        r#"<p class="muted">No app on the hub computer has turned on phones yet.</p>"#.into()
    } else {
        apps.iter().map(|a| open(a, "")).collect()
    };
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Keep Hub — certificate</title>
<style>
:root {{ --bg:#f1f5f4; --card:#ffffff; --text:#1e293b; --muted:#64748b; --accent:#0f766e; --line:#e2e8f0; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#15181c; --card:#20252b; --text:#eef1f4; --muted:#aab3bd; --accent:#5eead4; --line:#3a424b; }} }}
body {{ margin:0; background:var(--bg); color:var(--text); font:17px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }}
main {{ max-width:480px; margin:0 auto; padding:16px; }}
h1 {{ font-size:22px; margin:8px 0 4px; }} h2 {{ font-size:18px; margin:20px 0 6px; }}
.card {{ background:var(--card); border:1px solid var(--line); border-radius:12px; padding:14px 16px; margin:12px 0; }}
.muted {{ color:var(--muted); font-size:15px; }}
.fp {{ font:600 17px/1.6 ui-monospace, "SF Mono", Menlo, Consolas, monospace; letter-spacing:.5px; word-spacing:4px; }}
a.button {{ display:block; text-align:center; text-decoration:none; background:var(--accent); color:#fff; font-weight:600; border-radius:10px; padding:14px; margin:10px 0; min-height:24px; }}
@media (prefers-color-scheme: dark) {{ a.button {{ color:#0d1117; }} }}
ol {{ padding-left:22px; }} li {{ margin:6px 0; }}
</style></head>
<body><main>
<h1>Keep Hub</h1>
<p class="muted">Step 1 on this device: trust the hub's certificate, so the household's apps open securely at <b>https://{address}</b>.</p>
<div class="card">
<h2 style="margin-top:0">First, compare</h2>
<p>Look at the Phones screen of an app on the hub computer. Its fingerprint must be exactly these digits:</p>
<div class="fp">{fp}</div>
<p class="muted">If even one differs, stop and don't download anything: another device on the Wi-Fi is answering for the hub, and it would see the household PIN.</p>
<div class="muted">Certificate</div><div><b>{ca}</b></div>
<p>They match? Then download it:</p>
<a class="button" href="{crt}">Download certificate (Android)</a>
<a class="button" href="{mc}">Download certificate (iPhone or iPad)</a>
<p class="muted">The certificate is only valid for the hub computer's address ({address}). It cannot be used for any other website.</p>
</div>
{step2}
{cards}
<div class="card"><h2 style="margin-top:0">Already installed?</h2>
{links}
</div>
</main></body></html>
"#,
        fp = xml(&info.fingerprint),
        ca = xml(&info.ca_name),
        crt = CA_CRT_PATH,
        mc = CA_MOBILECONFIG_PATH,
    )
}

// ----- serving it ---------------------------------------------------------------------------------

fn query<'a>(url: &'a str, key: &str) -> Option<&'a str> {
    url.split_once('?')?
        .1
        .split('&')
        .find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
}

/// One request to the page's own server (behind [`front`]).
pub(crate) fn handle(hub: &Arc<Hub>, req: Request) {
    let url = req.url().to_string();
    let path = url.split('?').next().unwrap_or("").to_string();
    let ua = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("User-Agent"))
        .map(|h| h.value.as_str().to_string())
        .unwrap_or_default();
    let info = ca::read_info(&hub.data).unwrap_or_default();
    let ca_pem = std::fs::read_to_string(hub.data.join(ca::CA_CERT_FILE)).unwrap_or_default();
    let apps: Vec<AppLink> = hub
        .lock()
        .registry
        .apps()
        .unwrap_or_default()
        .into_iter()
        .map(|a| AppLink {
            id: a.id,
            title: a.title,
            port: a.public_port,
        })
        .collect();
    let join = query(&url, "app").and_then(|id| {
        let app = apps.iter().find(|a| a.id == id)?.clone();
        let (key, raw) = query(&url, "pair")
            .map(|c| ("pair", c))
            .or_else(|| query(&url, "invite").map(|c| ("invite", c)))?;
        Some(Join {
            app,
            key,
            code: code_param(raw)?,
        })
    });
    let get = req.method() == &tiny_http::Method::Get || req.method() == &tiny_http::Method::Head;
    let (status, ctype, body, extra): (u16, &str, Vec<u8>, Option<(&str, String)>) =
        match path.as_str() {
            _ if !get => (405, "text/plain", Vec::new(), None),
            "/" => (
                200,
                "text/html; charset=utf-8",
                page(&info, device(&ua), &apps, join.as_ref()).into_bytes(),
                None,
            ),
            CA_CRT_PATH => (
                200,
                "application/x-x509-ca-cert",
                ca_pem.into_bytes(),
                Some((
                    "Content-Disposition",
                    "attachment; filename=\"keep-hub-ca.crt\"".into(),
                )),
            ),
            CA_MOBILECONFIG_PATH => (
                200,
                "application/x-apple-aspen-config",
                ca::from_pem(&ca_pem)
                    .map(|der| mobileconfig(&der, &info.ca_name))
                    .unwrap_or_default()
                    .into_bytes(),
                None,
            ),
            _ => (
                302,
                "text/plain",
                Vec::new(),
                Some(("Location", "/".into())),
            ),
        };
    let mut resp = Response::from_data(body).with_status_code(status);
    let mut headers: Vec<(&str, String)> = vec![
        ("Content-Type", ctype.into()),
        ("Cache-Control", "no-store".into()),
        ("Connection", "close".into()),
    ];
    headers.extend(HELPER_HEADERS.iter().map(|(k, v)| (*k, v.to_string())));
    headers.extend(extra);
    for (k, v) in headers {
        if let Ok(h) = Header::from_bytes(k.as_bytes(), v.as_bytes()) {
            resp.add_header(h);
        }
    }
    let method = req.method().as_str().to_string();
    let _ = req.respond(resp);
    hub.log_request(&method, &path, status);
}

/// The page's front on the home network: at most [`MAX_HELPER`] connections,
/// [`crate::relay::MAX_PER_ADDRESS`] from one address, each closed after [`HELPER_IDLE`] without traffic,
/// passed to the page's own server on `backend`. Waits in `accept`; closing wakes it
/// ([`crate::relay::wake`]).
pub(crate) fn front(
    listener: TcpListener,
    backend: SocketAddr,
    stop: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
) {
    let active = Arc::new(AtomicUsize::new(0));
    let per = Arc::new(Mutex::new(std::collections::HashMap::<IpAddr, usize>::new()));
    if listener.set_nonblocking(false).is_err() {
        return;
    }
    loop {
        let accepted = listener.accept();
        if stop.load(Ordering::SeqCst) || stopping.load(Ordering::SeqCst) {
            return;
        }
        match accepted {
            Ok((tcp, peer)) => {
                if active.load(Ordering::SeqCst) >= MAX_HELPER {
                    drop(tcp);
                    continue;
                }
                let Some(slot) = Slot::take(&per, peer.ip()) else {
                    drop(tcp);
                    continue;
                };
                active.fetch_add(1, Ordering::SeqCst);
                let act = active.clone();
                let spawned = std::thread::Builder::new()
                    .name("hub-page-front".into())
                    .spawn(move || {
                        let _slot = slot;
                        let _ = pipe(tcp, backend);
                        act.fetch_sub(1, Ordering::SeqCst);
                    });
                if spawned.is_err() {
                    active.fetch_sub(1, Ordering::SeqCst);
                }
            }
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

/// Bytes both ways between a visitor and the page's server, until either side closes or
/// nothing moves for [`HELPER_IDLE`].
fn pipe(outer: TcpStream, backend: SocketAddr) -> std::io::Result<()> {
    outer.set_nonblocking(false)?;
    outer.set_read_timeout(Some(HELPER_IDLE))?;
    outer.set_write_timeout(Some(HELPER_IDLE))?;
    let inner = TcpStream::connect_timeout(&backend, Duration::from_secs(5))?;
    inner.set_read_timeout(Some(HELPER_IDLE))?;
    inner.set_write_timeout(Some(HELPER_IDLE))?;
    let (mut from_in, mut to_out) = (inner.try_clone()?, outer.try_clone()?);
    let back = std::thread::Builder::new()
        .name("hub-page-back".into())
        .spawn(move || {
            let _ = std::io::copy(&mut from_in, &mut to_out);
            let _ = to_out.shutdown(Shutdown::Write);
        })?;
    let (mut from_out, mut to_in) = (outer.try_clone()?, inner.try_clone()?);
    let _ = std::io::copy(&mut from_out, &mut to_in);
    let _ = inner.shutdown(Shutdown::Both);
    let _ = back.join();
    let _ = outer.shutdown(Shutdown::Both);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> Info {
        Info {
            ca_name: "Keep Hub CA (DESK)".into(),
            address: "192.168.1.20".into(),
            ca_not_before: 0,
            ca_not_after: 1,
            cert_not_before: 0,
            cert_not_after: 1,
            fingerprint: "AAAA BBBB CCCC DDDD EEEE FFFF 0000 1111".into(),
        }
    }

    #[test]
    fn steps_have_their_bold_closed_and_escape_html() {
        assert_eq!(
            html("Open **Settings** > **A & B**"),
            "Open <b>Settings</b> &gt; <b>A &amp; B</b>"
        );
        for s in APPLE.iter().chain(&ANDROID).chain(&WINDOWS).chain(&MAC) {
            assert_eq!(s.matches("**").count() % 2, 0, "{s}");
        }
    }

    #[test]
    fn the_device_that_asked_comes_first() {
        let ua_iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)";
        let ua_android = "Mozilla/5.0 (Linux; Android 15; Pixel 9)";
        assert_eq!(device(ua_iphone), Device::Apple);
        assert_eq!(device(ua_android), Device::Android);
        assert_eq!(device("Mozilla/5.0 (Windows NT 10.0)"), Device::Computer);
        let pos = |p: &str, s: &str| p.find(s).unwrap();
        let p = page(&info(), Device::Apple, &[], None);
        assert!(pos(&p, "iPhone or iPad</h2>") < pos(&p, "Android phone"));
        let p = page(&info(), Device::Computer, &[], None);
        assert!(pos(&p, "Windows computer") < pos(&p, "Android phone"));
        assert!(pos(&p, "Mac</h2>") < pos(&p, "iPhone or iPad</h2>"));
    }

    #[test]
    fn the_page_gives_the_fingerprint_the_downloads_and_the_apps() {
        let apps = [AppLink {
            id: "vacapick".into(),
            title: "VacaPick".into(),
            port: 16443,
        }];
        let p = page(&info(), Device::Android, &apps, None);
        assert!(p.contains("AAAA BBBB CCCC DDDD EEEE FFFF 0000 1111"));
        assert!(p.contains(r#"href="/keep-hub-ca.crt""#));
        assert!(p.contains(r#"href="/keep-hub-ca.mobileconfig""#));
        assert!(p.contains(r#"href="https://192.168.1.20:16443/">Open VacaPick</a>"#));
        assert!(!p.contains("<script"));
        assert!(!p.contains("Step 2"));
        let join = Join {
            app: apps[0].clone(),
            key: "pair",
            code: "ABCD-EFGH".into(),
        };
        let p = page(&info(), Device::Android, &apps, Some(&join));
        assert!(
            p.contains(r#"href="https://192.168.1.20:16443/#pair=ABCD-EFGH">Open VacaPick</a>"#)
        );
    }

    #[test]
    fn only_a_code_shaped_parameter_is_used() {
        assert_eq!(code_param("abcd-efgh").as_deref(), Some("ABCD-EFGH"));
        assert_eq!(code_param("ABCDEFGH").as_deref(), Some("ABCD-EFGH"));
        for bad in ["ABCD", "ABCD-EFGH-1", "<script>", "ABCD EFGH", "ÄBCD-EFGH"] {
            assert_eq!(code_param(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_profile_carries_the_certificate_and_is_the_same_each_time() {
        let der = b"not really a certificate".to_vec();
        let m = mobileconfig(&der, "Keep Hub CA (A&B)");
        assert!(m.contains(&base64::engine::general_purpose::STANDARD.encode(&der)));
        assert!(m.contains("<string>com.apple.security.root</string>"));
        assert!(m.contains("Keep Hub CA (A&amp;B)"));
        assert_eq!(m, mobileconfig(&der, "Keep Hub CA (A&B)"));
    }
}
