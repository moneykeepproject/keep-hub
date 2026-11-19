//! Stage 2: web clients through the hub. A WASM client's large file, a plain client's small
//! files, compression, caching, security policies, the hub's headers, and the rule that a
//! transfer is closed only when nothing moves. The test names give the acceptance test of
//! `docs/specs/keep-hub.md` they cover; the hub's memory while it streams a large file is
//! in `tests/memory.rs`.
//!
//! Everything runs on 127.0.0.1; nothing leaves this computer.

mod support;

use std::time::Duration;

use support::{Fixture, TestApp, PLAIN_CSP, PLAIN_HTML, WASM_ETAG, WASM_LEN};

fn one_app(f: &Fixture) -> TestApp {
    let app = TestApp::start("vacapick");
    f.register(&app, false, false);
    app
}

#[test]
fn at10_a_large_compressed_wasm_file_arrives_byte_for_byte_with_its_headers() {
    let f = Fixture::new();
    let app = one_app(&f);
    let got = f.download("vacapick", "/app.wasm", &[("Accept-Encoding", "br, gzip")]);
    assert_eq!(got.end, Ok(()), "the hub ended the download properly");
    assert_eq!(got.head.status, 200);
    assert_eq!(got.body_len, WASM_LEN as u64);
    assert_eq!(got.sha256, support::wasm_sha256(), "byte for byte");
    let h = &got.head;
    assert_eq!(h.header("content-type"), Some("application/wasm"));
    assert_eq!(h.header("content-encoding"), Some("br"));
    assert_eq!(
        h.header("content-length"),
        Some(WASM_LEN.to_string().as_str())
    );
    assert_eq!(h.header("etag"), Some(WASM_ETAG));
    assert_eq!(h.header("cache-control"), Some("no-cache"));
    assert_eq!(h.header("vary"), Some("Accept-Encoding"));
    // the hub passed the phone's Accept-Encoding on and compressed nothing itself
    let seen = app.seen();
    assert_eq!(seen[0].header("accept-encoding"), Some("br, gzip"));
    // a phone that doesn't accept br is given what the app chooses
    let gz = f.download("vacapick", "/app.wasm", &[("Accept-Encoding", "gzip")]);
    assert_eq!(gz.head.header("content-encoding"), Some("gzip"));
    assert_eq!(gz.sha256, got.sha256);
    eprintln!("12 MB through the hub in {:?}", got.elapsed);
}

#[test]
fn at10_a_second_request_with_if_none_match_gets_304_with_no_body() {
    let f = Fixture::new();
    let app = one_app(&f);
    let got = f.download("vacapick", "/app.wasm", &[("If-None-Match", WASM_ETAG)]);
    assert_eq!(got.end, Ok(()));
    assert_eq!(got.head.status, 304);
    assert_eq!(got.body_len, 0);
    assert_eq!(got.head.header("etag"), Some(WASM_ETAG));
    assert_eq!(got.head.header("cache-control"), Some("no-cache"));
    assert_eq!(app.seen()[0].header("if-none-match"), Some(WASM_ETAG));
    // the hub's headers are on a 304 too
    assert_eq!(got.head.header("x-content-type-options"), Some("nosniff"));
    // HEAD: the headers and no body
    let head = f.phone("vacapick", "HEAD", "/app.wasm", &[], None);
    assert_eq!(head.status, 200);
    assert_eq!(head.body.len(), 0);
    assert_eq!(
        head.header("content-length"),
        Some(WASM_LEN.to_string().as_str())
    );
}

#[test]
fn at11_a_plain_clients_files_and_policy_arrive_unchanged_with_the_hubs_headers() {
    let f = Fixture::new();
    let _app = one_app(&f);
    let page = f.phone("vacapick", "GET", "/plain/index.html", &[], None);
    assert_eq!(page.status, 200);
    assert_eq!(page.text(), PLAIN_HTML);
    assert_eq!(
        page.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(page.header("content-security-policy"), Some(PLAIN_CSP));
    assert_eq!(page.header("x-content-type-options"), Some("nosniff"));
    // the app sent a weaker referrer policy: the hub's is the only one that arrives
    let referrer: Vec<&str> = page
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("referrer-policy"))
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(referrer, ["no-referrer"]);
    // one security policy, the app's, unchanged; the hub adds none of its own
    let csp = page
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("content-security-policy"))
        .count();
    assert_eq!(csp, 1);
    let js = f.phone("vacapick", "GET", "/plain/app.js", &[], None);
    assert_eq!(js.text(), "document.title = 'Plain';");
    assert_eq!(js.header("content-type"), Some("text/javascript"));
    assert_eq!(js.header("referrer-policy"), Some("no-referrer"));
    // no HSTS for a phone that came by address (only by the hub name: tests/fallback.rs)
    assert_eq!(page.header("strict-transport-security"), None);
}

#[test]
fn at11_the_hubs_headers_are_on_api_answers_and_refusals_too() {
    let f = Fixture::new();
    let _app = one_app(&f);
    f.set_pin();
    let sam = f.add_member("Sam");
    let token = f.pair(sam, "vacapick", "Sam's phone");
    for r in [
        f.api("vacapick", &token, "GET", "/api/trips"),
        f.phone("vacapick", "GET", "/api/trips", &[], None),
        f.phone("vacapick", "GET", "/hub/check", &[], None),
    ] {
        assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
        assert_eq!(r.header("referrer-policy"), Some("no-referrer"));
    }
}

#[test]
fn at12_a_download_that_sends_nothing_for_the_idle_time_is_closed() {
    // The shipped hub waits 30 seconds; this one waits 1 second, so the test is quick.
    let f = Fixture::with_idle(Duration::from_secs(1));
    let _app = one_app(&f);
    let got = f.download("vacapick", "/stall", &[]);
    assert_eq!(got.head.status, 200);
    assert_eq!(got.body_len, 10, "the bytes before the stall arrived");
    assert!(
        got.end.is_err(),
        "cut short, not ended properly: {:?}",
        got.end
    );
    assert!(
        got.elapsed >= Duration::from_secs(1) && got.elapsed < Duration::from_secs(5),
        "closed after {:?}",
        got.elapsed
    );
}

#[test]
fn at12_a_download_that_keeps_sending_is_not_closed() {
    // Five times the idle time (5 minutes with the shipped 30 seconds; 5 seconds here),
    // one byte every 0.4 seconds.
    let f = Fixture::with_idle(Duration::from_secs(1));
    let _app = one_app(&f);
    let got = f.download("vacapick", "/trickle?n=13&ms=400", &[]);
    assert_eq!(got.end, Ok(()), "after {:?}", got.elapsed);
    assert_eq!(got.body_len, 13);
    assert!(got.elapsed >= Duration::from_secs(5), "{:?}", got.elapsed);
}

#[test]
fn the_shipped_idle_limit_is_thirty_seconds() {
    assert_eq!(keep_hub::relay::IDLE, Duration::from_secs(30));
    assert_eq!(
        keep_hub::HubOptions::new(std::path::PathBuf::from("x")).idle,
        Duration::from_secs(30)
    );
}

/// One request per connection (owner decision 2026-11-18): how long a web client of many
/// small files takes. A phone resumes its TLS sessions; this test client does not, so this
/// is the slower case.
#[test]
fn forty_small_files_load_one_connection_each() {
    let f = Fixture::new();
    let app = one_app(&f);
    let started = std::time::Instant::now();
    for i in 0..40 {
        let r = f.phone("vacapick", "GET", &format!("/files/{i}.js"), &[], None);
        assert_eq!(r.status, 200);
        assert_eq!(r.text(), format!("vacapick file /files/{i}.js"));
    }
    let took = started.elapsed();
    assert_eq!(app.seen().len(), 40);
    eprintln!("40 files, one connection each: {took:?}");
    // About 5 ms each on the Linux test machine. A hub that looked for connections every
    // 50 ms (ShareKeep's accept loop) took 2 seconds here.
    assert!(took < Duration::from_millis(1500), "{took:?}");
}
