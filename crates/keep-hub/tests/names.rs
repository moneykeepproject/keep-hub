//! Stage 3: the hub's name and its certificate, against a fake name service, a fake ACME
//! server that checks every signed request, and fake resolvers (`support/world.rs`). The
//! test names give the acceptance test of `docs/specs/keep-hub.md` they cover.
//!
//! The last test runs against the real staging services; it is skipped unless pointed at
//! them (see `at13_end_to_end_against_the_staging_services`).

mod support;

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use keep_hub::config::HubConfig;
use keep_hub::names::{Names, Outside};
use keep_hub::KeyStore;
use serde_json::{json, Value};
use support::world::{Home, World, ACME_DIR, CODE, SERVICE};
use support::Fixture;

const DAY: i64 = 86_400_000;
const HOME: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 20);

/// A names engine in a temporary folder, with a fake world sharing its clock.
struct Setup {
    dir: tempfile::TempDir,
    keys: KeyStore,
    clock: Arc<AtomicI64>,
    log: Arc<Mutex<Vec<String>>>,
    world: Arc<World>,
    names: Names,
}

fn config(staging: bool) -> HubConfig {
    let mut cfg = HubConfig::new(HOME);
    cfg.names.service = SERVICE.into();
    cfg.names.acme = ACME_DIR.into();
    cfg.names.staging = staging;
    cfg
}

impl Setup {
    fn new() -> Setup {
        Self::with(config(false))
    }

    fn with(cfg: HubConfig) -> Setup {
        let dir = tempfile::tempdir().unwrap();
        cfg.save(dir.path()).unwrap();
        let clock = Arc::new(AtomicI64::new(1_795_000_000_000));
        let world = World::new(clock.clone());
        let keys = KeyStore::memory();
        let log = Arc::new(Mutex::new(Vec::new()));
        let names = open(dir.path(), &keys, &clock, &log, world.outside());
        Setup {
            dir,
            keys,
            clock,
            log,
            world,
            names,
        }
    }

    /// The engine again on the same folder and keys (the hub restarted).
    fn reopen(&mut self) {
        let cfg = HubConfig::load(self.dir.path()).unwrap();
        let _ = cfg;
        self.names = open(
            self.dir.path(),
            &self.keys,
            &self.clock,
            &self.log,
            self.world.outside(),
        );
    }

    fn advance(&self, ms: i64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }

    fn status(&self) -> Value {
        self.names.status()
    }

    fn state(&self) -> String {
        self.status()["state"].as_str().unwrap().to_string()
    }

    fn orders(&self) -> u32 {
        self.world.acme.lock().unwrap().new_orders
    }

    /// Turn on with the code and do the work.
    fn turn_on(&self) {
        self.names.turn_on(Some(CODE)).unwrap();
        self.names.run_once();
    }
}

fn open(
    dir: &std::path::Path,
    keys: &KeyStore,
    clock: &Arc<AtomicI64>,
    log: &Arc<Mutex<Vec<String>>>,
    outside: Outside,
) -> Names {
    let cfg = HubConfig::load(dir).unwrap();
    let (c, l) = (clock.clone(), log.clone());
    Names::open(
        dir,
        &cfg,
        keys.clone(),
        outside,
        Arc::new(move || c.load(Ordering::SeqCst)),
        Arc::new(move |line: &str| l.lock().unwrap().push(line.to_string())),
    )
}

// ----- turning on -------------------------------------------------------------------------------

#[test]
fn at13_turning_on_ends_ready_with_a_certificate_for_the_name_and_no_proof_left() {
    let s = Setup::new();
    assert_eq!(s.state(), "off");
    s.turn_on();
    let st = s.status();
    assert_eq!(st["state"], "ready", "{st}");
    let name = st["name"].as_str().unwrap().to_string();
    assert!(name.ends_with(".hub-test.getmoneykeep.org"), "{name}");

    // the certificate: for the name, with the hub's key, 90 days
    let cert = s.names.certificate().unwrap();
    assert_eq!(cert.info.dns_names, std::slice::from_ref(&name));
    assert_eq!(cert.chain.len(), 2, "the leaf and the CA");
    assert_eq!(cert.info.not_after - cert.info.not_before, 90 * 86_400);
    assert!(!cert.staging);
    assert_eq!(st["certificate"]["days_left"], 90);
    assert_eq!(st["renewal_warning"], false);
    assert!(std::fs::read_to_string(s.dir.path().join("hub-name.crt"))
        .unwrap()
        .contains("BEGIN CERTIFICATE"));

    // the name points at the home address; the proof record is gone
    let ns = s.world.ns.lock().unwrap();
    assert_eq!(ns.a.get(&name).map(String::as_str), Some("192.168.1.20"));
    assert!(ns.txt.is_empty(), "{:?}", ns.txt);
    assert_eq!(ns.set_proofs, 1);
    assert_eq!(
        ns.calls,
        [
            "POST /hubs",
            "PUT /hubs/k7m2p9xw4t01/address",
            "PUT /hubs/k7m2p9xw4t01/proof",
            "DELETE /hubs/k7m2p9xw4t01/proof"
        ]
    );
    drop(ns);
    let acme = s.world.acme.lock().unwrap();
    assert!(acme.bad_requests.is_empty(), "{:?}", acme.bad_requests);
    assert_eq!((acme.new_orders, acme.new_accounts), (1, 1));
    assert_eq!(acme.directories, [ACME_DIR]);
    drop(acme);
    // turned on is a setting, kept in hub.json
    assert!(HubConfig::load(s.dir.path()).unwrap().names.enabled);
    assert_eq!(s.status()["requests_last_7_days"], 1);
}

#[test]
fn the_registration_code_is_needed_the_first_time_only() {
    let s = Setup::new();
    let e = s.names.turn_on(None).unwrap_err();
    assert!(e.contains("registration code"), "{e}");
    assert!(!HubConfig::load(s.dir.path()).unwrap().names.enabled);

    // a wrong code: off, with the service's reason, and nothing registered
    s.names.turn_on(Some("WRON-GCOD-EWRO-NGCO")).unwrap();
    s.names.run_once();
    let st = s.status();
    assert_eq!(st["state"], "off");
    assert!(st["message"].as_str().unwrap().contains("bad_code"), "{st}");
    assert!(st["name"].is_null());
    // a minute later the reason is still there
    s.advance(60_000);
    s.names.run_once();
    assert!(s.status()["message"].as_str().unwrap().contains("bad_code"));

    // the right one, typed forgivingly
    s.names.turn_on(Some("abcd-efgh-jklm-npqr")).unwrap();
    s.names.run_once();
    assert_eq!(s.state(), "ready");

    // off and on again: no code, no new registration, no new certificate
    s.names.turn_off().unwrap();
    s.names.run_once();
    assert_eq!(s.state(), "off");
    assert!(s.names.certificate().is_some(), "kept while off");
    s.names.turn_on(None).unwrap();
    s.names.run_once();
    assert_eq!(s.state(), "ready");
    assert_eq!(s.world.ns.lock().unwrap().registrations, 1);
    assert_eq!(s.orders(), 1);
}

#[test]
fn a_name_service_that_cant_be_reached_leaves_the_hub_waiting_with_its_code() {
    let s = Setup::new();
    s.world.service_down.store(true, Ordering::SeqCst);
    s.turn_on();
    let st = s.status();
    assert_eq!(st["state"], "waiting");
    assert!(
        st["message"].as_str().unwrap().contains("can't be reached"),
        "{st}"
    );
    // back again: the code given earlier is still used
    s.world.service_down.store(false, Ordering::SeqCst);
    s.names.run_once();
    assert_eq!(s.state(), "ready");
}

#[test]
fn the_name_and_certificate_survive_a_restart() {
    let mut s = Setup::new();
    s.turn_on();
    let name = s.status()["name"].clone();
    s.reopen();
    s.names.run_once();
    assert_eq!(s.state(), "ready");
    assert_eq!(s.status()["name"], name);
    assert_eq!(s.world.ns.lock().unwrap().registrations, 1);
    assert_eq!(s.orders(), 1);
    // the account is found again, not made again, on the next certificate
    s.names.renew_now().unwrap();
    s.names.run_once();
    let acme = s.world.acme.lock().unwrap();
    assert_eq!((acme.new_orders, acme.new_accounts), (2, 1));
}

#[test]
fn staging_uses_lets_encrypts_staging_service_and_only_with_the_staging_name_service() {
    // the staging switch with the real name service is refused
    let mut cfg = config(true);
    cfg.names.service = keep_hub::nameservice::NAME_SERVICE.into();
    let s = Setup::with(cfg);
    let e = s.names.turn_on(Some(CODE)).unwrap_err();
    assert!(e.contains("staging name service"), "{e}");

    // with Let's Encrypt as the authority, staging picks its staging directory
    let mut cfg = config(true);
    cfg.names.acme = keep_hub::acme::LETS_ENCRYPT.into();
    let s = Setup::with(cfg);
    s.turn_on();
    assert_eq!(s.state(), "ready");
    assert_eq!(
        s.world.acme.lock().unwrap().directories,
        ["https://acme-staging-v02.api.letsencrypt.org/directory"]
    );
    let st = s.status();
    assert_eq!(st["staging"], true);
    assert_eq!(st["certificate"]["staging"], true);
    assert!(s.names.certificate().unwrap().staging);
}

// ----- the self-test ----------------------------------------------------------------------------

#[test]
fn at14_a_router_that_refuses_the_name_is_blocked_and_the_fallback_is_offered() {
    let s = Setup::new();
    *s.world.home.lock().unwrap() = Home::Refuses;
    s.turn_on();
    let st = s.status();
    assert_eq!(st["state"], "blocked", "{st}");
    assert_eq!(st["fallback_offered"], true);
    assert!(st["message"].as_str().unwrap().contains("router"), "{st}");
    assert!(
        s.names.certificate().is_some(),
        "the certificate is still there"
    );

    // a home answer without the address is blocked too
    let mut s = Setup::new();
    *s.world.home.lock().unwrap() = Home::Other(Ipv4Addr::new(203, 0, 113, 9));
    s.turn_on();
    assert_eq!(s.state(), "blocked");
    // still blocked after a restart, before the next daily check
    s.reopen();
    s.advance(60_000);
    s.names.run_once();
    assert_eq!(s.state(), "blocked");

    // the router lets it through: ready at the next daily check
    *s.world.home.lock().unwrap() = Home::SameAsPublic;
    s.advance(DAY);
    s.names.run_once();
    assert_eq!(s.state(), "ready");
    assert_eq!(s.status()["fallback_offered"], false);
}

#[test]
fn when_the_public_resolver_cant_tell_the_hub_isnt_called_blocked() {
    let s = Setup::new();
    s.turn_on();
    // the public resolver goes quiet and the router starts refusing: no verdict either way
    s.world.public_down.store(true, Ordering::SeqCst);
    *s.world.home.lock().unwrap() = Home::Refuses;
    s.advance(DAY);
    s.names.run_once();
    assert_eq!(s.state(), "ready");
}

// ----- failures and limits ----------------------------------------------------------------------

#[test]
fn a_proof_that_never_appears_is_cleared_and_tried_again_the_next_day() {
    let s = Setup::new();
    s.world.proofs_hidden.store(true, Ordering::SeqCst);
    let before = s.clock.load(Ordering::SeqCst);
    s.turn_on();
    let st = s.status();
    assert_eq!(st["state"], "waiting", "{st}");
    assert!(
        st["message"].as_str().unwrap().contains("2 minutes"),
        "{st}"
    );
    // it waited 2 minutes, not more, and cleared the proof
    let waited = s.clock.load(Ordering::SeqCst) - before;
    assert!((120_000..=130_000).contains(&waited), "{waited}");
    assert!(s.world.ns.lock().unwrap().txt.is_empty());
    assert!(s.names.certificate().is_none());

    // not again the same day
    s.world.proofs_hidden.store(false, Ordering::SeqCst);
    s.advance(60 * 60_000);
    s.names.run_once();
    assert_eq!(s.orders(), 1);
    // the next day
    s.advance(DAY);
    s.names.run_once();
    assert_eq!(s.state(), "ready");
    assert_eq!(s.orders(), 2);
}

#[test]
fn lets_encrypts_weekly_limit_puts_the_hub_in_waiting_until_the_time_it_gives() {
    let s = Setup::new();
    s.world.acme.lock().unwrap().rate_limited = Some(3 * 3600);
    s.turn_on();
    let st = s.status();
    assert_eq!(st["state"], "waiting", "{st}");
    assert!(st["message"].as_str().unwrap().contains("limit"), "{st}");
    let retry = st["retry_at"].as_i64().unwrap();
    let now = s.clock.load(Ordering::SeqCst);
    assert!(
        (retry - now - 3 * 3_600_000).abs() < 60_000,
        "{}",
        retry - now
    );
    // nothing is sent before then, even on the next checks
    s.world.acme.lock().unwrap().rate_limited = None;
    s.advance(2 * 3_600_000);
    s.names.run_once();
    assert_eq!(s.orders(), 1);
    s.advance(3_600_000 + 60_000);
    s.names.run_once();
    assert_eq!(s.state(), "ready");
    assert_eq!(s.orders(), 2);
}

#[test]
fn at17_a_fourth_certificate_request_inside_7_days_is_not_sent() {
    let s = Setup::new();
    s.turn_on();
    for _ in 0..2 {
        s.advance(60_000);
        s.names.renew_now().unwrap();
        s.names.run_once();
    }
    assert_eq!(s.orders(), 3);
    s.advance(60_000);
    s.names.renew_now().unwrap();
    s.names.run_once();
    assert_eq!(s.orders(), 3, "the fourth was not sent");
    let st = s.status();
    assert_eq!(st["state"], "ready", "the certificate in use is fine");
    assert_eq!(st["requests_last_7_days"], 3);
    assert!(
        st["message"].as_str().unwrap().contains("3 certificates"),
        "{st}"
    );
    assert!(st["retry_at"].is_i64());
    // seven days after the first, there's room again
    s.advance(7 * DAY);
    s.names.renew_now().unwrap();
    s.names.run_once();
    assert_eq!(s.orders(), 4);
}

#[test]
fn at16_renewal_starts_at_a_third_of_the_life_retries_daily_and_warns_at_14_days() {
    let s = Setup::new();
    s.turn_on();
    let issued = s.names.certificate().unwrap().info.not_before;
    // 59 days in: two thirds of 90 not yet passed
    s.advance(59 * DAY);
    s.names.run_once();
    assert_eq!(s.orders(), 1);
    // day 60 and a bit: a third left, renewed on the daily check
    s.advance(DAY + 60_000);
    s.names.run_once();
    assert_eq!(s.orders(), 2);
    let renewed = s.names.certificate().unwrap().info.not_before;
    assert!(renewed > issued);
    assert_eq!(s.state(), "ready");

    // the next renewal fails: tried once a day, the old certificate still in use
    s.world.acme.lock().unwrap().fail_validation = true;
    s.advance(61 * DAY);
    s.names.run_once();
    assert_eq!(s.orders(), 3);
    let st = s.status();
    assert_eq!(st["state"], "ready");
    assert!(
        st["message"].as_str().unwrap().contains("couldn't check"),
        "{st}"
    );
    assert_eq!(s.names.certificate().unwrap().info.not_before, renewed);
    s.advance(3_600_000);
    s.names.run_once();
    assert_eq!(s.orders(), 3, "not again the same day");
    s.advance(DAY);
    s.names.run_once();
    assert_eq!(s.orders(), 4, "again the next day");

    // the warning appears only at 14 days or fewer
    let left = |s: &Setup| s.status()["certificate"]["days_left"].as_i64().unwrap();
    while left(&s) > 15 {
        s.advance(DAY);
        s.names.run_once();
    }
    assert_eq!(left(&s), 15);
    assert_eq!(s.status()["renewal_warning"], false);
    s.advance(DAY);
    s.names.run_once();
    assert_eq!(left(&s), 14);
    assert_eq!(s.status()["renewal_warning"], true);
    // the 7-day limit held all along: never more than 3 in any 7 days
    // (checked by the engine; here, at most one a day was sent)
    s.world.acme.lock().unwrap().fail_validation = false;
    s.advance(DAY);
    s.names.run_once();
    assert_eq!(s.status()["renewal_warning"], false, "renewed at last");
    assert_eq!(s.state(), "ready");
}

// ----- secrets ----------------------------------------------------------------------------------

#[test]
fn no_token_code_or_key_reaches_the_log_or_the_public_files() {
    let s = Setup::new();
    s.turn_on();
    let token = s
        .world
        .ns
        .lock()
        .unwrap()
        .hubs
        .values()
        .next()
        .unwrap()
        .0
        .clone();
    let names_json = std::fs::read_to_string(s.dir.path().join("names.json")).unwrap();
    let hub_json = std::fs::read_to_string(s.dir.path().join("hub.json")).unwrap();
    let lines = s.log.lock().unwrap().clone();
    assert!(
        lines.contains(&"names: certificate issued".to_string()),
        "{lines:?}"
    );
    for text in lines.iter().chain([&names_json, &hub_json]) {
        assert!(!text.contains(&token), "the token in {text}");
        assert!(!text.to_uppercase().contains("ABCDEFGHJKLMNPQR"));
        assert!(!text.contains(CODE));
        assert!(!text.contains("PRIVATE KEY"));
    }
    // the token is kept sealed, in the key store
    assert_eq!(
        s.keys.get("name-token").unwrap().unwrap().as_slice(),
        token.as_bytes()
    );
}

// ----- the admin address ------------------------------------------------------------------------

#[test]
fn names_are_turned_on_and_read_through_the_admin_address() {
    let (f, world) = Fixture::with_world(|cfg| {
        cfg.names.service = SERVICE.into();
        cfg.names.acme = ACME_DIR.into();
    });
    let st = f.admin_ok("GET", "/admin/v1/names", None);
    assert_eq!(st["state"], "off");
    let r = f.admin("POST", "/admin/v1/names/renew", None);
    assert_eq!((r.status, r.error().as_str()), (409, "names_off"));
    let r = f.admin("POST", "/admin/v1/names/on", None);
    assert_eq!((r.status, r.error().as_str()), (409, "names_refused"));

    f.admin_ok(
        "POST",
        "/admin/v1/names/on",
        Some(json!({ "registration_code": CODE })),
    );
    // The hub's own thread does the work. This test hub listens on 127.0.0.1, which the
    // name service refuses (a hub must be on a home network), so it registers and waits.
    let mut st = Value::Null;
    for _ in 0..200 {
        st = f.admin_ok("GET", "/admin/v1/names", None);
        if st["state"] == "waiting" {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(st["state"], "waiting", "{st}");
    assert!(st["name"].is_string(), "registered: {st}");
    assert!(
        st["message"]
            .as_str()
            .unwrap()
            .contains("address_not_private"),
        "{st}"
    );
    assert_eq!(
        f.admin_ok("GET", "/admin/v1/status", None)["names"],
        "waiting"
    );
    assert_eq!(world.ns.lock().unwrap().registrations, 1);
    assert_eq!(
        world.acme.lock().unwrap().new_orders,
        0,
        "no certificate without the address"
    );
    // nothing about the code in the hub's log
    assert!(f.log_lines().iter().all(|l| !l.contains(CODE)));

    f.admin_ok("POST", "/admin/v1/names/off", None);
    assert_eq!(f.admin_ok("GET", "/admin/v1/names", None)["state"], "off");
}

// ----- end to end ---------------------------------------------------------------------------------

/// Acceptance test 13 against the real staging services. Skipped unless run with
/// `cargo test -p keep-hub --test names -- --ignored` and these set:
///
/// - `KEEP_HUB_E2E_SERVICE`: the staging name service, e.g. `https://<host>/v1`
/// - `KEEP_HUB_E2E_CODE`: a registration code for it
/// - `KEEP_HUB_E2E_ADDRESS` (optional): the home address to publish (default 192.168.1.20)
///
/// It asks Let's Encrypt's staging service for one certificate, never the real one.
#[test]
#[ignore = "end to end: needs the staging name service, a code and the internet"]
fn at13_end_to_end_against_the_staging_services() {
    let (Ok(service), Ok(code)) = (
        std::env::var("KEEP_HUB_E2E_SERVICE"),
        std::env::var("KEEP_HUB_E2E_CODE"),
    ) else {
        panic!("set KEEP_HUB_E2E_SERVICE and KEEP_HUB_E2E_CODE (see this test's comment)");
    };
    let address: Ipv4Addr = std::env::var("KEEP_HUB_E2E_ADDRESS")
        .unwrap_or_else(|_| "192.168.1.20".into())
        .parse()
        .expect("KEEP_HUB_E2E_ADDRESS is an IPv4 address");
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = HubConfig::new(address);
    cfg.names.service = service;
    cfg.names.staging = true;
    cfg.save(dir.path()).unwrap();
    let outside = Outside::system().unwrap();
    let lookup = outside.lookup.clone();
    let log = Arc::new(Mutex::new(Vec::new()));
    let l = log.clone();
    let names = Names::open(
        dir.path(),
        &cfg,
        KeyStore::memory(),
        outside,
        Arc::new(keep_hub::util::now_ms),
        Arc::new(move |line: &str| l.lock().unwrap().push(line.to_string())),
    );
    names.turn_on(Some(&code)).unwrap();
    names.run_once();
    let st = names.status();
    eprintln!("{st:#}\n{:#?}", log.lock().unwrap());
    // Ready, or Blocked when this home's router refuses the name: either way a certificate
    let state = st["state"].as_str().unwrap();
    assert!(state == "ready" || state == "blocked", "{st}");
    let cert = names.certificate().unwrap();
    let name = st["name"].as_str().unwrap();
    assert_eq!(cert.info.dns_names, [name]);
    assert!(cert.staging);
    // the proof record is gone (allow its 60-second TTL to pass)
    let record = format!("_acme-challenge.{name}");
    let mut gone = false;
    for _ in 0..30 {
        if lookup
            .public(&record, keep_hub::dns::Kind::Txt)
            .is_ok_and(|v| v.is_empty())
        {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    assert!(gone, "the proof record is still published");
}

// ----- the hub's own HTTPS client -----------------------------------------------------------------

/// The client the hub uses for the name service, Let's Encrypt and DNS, against a real TLS
/// server on this computer (a hub's app port), trusting only that hub's authority.
#[test]
fn the_hubs_https_client_reads_answers_and_refuses_a_server_it_doesnt_trust() {
    use keep_hub::client::{Http, HttpsClient};
    let f = Fixture::new();
    let app = support::TestApp::start("alpha");
    f.register(&app, false, false);
    let port = f.port("alpha").port();
    let client = HttpsClient::with_roots(&[f.hub().ca_der.clone()]).unwrap();
    let r = client
        .send(
            "GET",
            &format!("https://127.0.0.1:{port}/hub/check"),
            &[],
            None,
        )
        .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.json().unwrap(), json!({ "hub": "keep-hub", "ok": true }));
    // a POST with a body and a refusal
    let r = client
        .send(
            "POST",
            &format!("https://127.0.0.1:{port}/hub/pair"),
            &[("Content-Type", "application/json")],
            Some(br#"{"code":"AAAA-AAAA","pin":"000000","device":"x"}"#),
        )
        .unwrap();
    assert_eq!(
        r.status,
        409,
        "no PIN set yet: {}",
        String::from_utf8_lossy(&r.body)
    );
    // another hub's authority: refused before any request is sent
    let other = Fixture::new();
    let stranger = HttpsClient::with_roots(&[other.hub().ca_der.clone()]).unwrap();
    let e = stranger
        .send(
            "GET",
            &format!("https://127.0.0.1:{port}/hub/check"),
            &[],
            None,
        )
        .unwrap_err();
    assert!(e.contains("127.0.0.1"), "{e}");
    assert!(app.seen().is_empty());
}
