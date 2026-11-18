# Stage 2: what was built

Implementer's notes (2026-11-18). This is not a spec: `docs/specs/keep-hub.md` says what the
hub must do. Stage 2 of `AGENTS.md` section 5 is web client pass-through: large files,
compression, caching, headers.

## Built

- **The hub's headers on every answer.** `X-Content-Type-Options: nosniff` and
  `Referrer-Policy: no-referrer` are now added to answers the hub passes on from an app's
  backend, not only to its own. A backend's own header of the same name is replaced, never
  sent twice; the hub's values are already the strictest (`http::HUB_HEADERS`,
  `http::answer_head`).
- **Everything else passes through untouched:** `Accept-Encoding` to the backend;
  `Content-Encoding`, `Content-Type`, `ETag`, `Cache-Control`, `Vary`, 304 answers and the
  app's `Content-Security-Policy` back to the phone. The hub never compresses, decompresses,
  caches or adds a security policy. (Stage 1's relay already did this; stage 2 tests it.)
- **Large files stream** through one 64 KB buffer. No time limit while bytes move; closed
  after 30 seconds with none, either way (`relay::IDLE`). A backend may take up to 120
  seconds to *start* an answer, so an app can work out a slow report.
- **The idle limit is an option** of `HubOptions` (`idle`), so tests use 1 second. It is
  not in `hub.json`: the spec has no setting for it.
- **Connections are taken at once.** The accept loop copied from ShareKeep looked for a new
  connection every 50 ms. With one request per connection that delayed every file: 40 small
  files took 2.0 s through the hub. The loop now waits in `accept` and is woken by a
  connection when its port closes (`relay::wake`). 40 files now take about 0.2 s.

## Owner decision on 2026-11-18

**One request per connection stays.** The hub closes after every answer, so every request
is read and checked on its own. Keep-alive would make the hub find where each backend
answer ends before reading the next request, in the most security-sensitive code.
`forty_small_files_load_one_connection_each` measures the cost; revisit only if a real
client is slow on real Wi-Fi.

## Acceptance tests covered

| Spec test | Where |
|---|---|
| 10 | `tests/web.rs`: two `at10_…` tests (12 MB byte for byte with `application/wasm`, `br` and `ETag`; 304 with no body). `tests/memory.rs`: the hub's memory doesn't grow by the file's size |
| 11 | `tests/web.rs`: two `at11_…` tests |
| 12 | `tests/web.rs`: two `at12_…` tests, with the idle limit at 1 second: a stall is cut after 1 s; a download that keeps sending for five times the limit finishes. `the_shipped_idle_limit_is_thirty_seconds` checks the real value |

### How the memory test works

`tests/memory.rs` is its own test program with a counting allocator, holding this one test
only. The hub, a test app that makes the 12 MB file as it sends it, and a phone that keeps
only a hash all run in the process. Measured: the peak grows by about 343 KB while 12 MB
passes through. The test allows 2 MB. Checked that it fails when the hub holds the file:
with the relay changed to buffer the whole answer, the peak grew by 16 MB and the test
failed.

## Measured (Linux test machine, loopback)

| What | Time |
|---|---|
| 12 MB WASM file through the hub | about 0.3 s |
| 40 small files, one connection each, no TLS session resumption | about 0.2 s (2.0 s before the accept fix) |

Loopback is not Wi-Fi, and a phone resumes TLS sessions where this test client doesn't.

## Not built

- **HSTS** (`Strict-Transport-Security` when the phone used the hub name) comes with the
  name in stage 3. The spec gives no `max-age`; that needs deciding then. A test checks a
  phone that came by address gets none.
- **Test 22** (a headless browser with a WASM and a plain client) is end to end and needs the
  hub name: later.
