//! Acceptance test 10, its last part: the hub's memory does not grow by a large file's size
//! while it passes the file on.
//!
//! This test program counts every allocation (its own global allocator), so it holds this
//! one test only: other tests running beside it would blur the count. The hub, the test app
//! and the phone all run in this process; the test app makes the file as it sends it and
//! the phone keeps only a hash, so what grows is what the hub holds.

mod support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use support::{Fixture, TestApp, WASM_LEN};

struct Counting;

static NOW: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(by: usize) {
    let now = NOW.fetch_add(by, Ordering::SeqCst) + by;
    PEAK.fetch_max(now, Ordering::SeqCst);
}

// SAFETY: every call is passed to the system allocator unchanged; only sizes are counted.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        NOW.fetch_sub(layout.size(), Ordering::SeqCst);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            if new_size >= layout.size() {
                grew(new_size - layout.size());
            } else {
                NOW.fetch_sub(layout.size() - new_size, Ordering::SeqCst);
            }
        }
        p
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

#[test]
fn at10_the_hubs_memory_does_not_grow_by_the_files_size() {
    let f = Fixture::new();
    let app = TestApp::start("vacapick");
    f.register(&app, false, false);
    // once first, so the hub's buffers and TLS session memory are already there
    let warm = f.download("vacapick", "/app.wasm", &[("Accept-Encoding", "br")]);
    assert_eq!(warm.body_len, WASM_LEN as u64);

    let before = NOW.load(Ordering::SeqCst);
    PEAK.store(before, Ordering::SeqCst);
    let got = f.download("vacapick", "/app.wasm", &[("Accept-Encoding", "br")]);
    let peak = PEAK.load(Ordering::SeqCst);
    assert_eq!(got.end, Ok(()));
    assert_eq!(got.body_len, WASM_LEN as u64);
    assert_eq!(got.sha256, support::wasm_sha256());

    let growth = peak.saturating_sub(before);
    eprintln!(
        "peak growth while passing on {} MB: {} KB",
        WASM_LEN >> 20,
        growth >> 10
    );
    // the hub, the phone and the test app together: a few buffers, never the file
    assert!(
        growth < 2 * 1024 * 1024,
        "memory grew by {growth} bytes for a {WASM_LEN}-byte file"
    );
}
