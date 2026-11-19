#!/usr/bin/env python3
"""Acceptance test 22, the browser's part: run by `tests/browser.rs` (ignored unless asked for).

For each test client in the job file (a plain client and a WebAssembly client, on their apps'
ports), in a headless Chromium:

1. open it by the hub's name (https://<name>:<port>/#pair=<code>), and check the hub answered
   with the name's certificate;
2. pair: type the household PIN, and see the client's own /api/ answer with the member's name;
3. for the WebAssembly client, check the module loaded by streaming (application/wasm);
4. go offline: the page still opens from its service worker, and /api/ says offline;
5. come back: /api/ answers again with the same device token.

The name is mapped to the hub's address in the browser (--host-resolver-rules), so the test
doesn't depend on this home's router answering for the name. The staging certificate isn't
trusted by browsers, so certificate errors are ignored (a real certificate needs nothing).

    python3 browser.py <job.json>

Needs Playwright for Python and its Chromium: pip install playwright && playwright install
chromium (or set KEEP_HUB_E2E_CHROME to a Chrome or Chromium program). Exit code 0 when every
client passed.

A job without "certificate_name" (the run against a local test hub) skips the check of the
name's certificate: that hub answers with its own.
"""

import json
import os
import sys

from playwright.sync_api import sync_playwright

TIMEOUT_MS = 30_000


def check(ok, what):
    if not ok:
        raise AssertionError(what)
    print("  ok:", what)


def text_is(page, element, value):
    page.wait_for_function(
        "([id, v]) => document.getElementById(id).textContent === v",
        arg=[element, value],
        timeout=TIMEOUT_MS,
    )


def run_client(p, job, client):
    name, address, pin, member = job["name"], job["address"], job["pin"], job["member"]
    print(f"{client['kind']} client: {client['url'].split('#')[0]}")
    browser = p.chromium.launch(
        executable_path=os.environ.get("KEEP_HUB_E2E_CHROME") or None,
        args=[
            f"--host-resolver-rules=MAP {name} {address}",
            "--ignore-certificate-errors",
            # straight to the hub, as a phone on the home Wi-Fi (never a proxy from the
            # environment)
            "--no-proxy-server",
        ],
    )
    try:
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.set_default_timeout(TIMEOUT_MS)

        # 1. by name
        response = page.goto(client["url"])
        check(response is not None and response.ok, "the client opened by the hub's name")
        if job.get("certificate_name"):
            details = response.security_details() or {}
            subject = details.get("subjectName")
            check(subject == job["certificate_name"], f"the name's certificate ({subject})")

        # 2. pair, and call /api/
        page.wait_for_selector("#pairing:not([hidden])")
        page.fill("#pin", pin)
        page.click("#pair")
        text_is(page, "status", "paired")
        text_is(page, "hello", member)
        check(True, f"paired, and /api/ knows {member}")

        # 3. WebAssembly by streaming
        if client["kind"] == "wasm":
            text_is(page, "wasm", "42")
            check(True, "the WebAssembly module loaded by streaming")

        # the service worker controls the page (after one reload at most)
        page.wait_for_function("navigator.serviceWorker && navigator.serviceWorker.ready.then(() => true)")
        if not page.evaluate("navigator.serviceWorker.controller !== null"):
            page.reload()
        page.wait_for_function("navigator.serviceWorker.controller !== null")
        check(True, "the service worker controls the page")

        # 4. offline
        context.set_offline(True)
        page.reload()
        text_is(page, "hello", "offline")
        check(page.title().startswith("Keep Hub test client"), "offline, the page opens from its cache")

        # 5. back
        context.set_offline(False)
        page.click("#again")
        text_is(page, "hello", member)
        check(True, "back online, the same device token works")
    finally:
        browser.close()


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    with open(sys.argv[1], encoding="utf-8") as f:
        job = json.load(f)
    failed = 0
    with sync_playwright() as p:
        for client in job["clients"]:
            try:
                run_client(p, job, client)
            except Exception as e:  # noqa: BLE001 - report every client, then fail
                failed += 1
                print(f"  FAILED: {client['kind']} client: {e}")
    print("passed" if failed == 0 else f"{failed} client(s) failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
