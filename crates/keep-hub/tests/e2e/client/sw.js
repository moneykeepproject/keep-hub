// The test client's service worker: the client's files come from its cache when the phone
// is offline; /api/ and the hub's own paths always go to the network.
"use strict";

const CACHE = "keep-hub-e2e-v1";
const FILES = ["./", "index.html", "app.js", "answer.wasm"];

self.addEventListener("install", (ev) => {
  ev.waitUntil(caches.open(CACHE).then((c) => c.addAll(FILES)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (ev) => {
  ev.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", (ev) => {
  const url = new URL(ev.request.url);
  if (ev.request.method !== "GET" || url.pathname.startsWith("/api/") || url.pathname.startsWith("/hub/")) {
    return;
  }
  ev.respondWith(
    fetch(ev.request)
      .then((r) => {
        const copy = r.clone();
        caches.open(CACHE).then((c) => c.put(ev.request, copy));
        return r;
      })
      .catch(() => caches.match(ev.request, { ignoreSearch: true }))
  );
});
