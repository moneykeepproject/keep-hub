// The test client for acceptance test 22: a plain client (kind "plain") and a WebAssembly
// client (kind "wasm") share it. It does what a phone's client does with Keep Hub: pairs with
// the code in the address (#pair=...), keeps its device token in its own storage, calls the
// app's /api/ with it, and keeps working offline through its service worker.
"use strict";

const KIND = document.documentElement.dataset.kind;
const show = (id, text) => {
  document.getElementById(id).textContent = text;
};

async function wasmAnswer() {
  if (KIND !== "wasm") {
    return "not used";
  }
  // streaming needs application/wasm, which the hub passes through untouched
  const { instance } = await WebAssembly.instantiateStreaming(fetch("answer.wasm"));
  return String(instance.exports.answer());
}

function pairingCode() {
  const m = /[#&]pair=([A-Za-z0-9-]+)/.exec(location.hash);
  return m ? m[1] : null;
}

async function hello() {
  const token = localStorage.getItem("token");
  if (!token) {
    show("hello", "not paired");
    return;
  }
  try {
    const r = await fetch("/api/hello", {
      headers: { Authorization: "Bearer " + token, "Keep-Request-Id": "e2e-" + Date.now() },
      cache: "no-store",
    });
    if (!r.ok) {
      show("hello", "error " + r.status);
      return;
    }
    const body = await r.json();
    show("hello", body.member_name);
  } catch (e) {
    show("hello", "offline");
  }
}

async function pair(code, pin) {
  const r = await fetch("/hub/pair", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code: code, pin: pin, device: "Browser (" + KIND + ")" }),
  });
  const body = await r.json();
  if (!r.ok) {
    show("status", "pairing refused: " + (body.error || r.status));
    return;
  }
  localStorage.setItem("token", body.token);
  history.replaceState(null, "", location.pathname);
  document.getElementById("pairing").hidden = true;
  show("status", "paired");
  await hello();
}

async function start() {
  if ("serviceWorker" in navigator) {
    try {
      await navigator.serviceWorker.register("sw.js");
    } catch (e) {
      show("status", "no service worker: " + e);
    }
  }
  try {
    show("wasm", await wasmAnswer());
  } catch (e) {
    show("wasm", "failed: " + e);
  }
  const code = pairingCode();
  if (code && !localStorage.getItem("token")) {
    const form = document.getElementById("pairing");
    form.hidden = false;
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      pair(code, document.getElementById("pin").value);
    });
  }
  document.getElementById("again").addEventListener("click", hello);
  await hello();
}

start();
