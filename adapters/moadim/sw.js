// SPDX-License-Identifier: MIT
// The page's service worker (UI-API.md): keeps ui.html, ui.js and ui.css so an installed
// page opens; asks the server first and falls back to the copy. Nothing else is kept: never /api/.
'use strict';
const CACHE = 'sigelo-ui-1', KEPT = ['/ui.html', '/ui.js', '/ui.css'];
const keyOf = (path) => (path === '/' ? '/ui.html' : path);
self.addEventListener('install', (e) => { e.waitUntil(caches.open(CACHE).then((c) => c.addAll(KEPT))); self.skipWaiting(); });
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', (e) => {
  const u = new URL(e.request.url), key = keyOf(u.pathname);
  if (e.request.method !== 'GET' || u.origin !== self.location.origin || !KEPT.includes(key)) return;
  e.respondWith(fetch(e.request).then((r) => {
    if (r.ok) { const copy = r.clone(); e.waitUntil(caches.open(CACHE).then((c) => c.put(key, copy))); }
    return r;
  }).catch(() => caches.match(key).then((r) => r ?? Response.error())));
});
