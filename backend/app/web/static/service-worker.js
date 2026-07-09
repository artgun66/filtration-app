// Minimal service worker: caches the app shell so the PWA is installable and
// loads its static assets offline. Data requests (scan/results) always hit the
// network — we never cache email verdicts.
const CACHE = 'filtration-v1';
const SHELL = ['/', '/static/app.css', '/static/htmx.min.js', '/manifest.webmanifest'];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).catch(() => {}));
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  // Cache-first only for static shell assets; everything else is network.
  if (url.pathname.startsWith('/static/') || SHELL.includes(url.pathname)) {
    event.respondWith(caches.match(request).then((r) => r || fetch(request)));
  }
});
