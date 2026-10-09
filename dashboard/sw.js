/* PortDrift app-shell cache: never cache imported scans, API calls or arbitrary URLs. */
const CACHE = "portdrift-static-v0.4.0";
const PREFIX = "portdrift-static-";
const STATIC = [
  "./", "./index.html", "./styles.css", "./app.mjs", "./logic.mjs",
  "./manifest.webmanifest", "./icon.svg",
  "./samples/before.json", "./samples/after.json"
];
self.addEventListener("install", event => {
  event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(STATIC)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(
    keys.filter(key => key.startsWith(PREFIX) && key !== CACHE).map(key => caches.delete(key))
  )).then(() => self.clients.claim()));
});
self.addEventListener("fetch", event => {
  const req = event.request;
  if (req.method !== "GET" || new URL(req.url).origin !== self.location.origin) return;
  const allowed = new Set(STATIC.map(p => new URL(p, self.registration.scope).href));
  // Restrict interception to the exact, versioned offline app shell.
  if (!allowed.has(req.url)) return;
  event.respondWith(caches.match(req).then(cached => cached || fetch(req)));
});
