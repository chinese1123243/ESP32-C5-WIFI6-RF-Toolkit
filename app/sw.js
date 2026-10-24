/* RFTOOL PWA service worker — 离线缓存 */
const CACHE = 'rftool-v2.3.0-r1';
const ASSETS = ['./', './index.html', './app.js?v=2.3.0', './app.js', './manifest.json', './icon.png'];

self.addEventListener('install', e => {
    e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)));
    self.skipWaiting();
});
self.addEventListener('activate', e => {
    e.waitUntil(
        caches.keys().then(keys =>
            Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
        )
    );
    self.clients.claim();
});
self.addEventListener('fetch', e => {
    e.respondWith(
        caches.match(e.request).then(r => r || fetch(e.request).then(resp => {
            const copy = resp.clone();
            caches.open(CACHE).then(c => c.put(e.request, copy)).catch(()=>{});
            return resp;
        }).catch(() => caches.match('./index.html')))
    );
});
