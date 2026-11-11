const CACHE_NAME = "skypay-v1";

self.addEventListener("install", event => {
  self.skipWaiting();
});

self.addEventListener("activate", event => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();

      await Promise.all(
        keys
          .filter(key => key !== CACHE_NAME)
          .map(key => caches.delete(key))
      );

      await self.clients.claim();
    })()
  );
});

self.addEventListener("fetch", event => {
  if (event.request.method !== "GET") return;

  event.respondWith(
    fetch(event.request).catch(async () => {
      if (event.request.mode === "navigate") {
        return (
          await caches.match("/") ||
          new Response("Internet connection required.", {
            status: 503,
            headers: { "Content-Type": "text/plain" }
          })
        );
      }

      return new Response("", { status: 503 });
    })
  );
});
