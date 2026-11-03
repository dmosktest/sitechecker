export function registerServiceWorker(): void {
  if (!("serviceWorker" in navigator)) return;
  // Drop stale SW/caches from earlier builds (they broke API/PoW flows).
  window.addEventListener("load", () => {
    void navigator.serviceWorker
      .getRegistrations()
      .then((regs) => Promise.all(regs.map((r) => r.unregister())))
      .catch(() => {});
    if ("caches" in window) {
      void caches
        .keys()
        .then((keys) => Promise.all(keys.map((k) => caches.delete(k))))
        .catch(() => {});
    }
  });
}
