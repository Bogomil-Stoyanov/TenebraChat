/// <reference lib="webworker" />
/* eslint-disable no-restricted-globals */

import { precacheAndRoute } from 'workbox-precaching';

declare const self: ServiceWorkerGlobalScope;

// ── Workbox precaching (vite-plugin-pwa injects the manifest here) ─────────
precacheAndRoute(self.__WB_MANIFEST);

// ── Push event: zero-knowledge ping ────────────────────────────────────────
// We intentionally ignore `event.data` — the server only sends { type: 'PING' }.
// No message content ever reaches the service worker, preserving E2EE guarantees.
self.addEventListener('push', (event: PushEvent) => {
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clients) => {
      // If any window has focus the user is actively looking at the app — skip notification.
      const appFocused = clients.some((c) => c.focused);
      if (appFocused) return;

      return self.registration.showNotification('Tenebra', {
        body: 'New encrypted message',
        icon: '/icon-192.png',
        badge: '/icon-192.png',
        tag: 'tenebra-ping',
        renotify: true,
        vibrate: [200, 100, 200],
        silent: false,
      } as NotificationOptions);
    })
  );
});

// ── Notification click: focus or open the app ──────────────────────────────
self.addEventListener('notificationclick', (event: NotificationEvent) => {
  event.notification.close();

  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((windowClients) => {
      // If a Tenebra window/tab is already open, focus it
      for (const client of windowClients) {
        if (client.url.includes(self.location.origin) && 'focus' in client) {
          return client.focus();
        }
      }
      // Otherwise open a new window
      return self.clients.openWindow('/');
    })
  );
});
