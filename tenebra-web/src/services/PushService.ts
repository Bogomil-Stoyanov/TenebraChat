/**
 * PushService — Register the browser for zero-knowledge Web Push notifications.
 *
 * Flow:
 *   1. Fetch the VAPID public key from the server.
 *   2. Wait for the service worker to be ready.
 *   3. Ask the user for notification permission.
 *   4. Subscribe to push via the PushManager.
 *   5. Send the subscription to POST /api/push/subscribe.
 */

import api from '@/api/client';

/**
 * Convert a URL-safe base64 VAPID key to a Uint8Array for the PushManager.
 */
function urlBase64ToUint8Array(base64String: string): Uint8Array {
  const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const rawData = atob(base64);
  const buffer = new ArrayBuffer(rawData.length);
  const outputArray = new Uint8Array(buffer);
  for (let i = 0; i < rawData.length; i++) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}

/**
 * Register for push notifications. Silently no-ops if:
 *   - Push API is unsupported
 *   - The user denies permission
 *   - VAPID keys are not configured on the server
 */
export async function registerForPushNotifications(): Promise<void> {
  try {
    console.info('[Push] Starting push registration...');

    // Guard: push must be supported
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
      console.warn('[Push] Push notifications are not supported in this browser');
      return;
    }

    // 1. Fetch the VAPID public key from the backend
    console.info('[Push] Fetching VAPID public key...');
    const { data: keyRes } = await api.get('/push/vapid-public-key');
    const vapidPublicKey: string | undefined = keyRes?.data?.vapidPublicKey;
    if (!vapidPublicKey) {
      console.warn('[Push] Server has no VAPID key configured — skipping');
      return;
    }
    console.info('[Push] Got VAPID key, waiting for service worker...');

    // 2. Wait for the service worker to be ready
    const registration = await navigator.serviceWorker.ready;

    // 3. Request notification permission
    const permission = await Notification.requestPermission();
    if (permission !== 'granted') {
      console.info('[Push] Notification permission denied');
      return;
    }

    // 4. Subscribe (or retrieve existing subscription)
    let subscription = await registration.pushManager.getSubscription();
    if (!subscription) {
      subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(vapidPublicKey) as BufferSource,
      });
    }

    // 5. Send subscription to the backend
    await api.post('/push/subscribe', { subscription: subscription.toJSON() });
    console.info('[Push] Subscription registered with server');
  } catch (err) {
    // Non-fatal — the app works fine without push
    console.warn('[Push] Failed to register push notifications:', err);
  }
}
