import { defineConfig } from 'vite';
import type { Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { VitePWA } from 'vite-plugin-pwa';
import { fileURLToPath, URL } from 'node:url';

/**
 * Suppress transient EPIPE / ECONNRESET errors from the WS proxy.
 * These occur when the client or backend closes a WebSocket before
 * the proxy finishes writing — harmless during development.
 */
function suppressProxyEpipe(): Plugin {
  return {
    name: 'suppress-proxy-epipe',
    configureServer(server) {
      server.httpServer?.on('upgrade', (_req, socket) => {
        socket.on('error', (err: NodeJS.ErrnoException) => {
          if (err.code === 'EPIPE' || err.code === 'ECONNRESET') return;
          console.error('[ws proxy]', err);
        });
      });
    },
  };
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    suppressProxyEpipe(),
    VitePWA({
      registerType: 'autoUpdate',
      strategies: 'injectManifest',
      srcDir: 'src',
      filename: 'sw.ts',
      manifest: {
        name: 'Tenebra Secure Messenger',
        short_name: 'Tenebra',
        description: 'Zero-knowledge E2EE messenger',
        theme_color: '#000000',
        background_color: '#000000',
        display: 'standalone',
        icons: [
          {
            src: '/icon-192.png',
            sizes: '192x192',
            type: 'image/png',
          },
          {
            src: '/icon-512.png',
            sizes: '512x512',
            type: 'image/png',
          },
          {
            src: '/icon-512.png',
            sizes: '512x512',
            type: 'image/png',
            purpose: 'maskable',
          },
        ],
      },
    }),
  ],

  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },

  server: {
    // Proxy API calls to the backend during development.
    // Override via VITE_API_URL env var (e.g. VITE_API_URL=http://192.168.1.10:3000).
    proxy: {
      '/api': {
        target: process.env.VITE_API_URL || 'http://localhost:3000',
        changeOrigin: true,
      },
      '/socket.io': {
        target: process.env.VITE_API_URL || 'http://localhost:3000',
        changeOrigin: true,
        ws: true,
      },
    },
  },
});
