/**
 * API Client — Preconfigured Axios instance for Tenebra backend.
 *
 * • Base URL is `/api` — Vite dev proxy forwards it to the backend.
 * • An interceptor attaches the JWT (if present) on every request.
 * • A helper lets other services set / clear the token.
 */

import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
  timeout: 15_000,
});

// ─── Token management ──────────────────────────────────────────────────────────

let authToken: string | null = null;

/**
 * Store the JWT in memory only.
 *
 * The token is intentionally **not** persisted to `sessionStorage` or
 * `localStorage` to prevent XSS exfiltration.  A page reload will
 * require re-authentication, which is the desired security trade-off.
 */
export function setToken(token: string): void {
  authToken = token;
}

/** Clear the stored JWT (logout). */
export function clearToken(): void {
  authToken = null;
}

/** Return the current in-memory JWT. */
export function getToken(): string | null {
  return authToken;
}

// ─── Request interceptor ───────────────────────────────────────────────────────

api.interceptors.request.use((config) => {
  const token = getToken();
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export default api;
