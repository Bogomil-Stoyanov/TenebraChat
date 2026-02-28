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
 * Store the JWT in memory and persist it in sessionStorage so it
 * survives soft navigations but is cleared when the tab closes.
 */
export function setToken(token: string): void {
    authToken = token;
    sessionStorage.setItem('tenebra_jwt', token);
}

/** Clear the stored JWT (logout). */
export function clearToken(): void {
    authToken = null;
    sessionStorage.removeItem('tenebra_jwt');
}

/** Return the current JWT (from memory or sessionStorage). */
export function getToken(): string | null {
    if (!authToken) {
        authToken = sessionStorage.getItem('tenebra_jwt');
    }
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
