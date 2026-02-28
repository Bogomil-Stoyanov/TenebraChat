# Tenebra Web Client

The browser-based frontend for the Tenebra secure messaging platform.

## Tech Stack

| Layer         | Technology                            |
| ------------- | ------------------------------------- |
| Framework     | React 18 + TypeScript 5               |
| Build         | Vite 5                                |
| Styling       | Tailwind CSS v4                       |
| Local Storage | Dexie (IndexedDB)                     |
| Encryption    | Web Crypto API (PBKDF2 + AES-GCM-256) |
| Icons         | Lucide React                          |

## Security Architecture

All sensitive material (private keys, session state) is encrypted at rest inside the browser's IndexedDB using:

- **PBKDF2** (SHA-256, 600 000 iterations) to derive a 256-bit key from the user's local password.
- **AES-GCM** (256-bit, random 12-byte IV) to encrypt / decrypt payloads.
- A verification token stored alongside the salt lets the app confirm a correct password without exposing key material.

> **Note:** The local password never leaves the browser — it is not sent to the backend.

## Getting Started

```bash
# Install dependencies
npm install

# Start the dev server (proxies /api to the backend on port 3000)
npm run dev

# Override the backend URL if needed
VITE_API_URL=http://192.168.1.10:3000 npm run dev
```

## Available Scripts

| Script            | Description                          |
| ----------------- | ------------------------------------ |
| `npm run dev`     | Start Vite dev server with HMR       |
| `npm run build`   | Type-check and build for production  |
| `npm run preview` | Preview the production build locally |
| `npm run lint`    | Run ESLint                           |

## Project Structure

```
src/
├── db/              # Dexie database schema & encrypted tables
├── services/        # SecurityService (PBKDF2 + AES-GCM)
├── App.tsx          # Root component (unlock / setup screen)
├── main.tsx         # Vite entry point
└── index.css        # Tailwind imports
```

## Backend Integration

During development, Vite proxies `/api` and `/socket.io` requests to the backend (`tenebra-server`). The target defaults to `http://localhost:3000` and can be overridden with the `VITE_API_URL` environment variable.
