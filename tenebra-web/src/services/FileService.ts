/**
 * FileService — Upload / download encrypted blobs via the Tenebra backend.
 *
 * All traffic is proxied through the backend — the client never talks to
 * MinIO directly:
 *   POST /api/files/upload                  → { object_name }
 *   GET  /api/files/download/:objectName    → raw binary
 *
 * The client always encrypts files *before* upload so MinIO only
 * ever stores opaque ciphertext.
 */

import api from '@/api/client';

// ─── Public API ────────────────────────────────────────────────────────────────

export interface UploadResult {
    /** MinIO object name (used as the file identifier). */
    objectName: string;
}

/**
 * Upload an already-encrypted blob through the backend to MinIO.
 *
 * 1. POST the raw binary to `/api/files/upload` with the filename in a header.
 * 2. The backend stores it in MinIO and returns the `object_name`.
 */
export async function uploadEncryptedFile(
    encryptedBlob: Blob,
    filename = 'encrypted.bin',
): Promise<UploadResult> {
    const res = await api.post('/files/upload', encryptedBlob, {
        headers: {
            'Content-Type': 'application/octet-stream',
            'X-Filename': filename,
        },
        // Prevent Axios from JSON-encoding the blob
        transformRequest: [(data: Blob) => data],
    });

    const { object_name } = res.data.data as { object_name: string };
    return { objectName: object_name };
}

/**
 * Download an encrypted file from the backend (which fetches it from MinIO).
 *
 * @param objectName The MinIO object name returned by {@link uploadEncryptedFile}.
 */
export async function downloadEncryptedFile(objectName: string): Promise<Blob> {
    const res = await api.get(`/files/download/${encodeURIComponent(objectName)}`, {
        responseType: 'blob',
    });
    return res.data as Blob;
}
