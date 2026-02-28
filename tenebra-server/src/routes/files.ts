import { Router, Request, Response } from 'express';
import express from 'express';
import { randomUUID } from 'crypto';
import { minioService } from '../services/MinioService';
import { ApiResponse } from '../types';

/** Strip path separators and control characters from user-supplied filenames. */
function sanitizeFilename(raw: string): string {
  return raw.replace(/[\/\\\x00-\x1f]/g, '_').slice(0, 255);
}

const router = Router();

// ─── Direct upload (client → backend → MinIO) ────────────────────────────────
// Accepts raw binary body up to 50 MB.  The original filename is passed via
// the X-Filename header so an object name can be generated.
router.post(
  '/upload',
  express.raw({ type: 'application/octet-stream', limit: '50mb' }),
  async (req: Request, res: Response) => {
    try {
      const body = req.body;
      if (!Buffer.isBuffer(body) || body.length === 0) {
        const response: ApiResponse = { success: false, error: 'Empty or invalid body' };
        return res.status(400).json(response);
      }

      const filename = sanitizeFilename((req.headers['x-filename'] as string) || 'encrypted.bin');
      const objectName = `${Date.now()}-${randomUUID()}-${filename}`;

      const storedName = await minioService.uploadFileWithName(
        objectName,
        body,
        'application/octet-stream'
      );

      const response: ApiResponse<{ object_name: string }> = {
        success: true,
        data: { object_name: storedName },
      };
      return res.json(response);
    } catch (error) {
      console.error('Error uploading file:', error);
      const response: ApiResponse = { success: false, error: 'Internal server error' };
      return res.status(500).json(response);
    }
  }
);

// ─── Direct download (MinIO → backend → client) ──────────────────────────────
router.get('/download/:objectName', async (req: Request, res: Response) => {
  try {
    const { objectName } = req.params;

    const exists = await minioService.fileExists(objectName);
    if (!exists) {
      const response: ApiResponse = { success: false, error: 'File not found' };
      return res.status(404).json(response);
    }

    const buffer = await minioService.downloadFile(objectName);
    res.set('Content-Type', 'application/octet-stream');
    res.set('Content-Length', String(buffer.length));
    return res.send(buffer);
  } catch (error) {
    console.error('Error downloading file:', error);
    const response: ApiResponse = { success: false, error: 'Internal server error' };
    return res.status(500).json(response);
  }
});

// ─── Presigned URL endpoints (kept for backward compatibility) ────────────────

// Get a presigned URL for uploading a file
router.post('/upload-url', async (req: Request, res: Response) => {
  try {
    const { filename, expiry = 3600 } = req.body;

    if (!filename) {
      const response: ApiResponse = {
        success: false,
        error: 'Missing required field: filename',
      };
      return res.status(400).json(response);
    }

    const objectName = `${Date.now()}-${randomUUID()}-${sanitizeFilename(filename)}`;
    const url = await minioService.getPresignedUploadUrl(objectName, expiry);

    const response: ApiResponse<{ url: string; object_name: string; expires_in: number }> = {
      success: true,
      data: {
        url,
        object_name: objectName,
        expires_in: expiry,
      },
    };
    return res.json(response);
  } catch (error) {
    console.error('Error generating upload URL:', error);
    const response: ApiResponse = {
      success: false,
      error: 'Internal server error',
    };
    return res.status(500).json(response);
  }
});

// Get a presigned URL for downloading a file
router.get('/download-url/:objectName', async (req: Request, res: Response) => {
  try {
    const { objectName } = req.params;
    const { expiry = 3600 } = req.query;

    const exists = await minioService.fileExists(objectName);
    if (!exists) {
      const response: ApiResponse = {
        success: false,
        error: 'File not found',
      };
      return res.status(404).json(response);
    }

    const url = await minioService.getPresignedUrl(objectName, parseInt(expiry as string, 10));

    const response: ApiResponse<{ url: string; expires_in: number }> = {
      success: true,
      data: {
        url,
        expires_in: parseInt(expiry as string, 10),
      },
    };
    return res.json(response);
  } catch (error) {
    console.error('Error generating download URL:', error);
    const response: ApiResponse = {
      success: false,
      error: 'Internal server error',
    };
    return res.status(500).json(response);
  }
});

// Get file info
router.get('/info/:objectName', async (req: Request, res: Response) => {
  try {
    const { objectName } = req.params;

    const info = await minioService.getFileInfo(objectName);
    if (!info) {
      const response: ApiResponse = {
        success: false,
        error: 'File not found',
      };
      return res.status(404).json(response);
    }

    const response: ApiResponse<typeof info> = {
      success: true,
      data: info,
    };
    return res.json(response);
  } catch (error) {
    console.error('Error getting file info:', error);
    const response: ApiResponse = {
      success: false,
      error: 'Internal server error',
    };
    return res.status(500).json(response);
  }
});

// Delete a file
router.delete('/:objectName', async (req: Request, res: Response) => {
  try {
    const { objectName } = req.params;

    const exists = await minioService.fileExists(objectName);
    if (!exists) {
      const response: ApiResponse = {
        success: false,
        error: 'File not found',
      };
      return res.status(404).json(response);
    }

    await minioService.deleteFile(objectName);

    const response: ApiResponse = {
      success: true,
      message: 'File deleted successfully',
    };
    return res.json(response);
  } catch (error) {
    console.error('Error deleting file:', error);
    const response: ApiResponse = {
      success: false,
      error: 'Internal server error',
    };
    return res.status(500).json(response);
  }
});

export default router;
