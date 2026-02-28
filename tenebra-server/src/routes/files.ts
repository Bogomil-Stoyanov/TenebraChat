import { Router, Request, Response } from 'express';
import { minioService } from '../services/MinioService';
import { ApiResponse } from '../types';

const router = Router();

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

    const objectName = `${Date.now()}-${filename}`;
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
