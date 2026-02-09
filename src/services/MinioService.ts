import * as Minio from 'minio';
import { config } from '../config';
import { v4 as uuidv4 } from 'uuid';

class MinioService {
    private client: Minio.Client;
    private bucket: string;

    constructor() {
        this.client = new Minio.Client({
            endPoint: config.minio.endPoint,
            port: config.minio.port,
            useSSL: config.minio.useSSL,
            accessKey: config.minio.accessKey,
            secretKey: config.minio.secretKey,
        });
        this.bucket = config.minio.bucket;
    }

    async initialize(): Promise<void> {
        try {
            const exists = await this.client.bucketExists(this.bucket);
            if (!exists) {
                await this.client.makeBucket(this.bucket);
                console.log(`Bucket '${this.bucket}' created successfully`);
            }
        } catch (error) {
            console.error('Failed to initialize MinIO bucket:', error);
            throw error;
        }
    }

    async uploadFile(
        buffer: Buffer,
        contentType: string,
        metadata?: Record<string, string>
    ): Promise<string> {
        const fileId = uuidv4();
        const objectName = `${fileId}`;

        await this.client.putObject(
            this.bucket,
            objectName,
            buffer,
            buffer.length,
            {
                'Content-Type': contentType,
                ...metadata,
            }
        );

        return objectName;
    }

    async downloadFile(objectName: string): Promise<Buffer> {
        return new Promise((resolve, reject) => {
            const chunks: Buffer[] = [];

            this.client.getObject(this.bucket, objectName, (err, stream) => {
                if (err) {
                    reject(err);
                    return;
                }

                stream.on('data', (chunk: Buffer) => chunks.push(chunk));
                stream.on('end', () => resolve(Buffer.concat(chunks)));
                stream.on('error', reject);
            });
        });
    }

    async deleteFile(objectName: string): Promise<void> {
        await this.client.removeObject(this.bucket, objectName);
    }

    async getPresignedUrl(objectName: string, expirySeconds: number = 3600): Promise<string> {
        return this.client.presignedGetObject(this.bucket, objectName, expirySeconds);
    }

    async getPresignedUploadUrl(
        objectName: string,
        expirySeconds: number = 3600
    ): Promise<string> {
        return this.client.presignedPutObject(this.bucket, objectName, expirySeconds);
    }

    async fileExists(objectName: string): Promise<boolean> {
        try {
            await this.client.statObject(this.bucket, objectName);
            return true;
        } catch {
            return false;
        }
    }

    async getFileInfo(objectName: string): Promise<Minio.BucketItemStat | null> {
        try {
            return await this.client.statObject(this.bucket, objectName);
        } catch {
            return null;
        }
    }
}

export const minioService = new MinioService();
