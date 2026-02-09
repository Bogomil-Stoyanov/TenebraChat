import express, { Application, Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { config } from './config';
import { minioService } from './services/MinioService';
import './database/connection';
import userRoutes from './routes/users';
import keyRoutes from './routes/keys';
import messageRoutes from './routes/messages';
import fileRoutes from './routes/files';

const app: Application = express();

app.use(helmet());
app.use(cors());

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

app.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
  });
});

app.use('/api/users', userRoutes);
app.use('/api/keys', keyRoutes);
app.use('/api/messages', messageRoutes);
app.use('/api/files', fileRoutes);

app.use((req: Request, res: Response) => {
  res.status(404).json({
    success: false,
    error: 'Not found',
  });
});

app.use((err: Error, req: Request, res: Response, _next: NextFunction) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    error: config.server.nodeEnv === 'development' ? err.message : 'Internal server error',
  });
});

async function startServer() {
  try {
    try {
      await minioService.initialize();
      console.log('✅ MinIO initialized');
    } catch {
      console.warn('⚠️  MinIO not available - file storage disabled');
      console.warn('   Start MinIO with: docker-compose up -d minio');
    }

    app.listen(config.server.port, () => {
      console.log(`
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║   🌑 TENEBRA E2EE Chat Server                             ║
║                                                            ║
║   Server running on port ${config.server.port.toString().padEnd(30)}║
║   Environment: ${config.server.nodeEnv.padEnd(39)}║
║                                                            ║
║   Endpoints:                                               ║
║   • GET  /health              - Health check               ║
║   • POST /api/users/register  - Register user              ║
║   • POST /api/keys/*          - Key management             ║
║   • POST /api/messages/*      - Message queue              ║
║   • POST /api/files/*         - File storage               ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
      `);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();

export default app;
