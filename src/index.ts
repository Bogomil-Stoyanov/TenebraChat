import express, { Application, Request, Response, NextFunction } from 'express';
import { createServer } from 'http';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { config } from './config';
import { minioService } from './services/MinioService';
import './database/connection';
import userRoutes from './routes/users';
import keyRoutes from './routes/keys';
import messageRoutes from './routes/messages';
import fileRoutes from './routes/files';
import authRoutes from './routes/auth';
import { authenticate } from './middleware/auth';
import { AuthChallenge } from './models';
import { initSocket } from './socket';

const app: Application = express();
const httpServer = createServer(app);

// Rate limiter for authenticated API routes
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests, please try again later.' },
});

// Stricter rate limiter for file operations
const fileLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many file requests, please try again later.' },
});

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
app.use('/api/auth', authRoutes);
app.use('/api/keys', apiLimiter, authenticate, keyRoutes);
app.use('/api/messages', apiLimiter, authenticate, messageRoutes);
app.use('/api/files', fileLimiter, authenticate, fileRoutes);

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

    // Initialise Socket.io on the shared HTTP server
    initSocket(httpServer);

    httpServer.listen(config.server.port, () => {
      // Periodically clean up expired auth challenges (every 5 minutes)
      setInterval(
        () => {
          AuthChallenge.cleanupExpired().catch((err) => {
            console.error('Failed to clean up expired auth challenges:', err);
          });
        },
        5 * 60 * 1000
      );

      console.log(`
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║   🌑 TENEBRA E2EE Chat Server                             ║
║                                                            ║
║   Server running on port ${config.server.port.toString().padEnd(30)}║
║   Environment: ${config.server.nodeEnv.padEnd(39)}║
║                                                            ║
║   HTTP Endpoints:                                          ║
║   • GET  /health              - Health check               ║
║   • POST /api/users/register  - Register user              ║
║   • POST /api/auth/challenge  - Auth challenge             ║
║   • POST /api/auth/verify     - Verify & get JWT           ║
║   • POST /api/auth/logout     - Logout                     ║
║   • POST /api/keys/*          - Key management             ║
║   • POST /api/messages/send   - Send message               ║
║   • GET  /api/messages/offline - Fetch offline messages    ║
║   • POST /api/files/*         - File storage               ║
║                                                            ║
║   WebSocket:                                               ║
║   • Socket.io (JWT auth via handshake)                     ║
║   • Events: new_message                                    ║
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

export { app, httpServer };
