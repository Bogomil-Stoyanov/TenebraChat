import dotenv from 'dotenv';

dotenv.config();

export const config = {
  server: {
    port: parseInt(process.env.PORT || '3000', 10),
    nodeEnv: process.env.NODE_ENV || 'development',
  },
  database: {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432', 10),
    database: process.env.DB_NAME || 'tenebra',
    user: process.env.DB_USER || 'tenebra_user',
    password: process.env.DB_PASSWORD || 'your_secure_password_here',
  },
  minio: {
    endPoint: process.env.MINIO_ENDPOINT || 'localhost',
    port: parseInt(process.env.MINIO_PORT || '9000', 10),
    accessKey: process.env.MINIO_ACCESS_KEY || 'minioadmin',
    secretKey: process.env.MINIO_SECRET_KEY || 'minioadmin',
    bucket: process.env.MINIO_BUCKET || 'tenebra-files',
    useSSL: process.env.MINIO_USE_SSL === 'true',
  },
  jwt: {
    secret: process.env.JWT_SECRET || 'change-this-to-a-secure-random-string',
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
  },
};
