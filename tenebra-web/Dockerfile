# ── Build stage ──────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies first (layer caching)
COPY package*.json ./
RUN npm ci

# Copy source & build
COPY tsconfig.json tsconfig.app.json tsconfig.node.json ./
COPY index.html ./
COPY vite.config.ts ./
COPY src ./src
COPY public ./public

RUN npm run build

# ── Production stage — Nginx serves the static SPA ─────────────────────────
FROM nginx:1.27-alpine AS production

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# Create cache/pid dirs and grant nginx user ownership
RUN mkdir -p /var/cache/nginx/client_temp \
             /var/cache/nginx/proxy_temp \
             /var/cache/nginx/fastcgi_temp \
             /var/cache/nginx/uwsgi_temp \
             /var/cache/nginx/scgi_temp \
    && chown -R nginx:nginx /var/cache/nginx \
    && chown -R nginx:nginx /var/log/nginx \
    && sed -i 's|/run/nginx.pid|/tmp/nginx.pid|' /etc/nginx/nginx.conf

# Copy our custom Nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy built assets from the builder
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80

USER nginx

CMD ["nginx", "-g", "daemon off;"]
