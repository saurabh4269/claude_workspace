# syntax=docker/dockerfile:1

# Stage 1: build
FROM node:20-alpine AS builder

WORKDIR /app

# Copy manifests first so this layer is cached unless deps change
COPY package.json package-lock.json* ./

# npm ci is faster and strictly reproducible; falls back to npm install if no lockfile
RUN npm ci --prefer-offline 2>/dev/null || npm install --prefer-offline

# Copy source and build (vite build only - tsc type checking runs separately in CI)
COPY . .
RUN npx vite build

# Stage 2: runtime (nginx-alpine is ~7 MB)
FROM nginx:1.27-alpine AS runtime

# Remove default nginx static assets
RUN rm -rf /usr/share/nginx/html/*

# Copy built assets from builder
COPY --from=builder /app/dist /usr/share/nginx/html

# React Router: all routes serve index.html; /api proxies to backend service
RUN printf 'server {\n\
    listen 80;\n\
    root /usr/share/nginx/html;\n\
    index index.html;\n\
    client_max_body_size 52m;\n\
    gzip on;\n\
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml image/svg+xml;\n\
    location / {\n\
        try_files $uri $uri/ /index.html;\n\
    }\n\
    location /api {\n\
        proxy_pass http://backend:8000;\n\
        proxy_set_header Host $host;\n\
        proxy_set_header X-Real-IP $remote_addr;\n\
        proxy_read_timeout 120s;\n\
    }\n\
}\n' > /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
