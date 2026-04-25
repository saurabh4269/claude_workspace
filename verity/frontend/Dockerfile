# syntax=docker/dockerfile:1

# Stage 1: build
FROM node:20-alpine AS builder

WORKDIR /app

# Copy manifests first — this layer is cached until lock file changes
COPY package.json package-lock.json ./

# Cache mount keeps npm's content-addressable store across builds
RUN --mount=type=cache,target=/root/.npm \
    npm ci --prefer-offline --ignore-scripts

COPY . .
ENV NODE_ENV=production
RUN npx vite build

# Stage 2: runtime (~7 MB nginx-alpine)
FROM nginx:1.27-alpine AS runtime

RUN rm -rf /usr/share/nginx/html/*

COPY --link --from=builder /app/dist /usr/share/nginx/html

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
