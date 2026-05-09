# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Build args for environment
ARG VITE_API_URL=
ENV VITE_API_URL=$VITE_API_URL

# Edition flag (NAN-745). `enterprise` (default) keeps the @/enterprise/*
# alias pointed at the real implementations under src/enterprise/. `open`
# swaps it to the no-op stubs under src/enterprise-stubs/ for the open-core
# release. Mirrors the cargo edition flag in the root Dockerfile.
ARG VITE_EDITION=open
ENV VITE_EDITION=$VITE_EDITION

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy source
COPY . .

# Build
RUN npm run build

# Production stage - serve with nginx
FROM nginx:alpine

# Copy built assets
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy nginx config for SPA routing (use port 5173 to match dev server)
# Configure nginx to run as non-root (pid in /tmp, no access log to file)
RUN echo 'pid /tmp/nginx.pid; \
events { worker_connections 1024; } \
http { \
    include /etc/nginx/mime.types; \
    default_type application/octet-stream; \
    client_body_temp_path /tmp/client_body; \
    proxy_temp_path /tmp/proxy; \
    fastcgi_temp_path /tmp/fastcgi; \
    uwsgi_temp_path /tmp/uwsgi; \
    scgi_temp_path /tmp/scgi; \
    access_log /dev/stdout; \
    error_log /dev/stderr; \
    server { \
        listen 5173; \
        root /usr/share/nginx/html; \
        index index.html; \
        location / { \
            try_files $uri $uri/ /index.html; \
        } \
    } \
}' > /etc/nginx/nginx.conf && \
    rm -f /etc/nginx/conf.d/default.conf && \
    chown -R nginx:nginx /usr/share/nginx/html /var/cache/nginx /etc/nginx && \
    chmod -R 755 /usr/share/nginx/html

EXPOSE 5173

# Use numeric UID for K8s runAsNonRoot validation (nginx = 101 in alpine)
USER 101

CMD ["nginx", "-g", "daemon off;"]
