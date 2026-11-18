# Honeypot Framework - Nightwatch dashboard.
# Builds the Vite app, then serves it from nginx, which also proxies the API
# so the browser talks to a single origin (no CORS setup required).

FROM node:24-alpine AS build

WORKDIR /app

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build


FROM nginx:1.27-alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    # 127.0.0.1, not localhost: in this image localhost resolves to ::1 first,
    # nginx.conf only listens on IPv4, and the check failed while the site was up.
    CMD wget -qO- http://127.0.0.1/ >/dev/null || exit 1
