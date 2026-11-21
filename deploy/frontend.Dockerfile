FROM oven/bun:1.4 AS build

WORKDIR /app

COPY frontend/package.json frontend/bun.lock ./
RUN bun install --frozen-lockfile

COPY frontend/index.html frontend/vite.config.ts frontend/svelte.config.js frontend/tsconfig*.json ./
COPY frontend/src ./src
COPY frontend/public ./public
RUN bun --bun run build

FROM nginx:alpine
COPY deploy/frontend.nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist/ /usr/share/nginx/html/

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1/index.html || exit 1
