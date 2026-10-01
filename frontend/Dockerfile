FROM node:22-alpine AS build

WORKDIR /web
COPY package.json package-lock.json ./
RUN npm ci
COPY index.html vite.config.ts tsconfig.json ./
COPY src/ ./src/
ARG VITE_TRAILWEAVER_API_URL=/
ENV VITE_TRAILWEAVER_API_URL=${VITE_TRAILWEAVER_API_URL}
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine AS runtime
ENV TRAILWEAVER_API_UPSTREAM=api:8000 \
    NGINX_ENVSUBST_FILTER=TRAILWEAVER_API_UPSTREAM
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /web/dist/ /usr/share/nginx/html/
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/healthz"]
