# Stage 1: Build the React Admin Console
FROM node:20-alpine AS console-builder
WORKDIR /console
COPY console/package*.json ./
RUN npm ci --no-audit --no-fund
COPY console/ ./
RUN npm run build

# Stage 2: Build the Python Gateway image with bundled Admin Console static UI
FROM python:3.11-slim AS runtime
WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ANONIX_HOST=0.0.0.0 \
    ANONIX_PORT=8000 \
    ANONIX_DATA_DIR=/data

RUN useradd --create-home --uid 10001 anonix && mkdir -p /data && chown -R anonix:anonix /data /app

COPY pyproject.toml README.md LICENSE ./
COPY alembic.ini ./
COPY alembic ./alembic
COPY src ./src
COPY --from=console-builder /console/dist ./src/anonix_gateway/static

RUN pip install --no-cache-dir .

USER anonix
VOLUME ["/data"]
EXPOSE 8000

CMD ["anonix-gateway", "serve"]
