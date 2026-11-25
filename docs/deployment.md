# Deployment, Configuration & Setup Guide

Anonix Gateway can be deployed in four ways—from a 60-second Docker Compose stack with a built-in demo API, to an Enterprise BYOD setup wired into your existing PostgreSQL/Redis, to a standalone Python CLI.

---

## 1. Environment Configuration Reference (`ANONIX_*`)

All settings can be passed as environment variables or placed in a `.env` file:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `ANONIX_ENV` | `development` | `development` (auto-generates & persists keys in `ANONIX_DATA_DIR`) or `production` (fails closed if `ANONIX_MASTER_KEY` or `ANONIX_ADMIN_JWT_SECRET` is missing). |
| `ANONIX_HOST` | `0.0.0.0` | Bind host for the ASGI server. |
| `ANONIX_PORT` | `8000` | Listen port (Docker Compose maps `${ANONIX_PORT:-8000}:8000`). |
| `ANONIX_LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |
| `ANONIX_TENANCY_MODE` | `single_org` | `single_org` (default) or `multi_tenant` (`X-Anonix-Tenant`). |
| `ANONIX_DATABASE_URL` | *(SQLite)* | Async SQLAlchemy URL. Leave blank for `./data/anonix.db`, or set `postgresql+asyncpg://user:pass@host:5432/db`. |
| `ANONIX_REDIS_URL` | *(empty)* | Optional `redis://host:6379/0` for shared rate limiting across multiple gateway replicas. Omit for built-in in-memory rate limiting. |
| `ANONIX_MASTER_KEY` | *(auto in dev)* | Fernet key encrypting upstream credentials & OIDC client secrets. Generate with `anonix-gateway keygen`. |
| `ANONIX_ADMIN_JWT_SECRET` | *(auto in dev)* | HS256 signing secret for Control Plane admin JWTs. Generate with `anonix-gateway keygen`. |
| `ANONIX_DATA_DIR` | `./data` | Directory for SQLite DB and auto-generated dev `.anonix_secrets.json`. |
| `ANONIX_ALLOW_PRIVATE_UPSTREAMS` | `false` (`true` in Compose) | Allow `/proxy/*` to reach private/VPC/loopback upstream IPs. Cloud metadata IPs remain unconditionally blocked. |
| `ANONIX_BOOTSTRAP_ADMIN_EMAIL` | *(empty)* | Optional headless first-run admin email (skips web `/setup` wizard). |
| `ANONIX_BOOTSTRAP_ADMIN_PASSWORD` | *(empty)* | Optional headless first-run admin password (used with `ANONIX_BOOTSTRAP_ADMIN_EMAIL`). |
| `ANONIX_BOOTSTRAP_ORG_NAME` | `Default Organization` | Organization name created during headless bootstrap. |
| `ANONIX_ADMIN_TOKEN_TTL_MINUTES` | `480` | Admin console session JWT lifetime in minutes (8 hours). |
| `ANONIX_RATE_LIMIT_PER_MINUTE` | `120` | Data-plane per-caller requests per minute. |
| `ANONIX_MAX_PAYLOAD_BYTES` | `10485760` | Maximum inbound/upstream payload size in bytes (10 MiB). |
| `ANONIX_CORS_ORIGINS` | *(empty)* | Comma-separated CORS origins (e.g. `http://localhost:5173` during frontend dev). |
| `ANONIX_SSL_CERTFILE` / `ANONIX_SSL_KEYFILE` | *(empty)* | Paths to PEM certificate and private key for direct native HTTPS without a reverse proxy. |
| `ANONIX_DOMAIN` | `localhost` | Domain used by Caddy (`--profile tls`) for automatic Let's Encrypt HTTPS. |

---

## 2. Option A: Bundled Docker Compose (Fastest)

Starts **PostgreSQL 16** and **Anonix Gateway** (serving both the API and React Admin Console on port `8000`) with built-in in-memory rate limiting:

```bash
git clone https://github.com/lovepop1/Anonix-gateway.git
cd Anonix-gateway
cp .env.example .env

# Postgres + Gateway (default):
docker compose up -d --build

# Optional: add bundled Redis for multi-replica rate limiting:
docker compose -f docker-compose.yml -f docker-compose.redis.yml up -d --build
```

> **Windows Note:** If ports `8000` or `8080` are reserved by Hyper-V/WinNAT, override them in PowerShell before `docker compose up`:
> ```powershell
> $env:ANONIX_PORT="9000"
> $env:ANONIX_DEMO_PORT="9080"
> docker compose --profile demo up -d --build
> ```

1. Verify containers: `docker compose ps` (`postgres`, `redis`, `gateway`, `demo-upstream` should be healthy).
2. Open `http://localhost:8000` (or `:9000`) to complete the one-time `/setup` wizard and create your `platform_admin` account.
3. Follow the [5-Minute Live Demo Guide](demo-guide.md) and [Policy Authoring Guide](policies.md) to configure your first policy, group mapping, API key, upstream, and proxy route.

---

## 3. Scenario B: Enterprise BYOD (Existing PostgreSQL & Optional Redis)

Use `docker-compose.byod.yml` when your organization runs managed PostgreSQL (AWS RDS, Azure Database, Cloud SQL, or on-prem) and optionally Redis:

1. **Provision an empty database** and user with DDL privileges on your PostgreSQL server.
2. **Generate production secrets:**
   ```bash
   anonix-gateway keygen >> .env
   ```
   *(Or generate a Fernet `ANONIX_MASTER_KEY` and random `ANONIX_ADMIN_JWT_SECRET` in your secrets manager.)*
3. **Configure `.env`:**
   ```env
   ANONIX_ENV=production
   ANONIX_DATABASE_URL=postgresql+asyncpg://anonix_user:strong_pass@db.company.internal:5432/anonix
   # Optional: omit for built-in in-memory rate limiting
   ANONIX_REDIS_URL=redis://redis.company.internal:6379/0
   ANONIX_ALLOW_PRIVATE_UPSTREAMS=true
   ```
4. **Run the gateway container:**
   ```bash
   # BYOD Postgres + built-in in-memory rate limiting (or external ANONIX_REDIS_URL):
   docker compose -f docker-compose.byod.yml up -d

   # OR BYOD Postgres + bundled Docker Redis:
   docker compose -f docker-compose.byod.yml -f docker-compose.redis.yml up -d
   ```
   Tables are created automatically on startup (or you can run `alembic upgrade head` explicitly in CI/CD before rolling out replicas).

---

## 4. Scenario C: Single-Node PyPI CLI (No Docker Required)

Requires **Python 3.11+**:

```bash
pip install anonix-gateway
anonix-gateway init
anonix-gateway serve --port 8000
```

* `anonix-gateway init` generates `.env` secrets, initializes the database (SQLite `./data/anonix.db` by default if `ANONIX_DATABASE_URL` is blank), and interactively creates the first `platform_admin`.
* **Headless/CI alternative:** Skip `init` and set `ANONIX_BOOTSTRAP_ADMIN_EMAIL` + `ANONIX_BOOTSTRAP_ADMIN_PASSWORD` in `.env`, then run `anonix-gateway serve`.
* **Native TLS on a VM:**
  ```bash
  anonix-gateway serve --port 8443 --ssl-certfile /etc/certs/fullchain.pem --ssl-keyfile /etc/certs/privkey.pem
  ```

---

## 5. Scenario D: Production TLS & Edge Proxy Integration

See [SETUP.md — Scenario 4](../SETUP.md#7-scenario-4-production-https--tls-3-options) for the full TLS guide. Summary:

1. **Automatic HTTPS with Caddy (`--profile tls` in `docker-compose.yml`):**
   ```bash
   ANONIX_DOMAIN=mask.company.com docker compose --profile tls up -d
   ```
   Requires public DNS pointing to your host and ports `80`/`443` open for Let's Encrypt (otherwise Caddy falls back to an internal self-signed CA).
2. **Behind NGINX / Kong / AWS ALB (recommended for Cloud, Kubernetes & BYOD):**
   Terminate TLS at your load balancer, forward HTTP to `gateway:8000` (health check `/healthz` or `/readyz`), and optionally pass Trusted-Proxy headers—see [`examples/nginx-trusted-proxy.conf`](../examples/nginx-trusted-proxy.conf) and [Authentication Guide](authentication.md).
3. **Direct Native TLS (standalone VM / PyPI CLI only):**
   Pass `--ssl-certfile` and `--ssl-keyfile` to `anonix-gateway serve` (do not set these inside Docker Compose, as the container healthcheck probes `http://localhost:8000/healthz`).

---

## 6. Operations & Troubleshooting

* **Probes:** `GET /healthz` (liveness) and `GET /readyz` (verifies database connectivity).
* **Database Migrations:** `alembic upgrade head`.
* **Startup fails in production (`RuntimeError`):** Both `ANONIX_MASTER_KEY` and `ANONIX_ADMIN_JWT_SECRET` are mandatory when `ANONIX_ENV=production`.
* **Upstream `502` or SSRF block:** Internal/VPC upstreams (`10.x`, `172.16.x`, `192.168.x`, `127.0.0.1`) require `ANONIX_ALLOW_PRIVATE_UPSTREAMS=true`.
* **Upstream `404` on `/proxy/*`:** Check the **Strip prefix** checkbox on your `ProxyRoute`. Uncheck it if the upstream expects the prefix path (e.g. `demo-upstream` serves `/students/{id}`, so `/proxy/students/101` with strip unchecked forwards `/students/101`).
