# Deployment & BYOD Guide

Anonix Gateway supports three deployment models so organizations can start in seconds or integrate cleanly into existing enterprise infrastructure.

---

## 1. Option A: Bundled Docker Compose (Fastest)

Starts `postgres`, `redis`, and `gateway` (serving both the API and the React Admin Console on port `8000`):

```bash
cp .env.example .env
docker compose up -d
```

Open `http://localhost:8000` to create your initial `platform_admin` account.

To include the optional mock upstream API for testing:
```bash
docker compose --profile demo up -d
```

---

## 2. Option B: Enterprise BYOD (Bring Your Own PostgreSQL / Redis)

If your organization manages its own PostgreSQL (AWS RDS, Azure Database for PostgreSQL, Cloud SQL, or on-prem) and optionally Redis:

1. Create an empty PostgreSQL database and user with DDL permissions.
2. Generate cryptographic keys:
   ```bash
   anonix-gateway keygen >> .env
   ```
3. Configure `.env`:
   ```env
   ANONIX_ENV=production
   ANONIX_DATABASE_URL=postgresql+asyncpg://anonix_user:strong_pass@db.company.internal:5432/anonix
   # Optional (omit for built-in in-memory rate limiting):
   ANONIX_REDIS_URL=redis://redis.company.internal:6379/0
   ANONIX_ALLOW_PRIVATE_UPSTREAMS=true
   ```
4. Start only the gateway container:
   ```bash
   docker compose -f docker-compose.byod.yml up -d
   ```

Schema tables are initialized automatically on startup (or via `alembic upgrade head`).

---

## 3. Option C: Single-Node CLI (Without Docker)

Requires Python 3.11+:

```bash
pip install anonix-gateway
anonix-gateway init
anonix-gateway serve --port 8000
```

* `anonix-gateway init` generates `.env` secrets, creates the database schema (SQLite `./data/anonix.db` by default if `ANONIX_DATABASE_URL` is blank), and prompts for the first `platform_admin`.

---

## 4. Production Hardening Checklist

* **Required in `ANONIX_ENV=production`:** Set both `ANONIX_MASTER_KEY` and `ANONIX_ADMIN_JWT_SECRET` via environment variables, Kubernetes Secrets, AWS Secrets Manager, or HashiCorp Vault. Startup fails closed if either is missing in production mode.
* **TLS Termination:** Place your load balancer / reverse proxy (NGINX, Caddy, AWS ALB, Kubernetes Ingress) in front of port `8000` for HTTPS.
* **Upstream Firewall:** Ensure internal upstream APIs are reachable **only** from Anonix Gateway's subnet/IP so external callers cannot bypass masking.
* **Probes:** Use `GET /healthz` (liveness) and `GET /readyz` (database readiness).
