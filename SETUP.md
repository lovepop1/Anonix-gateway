# Anonix Gateway — Complete Setup & Operations Guide

Welcome to **Anonix Gateway**. This guide assumes **zero prior knowledge** of Anonix or Anonix Gateway and walks you through every architecture concept, deployment topology, authentication mode, and troubleshooting step from scratch.

---

## Table of Contents

1. [How Anonix Gateway Works (5-Minute Mental Model)](#1-how-anonix-gateway-works-5-minute-mental-model)
2. [Choose Your Deployment Scenario](#2-choose-your-deployment-scenario)
3. [Prerequisites](#3-prerequisites)
4. [Scenario 1: Bundled Docker Compose (Fastest End-to-End Stack)](#4-scenario-1-bundled-docker-compose-fastest-end-to-end-stack)
5. [Scenario 2: Enterprise BYOD (Your Existing PostgreSQL & Redis)](#5-scenario-2-enterprise-byod-your-existing-postgresql--redis)
6. [Scenario 3: Single-Node PyPI CLI (No Docker)](#6-scenario-3-single-node-pypi-cli-no-docker)
7. [Scenario 4: Production HTTPS / TLS (3 Options)](#7-scenario-4-production-https--tls-3-options)
8. [Scenario 5: Multi-Tenant Mode](#8-scenario-5-multi-tenant-mode)
9. [Scenario 6: Developing From Source (Backend + React Console)](#9-scenario-6-developing-from-source-backend--react-console)
10. [First-Run Configuration Walkthrough (Zero to Masked Traffic)](#10-first-run-configuration-walkthrough-zero-to-masked-traffic)
11. [Complete Environment Variable Reference (`ANONIX_*`)](#11-complete-environment-variable-reference-anonix_)
12. [Health Probes, Upgrades & Troubleshooting](#12-health-probes-upgrades--troubleshooting)

---

## 1. How Anonix Gateway Works (5-Minute Mental Model)

Anonix Gateway sits between **consumers** (partner apps, internal analytics tools, ETL jobs, AI pipelines) and **your data/APIs**, masking sensitive fields **strictly in RAM** before responses leave your network:

```text
  Consumer App ──(JWT / API Key / Trusted-Proxy)──▶ ANONIX GATEWAY
                                                         │
                         ┌───────────────────────────────┴───────────────────────────────┐
                         ▼                                                               ▼
               [ Mode 1: /proxy/{prefix}/* ]                                   [ Mode 2: POST /v1/mask ]
               Fetches live JSON/XML/YAML/CSV                                  Masks caller-submitted
               from your internal backend API,                                 JSON/XML/YAML/CSV payload
               masks it in RAM, returns masked                                 in RAM, returns masked
               output to the consumer.                                         output to the consumer.
```

### Key Concepts
* **Control Plane vs. Data Plane:**
  * **Control Plane (`/setup`, `/`, `/api/admin/*`):** Web Admin Console where `platform_admin`, `policy_author`, and `auditor` users manage policies, auth providers, group mappings, API keys, upstreams, routes, and audit logs.
  * **Data Plane (`/v1/mask`, `/proxy/*`):** High-throughput runtime endpoints called by applications and services.
* **Policies (`MaskingPolicy`):** Declarative YAML rules powered by [`anonix`](https://pypi.org/project/anonix/) (see [Policy & `anonix` Reference](docs/policies.md)).
* **Group Mappings:** Bind an authenticated caller's group (from OIDC/JWT, API Key, or Trusted-Proxy) to `(Policy + optional Role + Priority)`.
* **Fail-Closed Guarantee:** Missing/invalid auth $\rightarrow$ `401`; unmapped group or unauthorized policy $\rightarrow$ `403`; masking error or unexpected unstructured upstream response $\rightarrow$ raw payload is **dropped** and `502` is returned. **Zero PII is ever written to disk or the gateway database.**

---

## 2. Choose Your Deployment Scenario

| Scenario | Database | Cache / Rate Limit | Best For | Jump To |
| :--- | :--- | :--- | :--- | :--- |
| **1. Bundled Docker Compose** | Bundled Postgres 16 | Bundled Redis 7 | Evaluation, demos, single-host Docker | [Scenario 1](#4-scenario-1-bundled-docker-compose-fastest-end-to-end-stack) |
| **2. Enterprise BYOD** | Your RDS / Cloud SQL / Postgres | Your Redis *(or in-memory)* | Production, Kubernetes, HA replicas | [Scenario 2](#5-scenario-2-enterprise-byod-your-existing-postgresql--redis) |
| **3. PyPI CLI (No Docker)** | Auto SQLite `./data/anonix.db` *(or Postgres)* | Built-in in-memory *(or Redis)* | Single VM, air-gapped hosts, quick local use | [Scenario 3](#6-scenario-3-single-node-pypi-cli-no-docker) |
| **4. Production TLS** | Any of the above | Any of the above | Public/internal HTTPS endpoints | [Scenario 4](#7-scenario-4-production-https--tls-3-options) |
| **5. Multi-Tenant** | Postgres *(recommended)* | Redis *(recommended)* | SaaS / isolated business units (`X-Anonix-Tenant`) | [Scenario 5](#8-scenario-5-multi-tenant-mode) |

---

## 3. Prerequisites

* **For Docker deployments (Scenarios 1 & 2):** Docker Engine 24+ and Docker Compose v2 (`docker compose version`).
* **For CLI / Source deployments (Scenarios 3 & 6):** Python **3.11+** (`python --version`), `pip`, and (for frontend source builds) Node.js **20+**.
* **For BYOD deployments (Scenario 2):** An empty PostgreSQL 14+ database and a user with DDL (`CREATE TABLE`, `ALTER TABLE`) privileges.

---

## 4. Scenario 1: Bundled Docker Compose (Fastest End-to-End Stack)

This starts PostgreSQL, Redis, Anonix Gateway (serving both the API and React Admin Console), and optionally a mock `demo-upstream` student/hospital API.

### Linux / macOS
```bash
git clone https://github.com/lovepop1/Anonix-gateway.git
cd Anonix-gateway
cp .env.example .env

# Start Postgres + Redis + Gateway + Demo Upstream
docker compose --profile demo up -d --build
docker compose ps
```

### Windows (PowerShell)
> **Important for Windows:** Hyper-V / WinNAT often reserves ports `8000` and `8080`. Override them with `ANONIX_PORT` and `ANONIX_DEMO_PORT` if binding fails:
```powershell
git clone https://github.com/lovepop1/Anonix-gateway.git
cd Anonix-gateway
copy .env.example .env

$env:ANONIX_PORT="9000"
$env:ANONIX_DEMO_PORT="9080"

docker compose --profile demo up -d --build
docker compose ps
```

### Verify
* `http://localhost:8000/healthz` (or `:9000/healthz`) $\rightarrow$ `{"status":"ok","version":"0.1.0"}`
* `http://localhost:8000` (or `:9000`) $\rightarrow$ Opens the **First-Run Setup Wizard** (`/setup`).
* Stop & keep data: `docker compose --profile demo down`
* Stop & wipe volumes (fresh reset): `docker compose --profile demo down -v`

---

## 5. Scenario 2: Enterprise BYOD (Your Existing PostgreSQL & Redis)

Use `docker-compose.byod.yml` to run **only** the stateless Anonix Gateway container(s) against your managed database (AWS RDS, Azure Database for PostgreSQL, GCP Cloud SQL, or on-prem Postgres).

### Step 1: Prepare Database & Secrets
1. Create an empty database (e.g. `anonix`) and user (`anonix_user`) on your PostgreSQL server.
2. Generate cryptographic secrets (either via `anonix-gateway keygen` or Python):
   ```bash
   pip install anonix-gateway
   anonix-gateway keygen
   ```
   Copy the output `ANONIX_MASTER_KEY` and `ANONIX_ADMIN_JWT_SECRET`.

### Step 2: Configure `.env`
```env
ANONIX_ENV=production
ANONIX_PORT=8000
ANONIX_DATABASE_URL=postgresql+asyncpg://anonix_user:YOUR_DB_PASSWORD@db.company.internal:5432/anonix
# Optional: omit ANONIX_REDIS_URL if single-replica or using built-in in-memory rate limiting
ANONIX_REDIS_URL=redis://redis.company.internal:6379/0
ANONIX_MASTER_KEY=your-fernet-key-from-keygen
ANONIX_ADMIN_JWT_SECRET=your-jwt-secret-from-keygen
ANONIX_ALLOW_PRIVATE_UPSTREAMS=true
```
> **Note:** In `ANONIX_ENV=production`, startup **fails closed** if `ANONIX_MASTER_KEY` or `ANONIX_ADMIN_JWT_SECRET` is missing.

### Step 3: Start the Gateway
```bash
docker compose -f docker-compose.byod.yml up -d --build
```
Schema tables are initialized automatically on boot. For controlled CI/CD rollouts across multiple replicas, run `alembic upgrade head` once before starting the new replica set.

---

## 6. Scenario 3: Single-Node PyPI CLI (No Docker)

Ideal for standalone Linux/Windows VMs, local evaluation, or air-gapped environments.

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows:     .\.venv\Scripts\Activate.ps1

pip install anonix-gateway
anonix-gateway init
anonix-gateway serve --port 8000
```

* **`anonix-gateway init`**:
  * Creates `.env` with fresh `ANONIX_MASTER_KEY` and `ANONIX_ADMIN_JWT_SECRET` (unless `.env` already exists).
  * Creates SQLite database at `./data/anonix.db` (unless `ANONIX_DATABASE_URL` is set).
  * Prompts for Organization Name, `platform_admin` email, and password.
* **`anonix-gateway keygen`**: Prints fresh keys to stdout without touching files.
* **`anonix-gateway migrate`**: Ensures DB schema tables exist.
* **`anonix-gateway serve`**: Starts Uvicorn (`--host`, `--port`, `--ssl-certfile`, `--ssl-keyfile`).

### Headless / Unattended CLI Setup (CI or Cloud-Init)
Skip interactive `init` by setting bootstrap environment variables before `serve`:
```bash
export ANONIX_ENV=production
eval "$(anonix-gateway keygen)"
export ANONIX_BOOTSTRAP_ADMIN_EMAIL=admin@company.com
export ANONIX_BOOTSTRAP_ADMIN_PASSWORD='StrongPassword123!'
export ANONIX_BOOTSTRAP_ORG_NAME='Acme Corp'
anonix-gateway serve --port 8000
```

---

## 7. Scenario 4: Production HTTPS / TLS (3 Options)

### Option A: Automatic Let's Encrypt HTTPS via Caddy (Single-Host Docker)
```bash
ANONIX_DOMAIN=mask.company.com docker compose --profile tls up -d
```
Uses `Caddyfile` (`{$ANONIX_DOMAIN:localhost} { reverse_proxy gateway:8000 }`) on ports `80` and `443`.

### Option B: Corporate Load Balancer / Ingress (AWS ALB, NGINX, Kong, Traefik)
Terminate TLS at your load balancer and forward HTTP to Anonix Gateway on port `8000`.
If your edge proxy also authenticates users and passes identity headers, see [`examples/nginx-trusted-proxy.conf`](examples/nginx-trusted-proxy.conf) and configure a **Trusted-Proxy** Auth Provider in the **AUTH** tab.

### Option C: Direct Native TLS on Gateway (No External Proxy)
```bash
anonix-gateway serve \
  --port 8443 \
  --ssl-certfile /etc/certs/fullchain.pem \
  --ssl-keyfile /etc/certs/privkey.pem
```
Or set `ANONIX_SSL_CERTFILE` and `ANONIX_SSL_KEYFILE` in `.env`. Both must be provided together.

---

## 8. Scenario 5: Multi-Tenant Mode

By default, `ANONIX_TENANCY_MODE=single_org` routes all traffic to the `default` tenant. To isolate multiple organizations on one cluster:
1. Set `ANONIX_TENANCY_MODE=multi_tenant` in `.env`.
2. Callers include `X-Anonix-Tenant: <tenant-slug>` on Data Plane requests (`/v1/mask`, `/proxy/*`).

---

## 9. Scenario 6: Developing From Source (Backend + React Console)

```bash
git clone https://github.com/lovepop1/Anonix-gateway.git
cd Anonix-gateway

# 1. Backend
python -m venv .venv
# Activate .venv, then:
pip install -e ".[dev]"
export ANONIX_CORS_ORIGINS=http://localhost:5173
export ANONIX_ALLOW_PRIVATE_UPSTREAMS=true
anonix-gateway serve --port 9000

# 2. Frontend (separate terminal, optional hot-reload)
cd console
npm install
npm run dev
```
To rebuild the bundled console static assets for production packaging:
```bash
cd console
npm run typecheck && npm run build
# Copy console/dist/* into src/anonix_gateway/static/
```
Run checks:
```bash
ruff check src tests
ruff format --check src tests
mypy src
pytest -v
```

---

## 10. First-Run Configuration Walkthrough (Zero to Masked Traffic)

Once the gateway is running, open `http://localhost:8000` (or your configured port/domain):

1. **Bootstrap Admin (`/setup`):** Enter your Organization Name, Admin Email, and Password (`min 8 chars`), then sign in.
2. **Create a Policy (`POLICIES` tab):**
   * Click **New Policy**, give it a name (e.g. `student-policy`), paste YAML (see [Policy Reference](docs/policies.md) or `examples/policies/`), and test it immediately in the **Live Playground**.
   * Save and ensure a version is **Active**.
3. **Configure Caller Authentication (`AUTH` and/or `KEYS` tabs):**
   * **API Keys (`KEYS` tab):** Create a key, assign groups (e.g. `research-team`), and copy the `axk_...` secret (shown once).
   * **OIDC/JWT (`AUTH` tab):** Add your Okta / Google / Entra ID / Keycloak issuer URL, optional audience, and `groups` claim name.
   * **Trusted-Proxy (`AUTH` tab):** Add allowed proxy CIDRs and a shared secret (`X-Anonix-Proxy-Secret`).
4. **Create Group Mapping (`MAPPINGS` tab):**
   * Map `external_group` (`research-team`) $\rightarrow$ `policy` (`student-policy`) + optional `policy_role` (`researcher`) + `priority` (`10`).
5. **Register Upstream & Proxy Route (`UPSTREAMS` & `ROUTES` tabs):**
   * **Upstream:** Name `demo-api`, Base URL `http://demo-upstream:8080` (Docker) or `http://127.0.0.1:9080` (local), Outbound Auth `None` (or `bearer` / `api_key_header` / `basic` encrypted with `ANONIX_MASTER_KEY`).
   * **Proxy Route:** Prefix `/students`, Upstream `demo-api`, Policy `student-policy`.
     * **Strip prefix:** Leave **unchecked** if the upstream path includes the prefix (e.g. `demo-upstream` serves `/students/{id}`). Check **Strip prefix** if `/proxy/api/users` should hit upstream `/users`.
6. **Send Traffic & Verify Audit Log (`AUDIT` tab):**
   * `GET /proxy/students/101` with `X-API-Key: axk_...` $\rightarrow$ `200 OK` with role-masked JSON.
   * `GET /proxy/students/101` without auth $\rightarrow$ `401 Unauthorized`.
   * Check `AUDIT` tab $\rightarrow$ records caller, auth method, policy, role, status, latency with **zero PII**.

---

## 11. Complete Environment Variable Reference (`ANONIX_*`)

| Variable | Default | Description |
| :--- | :--- | :--- |
| `ANONIX_ENV` | `development` | `development` (auto-generates secrets) or `production` (strict fail-closed). |
| `ANONIX_HOST` | `0.0.0.0` | ASGI bind host. |
| `ANONIX_PORT` | `8000` | ASGI bind port. |
| `ANONIX_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`. |
| `ANONIX_TENANCY_MODE` | `single_org` | `single_org` or `multi_tenant`. |
| `ANONIX_DATABASE_URL` | *(SQLite in `data_dir`)* | Async DB URL (`postgresql+asyncpg://...` or `sqlite+aiosqlite:///...`). |
| `ANONIX_REDIS_URL` | *(empty)* | Optional `redis://host:6379/0` for shared rate limits & JWKS cache. |
| `ANONIX_MASTER_KEY` | *(auto in dev)* | Fernet key for encrypting upstream & OIDC secrets. |
| `ANONIX_ADMIN_JWT_SECRET` | *(auto in dev)* | HS256 secret for admin console JWTs. |
| `ANONIX_DATA_DIR` | `./data` | Local folder for SQLite DB and dev `.anonix_secrets.json`. |
| `ANONIX_ALLOW_PRIVATE_UPSTREAMS` | `false` (`true` in Compose) | Allow private/VPC/loopback upstream IPs; metadata IPs stay blocked. |
| `ANONIX_BOOTSTRAP_ADMIN_EMAIL` | *(empty)* | Headless initial `platform_admin` email. |
| `ANONIX_BOOTSTRAP_ADMIN_PASSWORD` | *(empty)* | Headless initial `platform_admin` password. |
| `ANONIX_BOOTSTRAP_ORG_NAME` | `Default Organization` | Initial organization name for headless bootstrap. |
| `ANONIX_ADMIN_TOKEN_TTL_MINUTES` | `480` | Admin session JWT lifetime in minutes. |
| `ANONIX_RATE_LIMIT_PER_MINUTE` | `120` | Data-plane per-caller request limit per minute. |
| `ANONIX_MAX_PAYLOAD_BYTES` | `10485760` | Max request/response payload size (10 MiB). |
| `ANONIX_CORS_ORIGINS` | *(empty)* | Comma-separated allowed CORS origins. |
| `ANONIX_SSL_CERTFILE` / `ANONIX_SSL_KEYFILE` | *(empty)* | PEM cert/key paths for native TLS. |
| `ANONIX_DOMAIN` | `localhost` | Public domain for Caddy `--profile tls`. |

---

## 12. Health Probes, Upgrades & Troubleshooting

### Health & Readiness Probes
* `GET /healthz` $\rightarrow$ Liveness probe (`200 OK` if ASGI process is up).
* `GET /readyz` $\rightarrow$ Readiness probe (`200 OK` if database connection succeeds).

### Common Issues & Fixes

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| Windows port bind error on `8000` / `8080` | Hyper-V / WinNAT port reservation | Set `$env:ANONIX_PORT="9000"` and `$env:ANONIX_DEMO_PORT="9080"` before `docker compose up`. |
| Gateway exits immediately in `production` | Missing `ANONIX_MASTER_KEY` or `ANONIX_ADMIN_JWT_SECRET` | Run `anonix-gateway keygen` and add both to `.env` or secret manager. |
| `401 Unauthorized` on `/v1/mask` or `/proxy/*` | Missing/invalid `X-API-Key`, expired OIDC JWT, or wrong `X-Anonix-Proxy-Secret` | Check caller credentials and `AUTH` / `KEYS` tab configuration. |
| `403 Forbidden` on `/v1/mask` or `/proxy/*` | Caller's groups have no `GroupMapping` for the target policy, or `blocked_subpaths` matched | Add a `GroupMapping` in `MAPPINGS` linking the caller's group to the route/request policy. |
| `404 Not Found` from upstream on `/proxy/*` | `Strip prefix` setting mismatch | Toggle **Strip prefix** on the `ProxyRoute` depending on whether the upstream expects the prefix. |
| `502 Bad Gateway` on `/proxy/*` | SSRF guard blocked private upstream IP, upstream unreachable, or masking failed (`on_error: raise`) | Set `ANONIX_ALLOW_PRIVATE_UPSTREAMS=true` for VPC/local upstreams; verify upstream health and policy selectors. |
