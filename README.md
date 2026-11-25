# Anonix Gateway

Self-hosted, fail-closed, on-the-fly data masking reverse proxy, API gateway, and web control plane powered by [`anonix`](https://pypi.org/project/anonix/).

Anonix Gateway lets any organization—universities, hospitals, SaaS platforms, or enterprises—deploy their own centralized data-masking layer in minutes. It protects **non-relational data** (`JSON`, `XML`, `YAML`, `CSV`) **in memory on the fly** without modifying existing backend databases or application code.

---

## Why Anonix Gateway?

While [`anonix`](https://github.com/lovepop1/Datamasking-Core) provides the pure Python in-memory masking library and CLI, enterprises need a complete self-hosted platform:

1. **Zero-Code API Protection (`/proxy/{prefix}/*`):** Sit Anonix in front of existing internal REST APIs. External consumers call Anonix; Anonix fetches raw responses from the internal upstream, masks them in RAM for the caller's role, and returns only safe data.
2. **Language-Agnostic Masking Service (`POST /v1/mask`):** Java, Node.js, Go, PHP, ETL, and AI/LLM pipelines send raw payloads and receive masked output on the fly.
3. **Web Admin Console (Moodle-Inspired Self-Hosted Control Plane):** First-run `/setup` wizard (zero hardcoded default passwords), versioned policy editor, Live Policy Playground, Auth Providers, Group Mappings, API Keys, Upstreams, Proxy Routes, and a Zero-PII Audit Log.
4. **Full Infrastructure & Auth Autonomy:** Run with bundled Docker PostgreSQL + Redis, **BYOD PostgreSQL** (`ANONIX_DATABASE_URL`), or zero-setup local SQLite; authenticate callers via **OIDC/JWT**, **API Keys**, and/or **Trusted-Proxy Headers**.

---

## Architecture Overview

```text
  Consumer Apps / Partner Services / ETL
         │
         │  Bearer OIDC JWT │ X-API-Key │ Trusted-Proxy Headers
         ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        ANONIX GATEWAY                                │
│                                                                      │
│  1. Inbound Auth Chain (Fail-closed 401)                             │
│  2. GroupMapping -> (Policy + Optional Role) (Fail-closed 403)       │
│  3. /proxy/* (httpx + SSRF Guard)  OR  POST /v1/mask                 │
│  4. anonix MaskingEngine in RAM (Fail-closed 502 on error)           │
│  5. Zero-PII Audit Logger + Web Admin Console                        │
└───────────────┬──────────────────────────────────┬───────────────────┘
                │ Outbound Service Creds           │ Metadata & Policies
                ▼                                  ▼
   Enterprise Internal APIs                 Gateway DB (Zero PII)
   (Private VPC / Firewall)              Postgres (Bundled/BYOD) or SQLite
```

---

## Quick Start

### Option 1: Docker Compose (Recommended)
```bash
cp .env.example .env
docker compose up -d
```
Open **`http://localhost:8000`** to complete the first-run administrator setup.

To include the optional mock Student/Hospital upstream API for an instant live demo:
```bash
docker compose --profile demo up -d
```

### Option 2: Enterprise BYOD (Bring Your Own PostgreSQL / Redis)
```bash
anonix-gateway keygen >> .env
# Edit .env and set ANONIX_DATABASE_URL (and optionally ANONIX_REDIS_URL)
docker compose -f docker-compose.byod.yml up -d
```

### Option 3: Single-Node CLI (No Docker)
```bash
pip install anonix-gateway
anonix-gateway init
anonix-gateway serve
```
*(If `ANONIX_DATABASE_URL` is omitted, a local SQLite database is created automatically in `./data/anonix.db`.)*

---

## Documentation

* [**Architecture & Security Model**](docs/architecture.md) — Control Plane vs. Data Plane, `GroupMapping` resolution, fail-closed guarantees, and zero-PII audit design.
* [**Deployment & BYOD Guide**](docs/deployment.md) — Docker Compose, Enterprise BYOD PostgreSQL/Redis, single-node CLI, secrets management, and TLS setup.
* [**Authentication & Authorization Guide**](docs/authentication.md) — OIDC/JWT (Google, Okta, Entra ID, Keycloak), API Keys, Trusted-Proxy headers (with NGINX example), and Admin RBAC.
* [**API Reference**](docs/api-reference.md) — Complete endpoint reference with `curl` and PowerShell examples.
* [**5-Minute Live Demo Guide**](docs/demo-guide.md) — Step-by-step walkthrough for evaluating or presenting Anonix Gateway end-to-end.

---

## Development & Verification

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

ruff check src tests
mypy src
pytest -v
```

## License

Apache License 2.0 — Copyright 2026 Adithya Nangarath and Nikhilesh Kalahasti. See [LICENSE](LICENSE).
