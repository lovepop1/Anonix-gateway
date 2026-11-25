<div align="center">

# Anonix Gateway

**Self-hosted, fail-closed, on-the-fly data masking reverse proxy, API gateway, and web control plane.**

[![CI](https://github.com/lovepop1/Anonix-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/lovepop1/Anonix-gateway/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/anonix-gateway.svg)](https://pypi.org/project/anonix-gateway/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-green.svg)](LICENSE)

Powered by [`anonix`](https://pypi.org/project/anonix/) · [Complete Setup Guide](SETUP.md) · [Architecture](docs/architecture.md) · [Policy & `anonix` Guide](docs/policies.md) · [Auth Guide](docs/authentication.md) · [API Reference](docs/api-reference.md)

</div>

---

## Overview

**Anonix Gateway** enables organizations to deploy a centralized, policy-driven masking layer on their own infrastructure. It masks **non-relational data** (`JSON`, `XML`, `YAML`, `CSV`) **in memory on the fly** based on caller identity and policy roles—without modifying existing backend databases or application code.

### Key Capabilities

| Capability | Description |
| :--- | :--- |
| **Reverse Proxy (`/proxy/{prefix}/*`)** | Sits in front of existing internal REST APIs, fetches raw responses using encrypted outbound credentials, and masks responses in RAM per caller role. |
| **Direct Masking API (`POST /v1/mask`)** | Language-agnostic masking endpoint for Java, Node.js, Go, PHP, ETL pipelines, and AI/LLM workflows. |
| **Multi-Mode Inbound Auth** | Enable **OIDC/JWT** (Okta, Google, Entra ID, Keycloak), scoped **API Keys**, and/or **Trusted-Proxy Headers** (NGINX, Kong, ALB) simultaneously. |
| **Web Admin Console** | Built-in React console with first-run `/setup` wizard, policy versioning & rollback, Live Policy Playground, RBAC (`platform_admin`, `policy_author`, `auditor`), and Zero-PII Audit Log. |
| **Deployment Flexibility** | Run via **Docker Compose** (bundled Postgres + optional Redis & Caddy TLS), **Enterprise BYOD Postgres** (`docker-compose.byod.yml`), or **PyPI CLI** (`pip install anonix-gateway`) with automatic SQLite. |

---

## Architecture

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
│  5. Zero-PII Audit Logger + Bundled Web Admin Console                │
└───────────────┬──────────────────────────────────┬───────────────────┘
                │ Outbound Service Creds           │ Metadata & Policies
                ▼                                  ▼
   Enterprise Internal APIs                 Gateway DB (Zero PII)
   (Private VPC / Firewall)              Postgres (Bundled/BYOD) or SQLite
```

---

## Quick Start

### 1. PyPI CLI (Single Node, Auto-SQLite)
```bash
pip install anonix-gateway
anonix-gateway init
anonix-gateway serve
```
Open **`http://localhost:8000`** to sign in to the Admin Console.

### 2. Docker Compose (Bundled Postgres + Gateway)
```bash
git clone https://github.com/lovepop1/Anonix-gateway.git
cd Anonix-gateway
cp .env.example .env
docker compose up -d
```
* **Add Bundled Redis (multi-replica rate limiting):** `docker compose -f docker-compose.yml -f docker-compose.redis.yml up -d`
* **Automatic HTTPS (Caddy):** `ANONIX_DOMAIN=mask.example.com docker compose --profile tls up -d`
* **With Mock Demo Upstream:** `docker compose --profile demo up -d`

### 3. Enterprise BYOD (Bring Your Own Postgres / Optional Redis)
```bash
anonix-gateway keygen >> .env
# Set ANONIX_DATABASE_URL (and optionally ANONIX_REDIS_URL) in .env
docker compose -f docker-compose.byod.yml up -d
# Or pair BYOD Postgres with bundled Docker Redis:
docker compose -f docker-compose.byod.yml -f docker-compose.redis.yml up -d
```

---

## Repository Structure

```text
anonix-gateway/
├── src/anonix_gateway/
│   ├── auth/            # OIDC/JWKS, API keys, Trusted-Proxy, Admin RBAC
│   ├── cache/           # Redis & in-memory rate limiter
│   ├── db/              # SQLAlchemy 2.0 async models & bootstrap
│   ├── masking/         # Thread-safe anonix MaskingEngine LRU cache
│   ├── proxy/           # SSRF guard & outbound validation
│   ├── routes/          # /v1/mask, /proxy/*, /api/setup/*, modular /api/admin/*
│   ├── schemas/         # Typed Pydantic OpenAPI response schemas
│   └── security/        # Argon2id, Fernet encryption, HS256 admin JWTs
├── console/             # Modular React 18 + TypeScript + Vite Admin Console
├── alembic/             # Database schema migrations
├── examples/            # Sample policies & NGINX Trusted-Proxy config
├── docs/                # Architecture, Deployment, Auth, API & Demo guides
└── tests/               # Unit & integration test suites
```

---

## Documentation & Examples

* [**Complete Setup & Operations Guide (`SETUP.md`)**](SETUP.md) — Step-by-step zero-to-production guide for Bundled Docker, Enterprise BYOD, PyPI CLI, TLS, Multi-Tenant, and Troubleshooting
* [**Architecture & Security Model**](docs/architecture.md) — Request lifecycle, 3 security planes, RBAC, SSRF guard, and fail-closed guarantees
* [**Deployment & BYOD Quick Reference**](docs/deployment.md) — Condensed deployment checklist
* [**Policy Authoring & `anonix` Reference**](docs/policies.md) — `MaskingPolicy` schema, JSONPath/XPath selectors, all 10 built-in techniques, roles, and versioning
* [**Authentication & Authorization Guide**](docs/authentication.md) — OIDC/JWT, API Keys, Trusted-Proxy headers, and Group Mappings
* [**API Reference**](docs/api-reference.md) — Data Plane (`/v1/mask`, `/proxy/*`) and Control Plane (`/api/admin/*`) endpoints
* [**5-Minute Live Demo Guide**](docs/demo-guide.md) — End-to-end walkthrough with mock upstream
* [**Sample Policies & NGINX Config**](examples/)

---

## Contributing & Security

* See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
* Report security vulnerabilities privately per [SECURITY.md](SECURITY.md).

## License

Apache License 2.0 — Copyright 2026 Adithya Nangarath and Nikhilesh Kalahasti. See [LICENSE](LICENSE).
