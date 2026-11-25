# Changelog

All notable changes to **Anonix Gateway** are documented in this file.

## [0.1.0] - 2026-11-25

### Added
- Self-hosted FastAPI gateway powered by `anonix>=0.1.0,<0.2.0` (`JSON`, `XML`, `YAML`, `CSV`).
- Reverse-proxy masking (`/proxy/{prefix}/*`) with longest-prefix routing, method/subpath restrictions, SSRF guard, and encrypted outbound upstream credentials.
- Direct on-the-fly masking endpoint (`POST /v1/mask`).
- Multi-mode inbound authentication: OIDC/JWT (JWKS + configurable claims), scoped API Keys, and Trusted-Proxy headers (CIDR allowlist + encrypted shared secret).
- Policy-required `GroupMapping` resolution (`external_group -> policy_id + optional policy_role`) with priority tie-breaking and cross-policy blocking.
- Control-plane RBAC (`platform_admin`, `policy_author`, `auditor`), full CRUD, policy versioning/rollback, and zero-PII `AuditEvent` ledger.
- Bundled React 18 + Vite Admin Console with first-run `/setup` wizard and Live Policy Playground.
- Deployment support for Docker Compose (Postgres + Redis), Enterprise BYOD Postgres (`docker-compose.byod.yml`), and single-node CLI (`anonix-gateway init` / `serve`).
