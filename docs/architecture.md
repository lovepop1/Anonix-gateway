# Architecture & Security Model

Anonix Gateway separates **administration (Control Plane)** from **runtime masking traffic (Data Plane)** and enforces **fail-closed** behavior at every boundary.

---

## 1. End-to-End Request Flow

```text
  Consumer App / Partner / ETL
         │
         │  Authorization: Bearer <OIDC JWT>
         │  OR  X-API-Key: axk_...
         │  OR  X-Anonix-User + X-Anonix-Groups + X-Anonix-Proxy-Secret
         ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                         ANONIX GATEWAY (FastAPI)                             │
│                                                                              │
│  [1] Rate Limiter (Redis fixed-window, or in-memory fallback) -> 429         │
│  [2] Inbound Auth Chain (OIDC/JWKS | API Key | Trusted Proxy) -> 401         │
│  [3] GroupMapping Lookup: groups -> (policy_id, role, priority) -> 403       │
│  [4] Route / Policy Authorization:                                           │
│      • /v1/mask: checks requested policy vs mapped policies & key scope      │
│      • /proxy/{prefix}/*: matches longest ProxyRoute, checks allowed_methods │
│        (405), blocked_subpaths (403), and caller access to route.policy_id   │
│  [5] Outbound Call (for /proxy/* only):                                      │
│      • SSRF Guard (blocks metadata/link-local; private IPs configurable)     │
│      • Strips inbound auth headers; injects encrypted upstream creds         │
│  [6] In-RAM MaskingEngine (anonix):                                          │
│      • Masks JSON / XML / YAML / CSV in memory -> 502 on failure             │
│  [7] Zero-PII AuditEvent persisted (metadata only; zero payload fields)      │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Core Design Principles

1. **Zero-PII Persistence:** Anonix Gateway never writes raw or masked payload fields to disk, database tables, or logs. All masking occurs strictly in RAM via `anonix.MaskingEngine`.
2. **No Hardcoded Policies or Magic Roles:** Every masking rule comes from explicit `MaskingPolicy` YAML stored in the database. No built-in default policy or privileged role name exists.
3. **Fail-Closed Everywhere:**
   * Missing or invalid caller credentials $\rightarrow$ `401 Unauthorized`.
   * Unmapped groups, blocked subpaths, or cross-policy access $\rightarrow$ `403 Forbidden`.
   * Disallowed HTTP method on a proxy route $\rightarrow$ `405 Method Not Allowed`.
   * Masking failure or unstructured upstream response (`on_unstructured=fail_closed`) $\rightarrow$ raw payload dropped, returns `502 Bad Gateway`.
   * Missing `ANONIX_MASTER_KEY` or `ANONIX_ADMIN_JWT_SECRET` when `ANONIX_ENV=production` $\rightarrow$ gateway refuses to start.
4. **No Hardcoded Secrets or Passwords:** Initial `platform_admin` accounts are created via first-run `/setup`, `anonix-gateway init`, or explicit `ANONIX_BOOTSTRAP_ADMIN_*` environment variables.

---

## 3. Three Security Planes

### Plane 1: Control Plane (`/api/setup/*`, `/api/admin/*`, Web Console)
* **Authentication:** Local `AdminUser` accounts hashed with **Argon2id**, issuing **HS256** session JWTs signed with `ANONIX_ADMIN_JWT_SECRET` (default TTL: `480` minutes via `ANONIX_ADMIN_TOKEN_TTL_MINUTES`).
* **RBAC Roles:**
  * `platform_admin`: Full access (Admin Users, Auth Providers, Group Mappings, API Keys, Upstreams, Proxy Routes, Policies, Audit Logs). Self-lockout and last-admin deletion protections are enforced.
  * `policy_author`: Create/edit/version/activate/delete `MaskingPolicy`s, run the Live Playground, view `GroupMapping`s.
  * `auditor`: Read-only access to Policies and Zero-PII `AuditEvent` logs.

### Plane 2: Data Plane — Inbound (`/proxy/{prefix}/*` and `POST /v1/mask`)
1. **Caller Authentication (`authenticate_caller`):** Evaluates configured `AuthProvider`s (OIDC/JWT with JWKS caching, Trusted-Proxy headers with CIDR allowlist + constant-time shared secret check) and `ApiKey`s (`axk_...` verified via cryptographic hash).
2. **Group $\rightarrow$ Policy + Role Resolution:**
   * Every `GroupMapping` binds `(external_group) -> (policy_id, optional policy_role, priority)`.
   * **`policy_id` is required** on every `GroupMapping`; `policy_role` is optional (`None` applies only unscoped rules in the policy).
   * **On `/proxy/*`:** Matches longest active `ProxyRoute` prefix, enforces `allowed_methods` (`405`) and `blocked_subpaths` (`403`), and verifies the caller has a `GroupMapping` matching `route.policy_id` (unless `allow_policy_override` is enabled). Enforces `ApiKey.allowed_policy_ids` if set.
   * **On `POST /v1/mask`:** If `"policy"` is provided (`X-Anonix-Policy` header or JSON envelope), verifies the caller's groups map to that policy (`403` otherwise); if omitted, selects the highest-priority `GroupMapping.policy_id`.

### Plane 3: Data Plane — Outbound (`/proxy/{prefix}/*` only)
* **SSRF Protection:** `validate_upstream_url` blocks link-local and cloud metadata IPs (`169.254.169.254`, `metadata.google.internal`) unconditionally, and blocks private/loopback networks (`10.0.0.0/8`, `127.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) unless `ANONIX_ALLOW_PRIVATE_UPSTREAMS=true` is explicitly configured for internal VPC upstreams.
* **Header Isolation:** Strips hop-by-hop headers and inbound caller credentials (`Authorization`, `X-API-Key`, `X-Anonix-*`) before forwarding to the upstream.
* **Encrypted Upstream Credentials:** Optional outbound `bearer`, `api_key_header`, or `basic` credentials are encrypted at rest with **Fernet** (`ANONIX_MASTER_KEY`) and decrypted in memory only when calling the upstream.

---

## 4. Database, Tenancy & Caching

* **Gateway Database (Zero Business PII):** Stores `Tenant`, `AdminUser`, `AuthProvider`, `MaskingPolicy`, `PolicyVersion`, `GroupMapping`, `ApiKey`, `Upstream`, `ProxyRoute`, and `AuditEvent`.
  * Supports **PostgreSQL** (`postgresql+asyncpg://...`) for multi-replica production and **SQLite** (`sqlite+aiosqlite:///./data/anonix.db`) for zero-config single-node CLI usage.
* **Tenancy:** Defaults to `ANONIX_TENANCY_MODE=single_org` (`default` tenant), while retaining `tenant_id` across all tables so `multi_tenant` (`X-Anonix-Tenant`) can be enabled without schema migration.
* **Rate Limiting & In-Memory Caches:**
  * **Rate Limiting:** Fixed-window per-minute counter (`ANONIX_RATE_LIMIT_PER_MINUTE`, default `120`). Uses Redis (`ANONIX_REDIS_URL`) when configured for shared multi-replica enforcement, automatically falling back to an in-memory store when Redis is omitted.
  * **Compiled `MaskingEngine` Cache:** Thread-safe in-memory LRU cache (`_MAX_ENGINES = 256`) keyed by `(policy_id, version_number, salt_digest)`.
  * **OIDC JWKS Cache:** In-memory TTL cache (`300s`) per `jwks_url` with automatic one-shot refresh on key rotation.
